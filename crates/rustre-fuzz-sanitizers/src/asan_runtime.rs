//! `ASan` runtime simulation — shadow memory, redzones, and violation detection.
//!
//! Implements the runtime side of `AddressSanitizer` in pure Rust: a 1/8-scale
//! shadow memory mapping, heap redzone insertion, quarantine for freed
//! allocations, load/store callbacks, stack/global overflow detection, and
//! a fake-stack for use-after-return detection.
//!
//! # Relationship to [`crate::asan_analyzer`]
//!
//! [`crate::asan_analyzer`] is the **static analysis / parsing** side: it
//! converts existing ASAN text output into structured [`crate::asan_analyzer::AsanReport`]
//! values.  It does not simulate memory at all.
//!
//! This module is the **runtime simulation** side: it models the in-process ASAN
//! machinery so that violations can be detected without LLVM instrumentation.
//! Note that this module defines its own [`AsanReport`] (a runtime *summary* struct)
//! which is unrelated to the identically-named parsed-report type in
//! [`crate::asan_analyzer`].
//! The two modules are **intentionally kept separate** and are not duplicates.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AsanError {
    #[error("heap-{rw}-overflow at {addr:#x}: shadow byte {shadow:#02x}", rw = if *.is_write { "write" } else { "read" })]
    HeapBufferOverflow { addr: u64, shadow: i8, is_write: bool },

    #[error("heap-use-after-free at {addr:#x}")]
    HeapUseAfterFree { addr: u64 },

    #[error("stack-buffer-overflow at {addr:#x}")]
    StackBufferOverflow { addr: u64 },

    #[error("global-buffer-overflow at {addr:#x} in {symbol}")]
    GlobalBufferOverflow { addr: u64, symbol: String },

    #[error("use-after-return at {addr:#x}")]
    UseAfterReturn { addr: u64 },

    #[error("use-after-scope at {addr:#x}")]
    UseAfterScope { addr: u64 },

    #[error("null-deref at {addr:#x}")]
    NullDeref { addr: u64 },

    #[error("shadow memory not initialised")]
    ShadowUninitialised,

    #[error("allocation failed: size {0}")]
    AllocationFailed(usize),
}

pub type AsanResult<T> = Result<T, AsanError>;

// ─── shadow memory constants ─────────────────────────────────────────────────

/// `ASan` maps 8 application bytes to 1 shadow byte.
pub const SHADOW_SCALE: usize = 3; // shift: addr >> 3
/// Default shadow memory offset (64-bit Linux).
pub const SHADOW_OFFSET: u64 = 0x7fff_8000_0000u64;
/// Redzone size in bytes on each side of a heap allocation.
pub const REDZONE_SIZE: usize = 16;
/// Magic shadow byte for left redzone.
pub const SHADOW_LEFT_REDZONE: i8 = -1; // 0xFA
/// Magic shadow byte for right redzone.
pub const SHADOW_RIGHT_REDZONE: i8 = -2; // 0xFB
/// Magic shadow byte for heap use-after-free (quarantine).
pub const SHADOW_FREED: i8 = -3; // 0xFD
/// Magic shadow byte for stack left redzone.
pub const SHADOW_STACK_LEFT: i8 = -4; // 0xF1
/// Magic shadow byte for stack right redzone.
pub const SHADOW_STACK_RIGHT: i8 = -5; // 0xF3
/// Magic shadow byte for use-after-return.
pub const SHADOW_USE_AFTER_RETURN: i8 = -6; // 0xF5
/// Magic shadow byte for global redzone.
pub const SHADOW_GLOBAL: i8 = -7; // 0xF9

/// Convert an application address to its shadow address.
#[must_use]
pub const fn app_to_shadow(addr: u64) -> u64 {
    (addr >> SHADOW_SCALE) + SHADOW_OFFSET
}

// ─── shadow memory ────────────────────────────────────────────────────────────

/// In-process shadow memory backed by a `HashMap` of pages.
/// Each page covers 4096 shadow bytes = 32 768 application bytes.
#[derive(Debug, Default)]
pub struct ShadowMemory {
    pages: RwLock<HashMap<u64, Box<[i8; 4096]>>>,
}

impl ShadowMemory {
    const PAGE_SIZE: u64 = 4096;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_key(shadow_addr: u64) -> u64 {
        shadow_addr & !(Self::PAGE_SIZE - 1)
    }

    fn ensure_page(&self, shadow_addr: u64) {
        let key = Self::page_key(shadow_addr);
        let pages = self.pages.read().unwrap();
        if pages.contains_key(&key) {
            return;
        }
        drop(pages);
        let mut pages = self.pages.write().unwrap();
        pages.entry(key).or_insert_with(|| Box::new([0i8; 4096]));
    }

    /// Read the shadow byte for an application address.
    ///
    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn read(&self, app_addr: u64) -> i8 {
        let shadow = app_to_shadow(app_addr);
        let key = Self::page_key(shadow);
        let off = crate::cast::u64_to_usize(shadow.saturating_sub(key));
        let pages = self.pages.read().unwrap();
        pages.get(&key).map_or(0, |p| p[off.min(4095)])
    }

    /// Write the shadow byte for an application address.
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn write(&self, app_addr: u64, value: i8) {
        let shadow = app_to_shadow(app_addr);
        self.ensure_page(shadow);
        let key = Self::page_key(shadow);
        let off = crate::cast::u64_to_usize(shadow.saturating_sub(key));
        let mut pages = self.pages.write().unwrap();
        if let Some(p) = pages.get_mut(&key) {
            p[off.min(4095)] = value;
        }
    }

    /// Mark `size` application bytes starting at `app_addr` as accessible (0).
    pub fn mark_accessible(&self, app_addr: u64, size: usize) {
        for i in 0..(size / 8) {
            self.write(app_addr + (i * 8) as u64, 0);
        }
        let tail = size % 8;
        if tail != 0 {
            self.write(app_addr + (size / 8 * 8) as u64, crate::cast::usize_to_i8(tail));
        }
    }

    /// Mark `size` application bytes starting at `app_addr` with `value`.
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn mark_region(&self, app_addr: u64, size: usize, value: i8) {
        let shadow_start = app_to_shadow(app_addr);
        let shadow_count = size.div_ceil(8);
        for i in 0..shadow_count as u64 {
            let shadow = shadow_start.saturating_add(i);
            self.ensure_page(shadow);
            let key = Self::page_key(shadow);
            let off = crate::cast::u64_to_usize(shadow.saturating_sub(key));
            let mut pages = self.pages.write().unwrap();
            if let Some(p) = pages.get_mut(&key) {
                p[off] = value;
            }
        }
    }

    /// Check whether an access to `app_addr` of `access_size` bytes is valid.
    ///
    /// # Errors
    /// Returns an `AsanError` if the access overlaps poisoned shadow memory.
    pub fn check_access(
        &self,
        app_addr: u64,
        access_size: usize,
        is_write: bool,
    ) -> AsanResult<()> {
        let shadow = self.read(app_addr);
        if shadow == 0 {
            return Ok(());
        }
        // Partially-valid: last `shadow` bytes of the 8-byte granule are valid.
        if shadow > 0 {
            let offset_within_granule = (app_addr % 8) as usize;
            if offset_within_granule + access_size <= crate::cast::i8_to_usize(shadow) {
                return Ok(());
            }
        }
        // Decode the error kind.
        match shadow {
            SHADOW_FREED => Err(AsanError::HeapUseAfterFree { addr: app_addr }),
            SHADOW_STACK_LEFT | SHADOW_STACK_RIGHT => {
                Err(AsanError::StackBufferOverflow { addr: app_addr })
            }
            SHADOW_GLOBAL => Err(AsanError::GlobalBufferOverflow {
                addr: app_addr,
                symbol: String::new(),
            }),
            SHADOW_USE_AFTER_RETURN => Err(AsanError::UseAfterReturn { addr: app_addr }),
            _ if app_addr < 0x10000 => Err(AsanError::NullDeref { addr: app_addr }),
            _ => Err(AsanError::HeapBufferOverflow { addr: app_addr, shadow, is_write }),
        }
    }
}

// ─── heap allocation with redzones ───────────────────────────────────────────

/// Metadata stored for every live heap allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapAlloc {
    /// Address of the user-visible allocation (after left redzone).
    pub user_addr: u64,
    /// Requested allocation size.
    pub user_size: usize,
    /// Address of the raw block including redzones.
    pub raw_addr: u64,
    /// Total size including both redzones.
    pub raw_size: usize,
    /// Allocation stack trace (PCs).
    pub alloc_trace: Vec<u64>,
    /// Deallocation stack trace (set when freed).
    pub free_trace: Option<Vec<u64>>,
    /// Whether this allocation is currently in the quarantine.
    pub quarantined: bool,
}

impl HeapAlloc {
    #[must_use]
    pub const fn new(user_addr: u64, user_size: usize, alloc_trace: Vec<u64>) -> Self {
        let raw_addr = user_addr.saturating_sub(REDZONE_SIZE as u64);
        let raw_size = user_size.saturating_add(REDZONE_SIZE.saturating_mul(2));
        Self {
            user_addr,
            user_size,
            raw_addr,
            raw_size,
            alloc_trace,
            free_trace: None,
            quarantined: false,
        }
    }
}

/// Quarantine list for freed allocations.  Prevents immediate reuse so that
/// use-after-free bugs are detectable within the quarantine window.
#[derive(Debug)]
pub struct QuarantineList {
    queue: Mutex<VecDeque<HeapAlloc>>,
    total_bytes: AtomicU64,
    /// Maximum total bytes to hold in quarantine.
    capacity_bytes: u64,
}

impl QuarantineList {
    #[must_use]
    pub const fn new(capacity_bytes: u64) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            total_bytes: AtomicU64::new(0),
            capacity_bytes,
        }
    }

    /// Add a freed allocation to the quarantine.
    pub fn enqueue(&self, alloc: HeapAlloc) {
        let size = alloc.raw_size as u64;
        self.total_bytes.fetch_add(size, Ordering::Relaxed);
        self.queue.lock().push_back(alloc);
    }

    /// Drain allocations from the quarantine until below `capacity_bytes`.
    /// Returns the drained allocations for actual release.
    pub fn drain_excess(&self) -> Vec<HeapAlloc> {
        let mut drained = Vec::new();
        while self.total_bytes.load(Ordering::Relaxed) > self.capacity_bytes {
            let front = self.queue.lock().pop_front();
            if let Some(a) = front {
                self.total_bytes.fetch_sub(a.raw_size as u64, Ordering::Relaxed);
                drained.push(a);
            } else {
                break;
            }
        }
        drained
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

// ─── global buffer registration ──────────────────────────────────────────────

/// Descriptor for a global variable, registered via
/// `__asan_register_globals` / `__asan_unregister_globals`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDesc {
    pub addr: u64,
    pub size: usize,
    pub size_with_redzone: usize,
    pub name: String,
    pub module_name: String,
    pub has_dynamic_init: bool,
}

impl GlobalDesc {
    #[must_use]
    pub const fn redzone_size(&self) -> usize {
        self.size_with_redzone - self.size
    }
}

// ─── stack fake-frame ─────────────────────────────────────────────────────────

/// A fake stack frame used for use-after-return detection.
/// `ASan` allocates local variables in a fake frame instead of the real stack,
/// and poisons the frame's shadow on function exit.
#[derive(Debug, Clone)]
pub struct FakeFrame {
    pub frame_addr: u64,
    pub frame_size: usize,
    pub function_name: String,
    pub poisoned: bool,
}

impl FakeFrame {
    #[must_use]
    pub fn new(frame_addr: u64, frame_size: usize, function_name: impl Into<String>) -> Self {
        Self { frame_addr, frame_size, function_name: function_name.into(), poisoned: false }
    }

    /// Poison the frame on function return (use-after-return detection).
    pub fn poison_on_return(&mut self, shadow: &ShadowMemory) {
        shadow.mark_region(self.frame_addr, self.frame_size, SHADOW_USE_AFTER_RETURN);
        self.poisoned = true;
    }

    /// Unpoison the frame on function entry.
    pub fn unpoison_on_entry(&mut self, shadow: &ShadowMemory) {
        shadow.mark_accessible(self.frame_addr, self.frame_size);
        self.poisoned = false;
    }
}

// ─── ASan runtime ─────────────────────────────────────────────────────────────

/// Central `ASan` runtime: holds shadow memory, quarantine, live allocations,
/// and global descriptors.
#[derive(Debug)]
pub struct AsanRuntime {
    pub shadow: Arc<ShadowMemory>,
    pub quarantine: Arc<QuarantineList>,
    live_allocs: Mutex<HashMap<u64, HeapAlloc>>,
    globals: Mutex<Vec<GlobalDesc>>,
    fake_frames: Mutex<HashMap<u64, FakeFrame>>,
    /// Total number of violations detected.
    violation_count: AtomicU64,
}

impl AsanRuntime {
    /// Create an `AsanRuntime` with the given quarantine capacity (bytes).
    #[must_use]
    pub fn new(quarantine_capacity_bytes: u64) -> Self {
        Self {
            shadow: Arc::new(ShadowMemory::new()),
            quarantine: Arc::new(QuarantineList::new(quarantine_capacity_bytes)),
            live_allocs: Mutex::new(HashMap::new()),
            globals: Mutex::new(Vec::new()),
            fake_frames: Mutex::new(HashMap::new()),
            violation_count: AtomicU64::new(0),
        }
    }

    // ── heap ────────────────────────────────────────────────────────────────

    /// Record a new heap allocation and set up redzones in shadow memory.
    pub fn on_alloc(&self, user_addr: u64, user_size: usize, trace: Vec<u64>) {
        let alloc = HeapAlloc::new(user_addr, user_size, trace);
        // Left redzone
        self.shadow.mark_region(alloc.raw_addr, REDZONE_SIZE, SHADOW_LEFT_REDZONE);
        // Accessible region
        self.shadow.mark_accessible(user_addr, user_size);
        // Right redzone
        let rz_addr = user_addr.saturating_add(user_size as u64);
        self.shadow.mark_region(rz_addr, REDZONE_SIZE, SHADOW_RIGHT_REDZONE);
        self.live_allocs.lock().insert(user_addr, alloc);
    }

    /// Handle a `free(user_addr)` call: quarantine the allocation and poison.
    ///
    /// # Errors
    /// Returns an `AsanError` if `user_addr` is not a live allocation (double/bad free).
    pub fn on_free(&self, user_addr: u64, free_trace: Vec<u64>) -> AsanResult<()> {
        let mut alloc = self
            .live_allocs
            .lock()
            .remove(&user_addr)
            .ok_or(AsanError::HeapUseAfterFree { addr: user_addr })?;
        alloc.free_trace = Some(free_trace);
        alloc.quarantined = true;
        // Poison the user region as freed.
        self.shadow.mark_region(alloc.user_addr, alloc.user_size, SHADOW_FREED);
        self.quarantine.enqueue(alloc);
        // Drain excess from quarantine.
        let _released = self.quarantine.drain_excess();
        // (In a real runtime we'd actually release memory here.)
        Ok(())
    }

    // ── load / store callbacks ───────────────────────────────────────────────

    /// `__asan_load1` / `__asan_load2` / `__asan_load4` / `__asan_load8`
    ///
    /// # Errors
    /// Returns an `AsanError` if the address is null or the access touches poisoned memory.
    pub fn on_load(&self, addr: u64, size: usize) -> AsanResult<()> {
        if addr == 0 {
            return Err(AsanError::NullDeref { addr });
        }
        self.shadow.check_access(addr, size, false)
    }

    /// `__asan_store1` / `__asan_store2` / `__asan_store4` / `__asan_store8`
    ///
    /// # Errors
    /// Returns an `AsanError` if the address is null or the access touches poisoned memory.
    pub fn on_store(&self, addr: u64, size: usize) -> AsanResult<()> {
        if addr == 0 {
            return Err(AsanError::NullDeref { addr });
        }
        self.shadow.check_access(addr, size, true)
    }

    /// Record a violation and return the total count.
    pub fn record_violation(&self, _err: &AsanError) -> u64 {
        self.violation_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[must_use]
    pub fn violation_count(&self) -> u64 {
        self.violation_count.load(Ordering::Relaxed)
    }

    // ── stack ────────────────────────────────────────────────────────────────

    /// Register a stack variable with redzones.
    pub fn on_stack_alloc(
        &self,
        var_addr: u64,
        var_size: usize,
        left_rz: usize,
        right_rz: usize,
    ) {
        self.shadow.mark_region(var_addr - left_rz as u64, left_rz, SHADOW_STACK_LEFT);
        self.shadow.mark_accessible(var_addr, var_size);
        self.shadow.mark_region(var_addr + var_size as u64, right_rz, SHADOW_STACK_RIGHT);
    }

    /// Deregister a stack variable on function return.
    pub fn on_stack_free(&self, var_addr: u64, var_size: usize, left_rz: usize, right_rz: usize) {
        self.shadow.mark_region(
            var_addr - left_rz as u64,
            var_size + left_rz + right_rz,
            SHADOW_FREED,
        );
    }

    // ── globals ──────────────────────────────────────────────────────────────

    /// `__asan_register_globals`
    pub fn register_globals(&self, globals: Vec<GlobalDesc>) {
        let mut g = self.globals.lock();
        for gd in &globals {
            self.shadow.mark_accessible(gd.addr, gd.size);
            let rz_start = gd.addr + gd.size as u64;
            let rz_size = gd.size_with_redzone - gd.size;
            self.shadow.mark_region(rz_start, rz_size, SHADOW_GLOBAL);
        }
        g.extend(globals);
    }

    /// `__asan_unregister_globals`
    pub fn unregister_globals(&self, base: u64) {
        let mut g = self.globals.lock();
        g.retain(|gd| {
            if gd.addr >= base {
                self.shadow.mark_region(
                    gd.addr - REDZONE_SIZE as u64,
                    gd.size_with_redzone,
                    0,
                );
                false
            } else {
                true
            }
        });
    }

    // ── fake stack (use-after-return) ────────────────────────────────────────

    /// Allocate a fake frame for use-after-return detection.
    pub fn push_fake_frame(&self, frame: FakeFrame) {
        let addr = frame.frame_addr;
        self.shadow.mark_accessible(addr, frame.frame_size);
        self.fake_frames.lock().insert(addr, frame);
    }

    /// Poison a fake frame on function return.
    pub fn pop_fake_frame(&self, frame_addr: u64) {
        let mut frames = self.fake_frames.lock();
        if let Some(frame) = frames.get_mut(&frame_addr) {
            frame.poison_on_return(&self.shadow);
        }
    }

    // ── stats ────────────────────────────────────────────────────────────────

    #[must_use]
    pub fn live_alloc_count(&self) -> usize {
        self.live_allocs.lock().len()
    }

    #[must_use]
    pub fn quarantine_count(&self) -> usize {
        self.quarantine.len()
    }

    /// Generate a report of all violations detected.
    #[must_use]
    pub fn report(&self) -> AsanReport {
        AsanReport {
            total_violations: self.violation_count(),
            live_allocs: self.live_alloc_count(),
            quarantine_allocs: self.quarantine_count(),
            quarantine_bytes: self.quarantine.total_bytes(),
        }
    }
}

/// Summary report for an `ASan` runtime session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsanReport {
    pub total_violations: u64,
    pub live_allocs: usize,
    pub quarantine_allocs: usize,
    pub quarantine_bytes: u64,
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_address_mapping() {
        let addr = 0x7ffe_0000_1000u64;
        let shadow = app_to_shadow(addr);
        assert_eq!(shadow, (addr >> SHADOW_SCALE) + SHADOW_OFFSET);
    }

    #[test]
    fn shadow_mark_and_check() {
        let shadow = ShadowMemory::new();
        shadow.mark_accessible(0x1000, 16);
        assert!(shadow.check_access(0x1000, 4, false).is_ok());
        shadow.mark_region(0x1000, 8, SHADOW_LEFT_REDZONE);
        assert!(shadow.check_access(0x1000, 1, false).is_err());
    }

    #[test]
    fn quarantine_drain() {
        let q = QuarantineList::new(100);
        let a = HeapAlloc::new(0x2000, 32, vec![]);
        let size = a.raw_size as u64;
        q.enqueue(a);
        assert_eq!(q.total_bytes(), size);
        // capacity=100, size=64 → no drain needed
        let drained = q.drain_excess();
        assert!(drained.is_empty());
    }

    #[test]
    fn asan_runtime_alloc_and_overflow() {
        let rt = AsanRuntime::new(1024 * 1024);
        rt.on_alloc(0x3000, 8, vec![]);
        // Access within bounds → OK
        assert!(rt.on_load(0x3000, 4).is_ok());
        // Access in right redzone → error
        let err = rt.on_load(0x3008, 1);
        assert!(err.is_err());
    }

    #[test]
    fn asan_runtime_use_after_free() {
        let rt = AsanRuntime::new(1024 * 1024);
        rt.on_alloc(0x4000, 16, vec![]);
        rt.on_free(0x4000, vec![]).unwrap();
        let err = rt.on_load(0x4000, 1);
        assert!(matches!(err, Err(AsanError::HeapUseAfterFree { .. })));
    }

    #[test]
    fn asan_runtime_null_deref() {
        let rt = AsanRuntime::new(0);
        let err = rt.on_load(0, 1);
        assert!(matches!(err, Err(AsanError::NullDeref { .. })));
    }

    #[test]
    fn global_registration() {
        let rt = AsanRuntime::new(0);
        rt.register_globals(vec![GlobalDesc {
            addr: 0x5000,
            size: 8,
            size_with_redzone: 24,
            name: "g_buf".into(),
            module_name: "test".into(),
            has_dynamic_init: false,
        }]);
        assert!(rt.on_load(0x5000, 1).is_ok());
        // Redzone starts at 0x5008
        let err = rt.on_load(0x5008, 1);
        assert!(err.is_err());
    }

    #[test]
    fn fake_frame_poison() {
        let rt = AsanRuntime::new(0);
        let frame = FakeFrame::new(0x6000, 32, "foo");
        rt.push_fake_frame(frame);
        assert!(rt.on_load(0x6000, 4).is_ok());
        rt.pop_fake_frame(0x6000);
        let err = rt.on_load(0x6000, 1);
        assert!(matches!(err, Err(AsanError::UseAfterReturn { .. })));
    }
}
