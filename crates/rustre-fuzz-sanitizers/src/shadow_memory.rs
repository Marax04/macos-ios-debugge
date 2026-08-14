//! `ASAN` shadow memory model.
//!
//! Models `ASan`'s 1/8-scale shadow memory mapping.  Each application byte maps
//! to a `ShadowByte` in the shadow region.  The shadow byte encodes whether
//! the corresponding 8-byte granule is addressable, a redzone, freed, etc.

use std::collections::HashMap;
use std::fmt;

// ─── ShadowByte ───────────────────────────────────────────────────────────────

/// Possible states of a shadow byte (8-application-byte granule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShadowByte {
    /// All 8 bytes in the granule are addressable.
    Addressable,
    /// 1–7 bytes of the granule are addressable (partial; value = count).
    PartiallyAddressable(u8),
    /// Heap left redzone.
    HeapLeftRedzone,
    /// Heap right redzone.
    HeapRightRedzone,
    /// Freed heap memory.
    HeapFreed,
    /// Stack left redzone.
    StackLeftRedzone,
    /// Stack right redzone.
    StackRightRedzone,
    /// Global variable redzone.
    Global,
    /// Use-after-return (`ASan` stack use-after-return detection).
    UseAfterReturn,
    /// Use-after-scope (stack variable went out of scope).
    UseAfterScope,
    /// User-poisoned memory.
    UserPoisoned,
    /// Array cookie (C++ new[] overhead).
    ArrayCookie,
    /// Intra-object padding.
    IntraObjectPadding,
    /// `ASan`-internal (instrumentation overhead).
    Internal,
}

impl ShadowByte {
    /// Return `true` if access to this shadow granule is an error.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        !matches!(self, Self::Addressable | Self::PartiallyAddressable(_))
    }

    /// Encode to a raw i8 shadow value (`ASan` encoding).
    #[must_use]
    pub const fn to_raw(&self) -> i8 {
        match self {
            Self::Addressable => 0,
            Self::PartiallyAddressable(n) => (*n & 0x07).cast_signed(),
            Self::HeapLeftRedzone => -128,
            Self::HeapRightRedzone => -126,
            Self::HeapFreed => -125,
            Self::StackLeftRedzone => -16,
            Self::StackRightRedzone => -15,
            Self::Global => -5,
            Self::UseAfterReturn => -3,
            Self::UseAfterScope => -2,
            Self::UserPoisoned => -1,
            Self::ArrayCookie => -6,
            Self::IntraObjectPadding => -7,
            Self::Internal => -8,
        }
    }

    /// Decode from a raw i8 shadow value.
    #[must_use]
    pub const fn from_raw(v: i8) -> Self {
        match v {
            0 => Self::Addressable,
            1..=7 => Self::PartiallyAddressable(v.cast_unsigned()),
            -128 => Self::HeapLeftRedzone,
            -126 => Self::HeapRightRedzone,
            -125 => Self::HeapFreed,
            -16 => Self::StackLeftRedzone,
            -15 => Self::StackRightRedzone,
            -5 => Self::Global,
            -3 => Self::UseAfterReturn,
            -2 => Self::UseAfterScope,
            -1 => Self::UserPoisoned,
            -6 => Self::ArrayCookie,
            -7 => Self::IntraObjectPadding,
            -8 => Self::Internal,
            _ => Self::UserPoisoned,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Addressable => "addressable",
            Self::PartiallyAddressable(_) => "partially-addressable",
            Self::HeapLeftRedzone => "heap-left-redzone",
            Self::HeapRightRedzone => "heap-right-redzone",
            Self::HeapFreed => "heap-freed",
            Self::StackLeftRedzone => "stack-left-redzone",
            Self::StackRightRedzone => "stack-right-redzone",
            Self::Global => "global-redzone",
            Self::UseAfterReturn => "use-after-return",
            Self::UseAfterScope => "use-after-scope",
            Self::UserPoisoned => "user-poisoned",
            Self::ArrayCookie => "array-cookie",
            Self::IntraObjectPadding => "intra-object-padding",
            Self::Internal => "asan-internal",
        }
    }
}

impl fmt::Display for ShadowByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ─── ShadowMap ────────────────────────────────────────────────────────────────

/// Mapping parameters for the shadow memory region.
#[derive(Debug, Clone, Copy)]
pub struct ShadowMap {
    /// Base address of the shadow region in application address space.
    pub shadow_base: u64,
    /// Bit-shift for the 1/8 scale (= 3 for ASAN).
    pub scale_shift: u8,
    /// Offset added after shifting (platform-dependent).
    pub shadow_offset: u64,
}

impl ShadowMap {
    /// Standard 64-bit Linux ASAN shadow mapping.
    pub const LINUX_X86_64: Self = Self {
        shadow_base: 0x7FFF_8000_0000,
        scale_shift: 3,
        shadow_offset: 0x7FFF_8000_0000,
    };

    /// Standard 64-bit macOS ASAN shadow mapping.
    pub const MACOS_X86_64: Self = Self {
        shadow_base: 0x0001_0000_0000,
        scale_shift: 3,
        shadow_offset: 0x0001_0000_0000,
    };

    /// Create a custom shadow map.
    #[must_use]
    pub const fn new(shadow_base: u64, scale_shift: u8, shadow_offset: u64) -> Self {
        Self {
            shadow_base,
            scale_shift,
            shadow_offset,
        }
    }

    /// Compute the shadow address for application address `addr`.
    #[must_use]
    pub const fn shadow_addr_for(&self, addr: u64) -> u64 {
        (addr >> self.scale_shift).wrapping_add(self.shadow_offset)
    }

    /// Granule size in bytes (= `2^scale_shift` = 8 for `ASAN`).
    #[must_use]
    pub const fn granule_size(&self) -> u64 {
        1u64 << self.scale_shift
    }
}

// ─── ShadowMemory ─────────────────────────────────────────────────────────────

/// Sparse shadow memory model.
///
/// Stores `ShadowByte` values for 8-byte granules (each granule covers one
/// shadow byte).  The map is sparse: only poisoned or tracked granules
/// occupy space.
#[derive(Debug, Default)]
pub struct ShadowMemory {
    /// `granule_index → shadow_byte`.  Granule index = `addr / 8`.
    shadow: HashMap<u64, ShadowByte>,
    /// Shadow map parameters.
    pub map: Option<ShadowMap>,
}

impl ShadowMemory {
    /// Create empty shadow memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the shadow map.
    #[must_use]
    pub const fn with_map(mut self, map: ShadowMap) -> Self {
        self.map = Some(map);
        self
    }

    /// Granule index for an address.
    #[must_use]
    pub const fn granule_index(addr: u64) -> u64 {
        addr / 8
    }

    /// Read the shadow byte for `addr`.
    #[must_use]
    pub fn read(&self, addr: u64) -> ShadowByte {
        let idx = Self::granule_index(addr);
        self.shadow
            .get(&idx)
            .copied()
            .unwrap_or(ShadowByte::Addressable)
    }

    /// Write a shadow byte for `addr`.
    pub fn write(&mut self, addr: u64, state: ShadowByte) {
        let idx = Self::granule_index(addr);
        if state == ShadowByte::Addressable {
            self.shadow.remove(&idx);
        } else {
            self.shadow.insert(idx, state);
        }
    }

    /// Poison a range `[addr, addr + size)` with `state`.
    pub fn poison(&mut self, addr: u64, size: u64, state: ShadowByte) {
        let granule = 8u64;
        let first = addr / granule;
        // `addr` and `size` come from the caller. A plain `addr + size`
        // overflows near the top of the address space: with overflow checks on
        // it panics, and without them it wraps to a small value, making
        // `first..last` an EMPTY range — so the poison would silently not be
        // applied and an out-of-range access would silently be reported valid.
        let last = addr.saturating_add(size).div_ceil(granule);
        for g in first..last {
            self.shadow.insert(g, state);
        }
    }

    /// Unpoison a range `[addr, addr + size)`.
    pub fn unpoison(&mut self, addr: u64, size: u64) {
        let granule = 8u64;
        let first = addr / granule;
        // `addr` and `size` come from the caller. A plain `addr + size`
        // overflows near the top of the address space: with overflow checks on
        // it panics, and without them it wraps to a small value, making
        // `first..last` an EMPTY range — so the poison would silently not be
        // applied and an out-of-range access would silently be reported valid.
        let last = addr.saturating_add(size).div_ceil(granule);
        for g in first..last {
            self.shadow.remove(&g);
        }
    }

    /// Check if accessing `[addr, addr + size)` would be an `ASan` error.
    #[must_use]
    pub fn is_access_valid(&self, addr: u64, size: u64) -> bool {
        let granule = 8u64;
        let first = addr / granule;
        // `addr` and `size` come from the caller. A plain `addr + size`
        // overflows near the top of the address space: with overflow checks on
        // it panics, and without them it wraps to a small value, making
        // `first..last` an EMPTY range — so the poison would silently not be
        // applied and an out-of-range access would silently be reported valid.
        let last = addr.saturating_add(size).div_ceil(granule);
        for g in first..last {
            let sb = self
                .shadow
                .get(&g)
                .copied()
                .unwrap_or(ShadowByte::Addressable);
            if sb.is_poisoned() {
                return false;
            }
        }
        true
    }

    /// Find the first poisoned granule in `[addr, addr + size)`.
    #[must_use]
    pub fn first_poison(&self, addr: u64, size: u64) -> Option<(u64, ShadowByte)> {
        let granule = 8u64;
        let first = addr / granule;
        // `addr` and `size` come from the caller. A plain `addr + size`
        // overflows near the top of the address space: with overflow checks on
        // it panics, and without them it wraps to a small value, making
        // `first..last` an EMPTY range — so the poison would silently not be
        // applied and an out-of-range access would silently be reported valid.
        let last = addr.saturating_add(size).div_ceil(granule);
        for g in first..last {
            if let Some(&sb) = self.shadow.get(&g)
                && sb.is_poisoned()
            {
                return Some((g * granule, sb));
            }
        }
        None
    }

    /// Number of poisoned granules.
    #[must_use]
    pub fn poisoned_count(&self) -> usize {
        self.shadow.values().filter(|s| s.is_poisoned()).count()
    }
}

// ─── AddressValidator ─────────────────────────────────────────────────────────

/// Validate memory accesses against a shadow memory model.
#[derive(Debug, Default)]
pub struct AddressValidator {
    shadow: ShadowMemory,
    /// Total checks performed.
    pub check_count: u64,
    /// Total violations detected.
    pub violation_count: u64,
}

impl AddressValidator {
    /// Create a validator backed by a fresh shadow memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Give access to the underlying shadow memory.
    pub const fn shadow_mut(&mut self) -> &mut ShadowMemory {
        &mut self.shadow
    }

    /// Check if `[addr, addr+size)` is valid.  Updates statistics.
    pub fn check(&mut self, addr: u64, size: u64) -> bool {
        self.check_count += 1;
        let valid = self.shadow.is_access_valid(addr, size);
        if !valid {
            self.violation_count += 1;
        }
        valid
    }

    /// Violation ratio.
    #[must_use]
    pub fn violation_rate(&self) -> f64 {
        if self.check_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.violation_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.check_count).unwrap_or(u32::MAX))
        }
    }
}

// ─── HeapRedzone ──────────────────────────────────────────────────────────────

/// Model of a heap redzone surrounding an allocation.
#[derive(Debug, Clone)]
pub struct HeapRedzone {
    /// Address of the allocation (user-visible pointer).
    pub user_addr: u64,
    /// Size of the user allocation.
    pub user_size: u64,
    /// Redzone size on left.
    pub left_redzone: u64,
    /// Redzone size on right.
    pub right_redzone: u64,
}

impl HeapRedzone {
    /// Default redzone size for most allocators.
    pub const DEFAULT_REDZONE: u64 = 16;

    /// Create a standard heap redzone.
    #[must_use]
    pub const fn new(user_addr: u64, user_size: u64) -> Self {
        Self {
            user_addr,
            user_size,
            left_redzone: Self::DEFAULT_REDZONE,
            right_redzone: Self::DEFAULT_REDZONE,
        }
    }

    /// Apply redzones to a shadow memory.
    pub fn apply(&self, shadow: &mut ShadowMemory) {
        let alloc_start = self.user_addr.saturating_sub(self.left_redzone);
        shadow.poison(alloc_start, self.left_redzone, ShadowByte::HeapLeftRedzone);
        shadow.unpoison(self.user_addr, self.user_size);
        let right_start = self.user_addr.saturating_add(self.user_size);
        shadow.poison(
            right_start,
            self.right_redzone,
            ShadowByte::HeapRightRedzone,
        );
    }

    /// Remove redzones and poison the user region as freed.
    pub fn free(&self, shadow: &mut ShadowMemory) {
        let alloc_start = self.user_addr.saturating_sub(self.left_redzone);
        let total = self.chunk_size();
        shadow.poison(alloc_start, total, ShadowByte::HeapFreed);
    }

    /// Total chunk size (`left_redzone` + user + `right_redzone`).
    #[must_use]
    pub const fn chunk_size(&self) -> u64 {
        // Every term is caller-supplied, so the sum can overflow.
        self.left_redzone
            .saturating_add(self.user_size)
            .saturating_add(self.right_redzone)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ShadowByte ────────────────────────────────────────────────────────────

    #[test]
    fn shadow_byte_addressable_not_poisoned() {
        assert!(!ShadowByte::Addressable.is_poisoned());
    }

    #[test]
    fn shadow_byte_freed_is_poisoned() {
        assert!(ShadowByte::HeapFreed.is_poisoned());
    }

    #[test]
    fn shadow_byte_raw_roundtrip() {
        for &sb in &[
            ShadowByte::Addressable,
            ShadowByte::HeapLeftRedzone,
            ShadowByte::HeapRightRedzone,
            ShadowByte::HeapFreed,
            ShadowByte::StackLeftRedzone,
            ShadowByte::Global,
            ShadowByte::UserPoisoned,
        ] {
            let raw = sb.to_raw();
            let back = ShadowByte::from_raw(raw);
            assert_eq!(sb, back, "failed roundtrip for {sb:?}");
        }
    }

    #[test]
    fn shadow_byte_partially_addressable() {
        let sb = ShadowByte::PartiallyAddressable(4);
        assert!(!sb.is_poisoned());
        assert_eq!(sb.to_raw(), 4);
    }

    #[test]
    fn shadow_byte_display() {
        assert_eq!(ShadowByte::HeapFreed.to_string(), "heap-freed");
        assert_eq!(ShadowByte::Addressable.to_string(), "addressable");
    }

    // ── ShadowMap ─────────────────────────────────────────────────────────────

    #[test]
    fn shadow_map_granule_size() {
        assert_eq!(ShadowMap::LINUX_X86_64.granule_size(), 8);
    }

    #[test]
    fn shadow_map_addr_for() {
        let map = ShadowMap::LINUX_X86_64;
        let shadow = map.shadow_addr_for(0x1000);
        // (0x1000 >> 3) + offset
        assert_eq!(shadow, (0x1000u64 >> 3).wrapping_add(0x7FFF_8000_0000));
    }

    // ── ShadowMemory ──────────────────────────────────────────────────────────

    #[test]
    fn shadow_memory_read_unset_is_addressable() {
        let sm = ShadowMemory::new();
        assert_eq!(sm.read(0x1000), ShadowByte::Addressable);
    }

    #[test]
    fn shadow_memory_write_read() {
        let mut sm = ShadowMemory::new();
        sm.write(0x1000, ShadowByte::HeapFreed);
        assert_eq!(sm.read(0x1000), ShadowByte::HeapFreed);
    }

    #[test]
    fn shadow_memory_write_addressable_removes() {
        let mut sm = ShadowMemory::new();
        sm.write(0x1000, ShadowByte::UserPoisoned);
        sm.write(0x1000, ShadowByte::Addressable);
        assert_eq!(sm.poisoned_count(), 0);
    }

    #[test]
    fn shadow_memory_poison_range() {
        let mut sm = ShadowMemory::new();
        sm.poison(0x1000, 32, ShadowByte::HeapLeftRedzone);
        assert!(sm.poisoned_count() >= 1);
    }

    #[test]
    fn shadow_memory_unpoison_range() {
        let mut sm = ShadowMemory::new();
        sm.poison(0x1000, 64, ShadowByte::UserPoisoned);
        sm.unpoison(0x1000, 64);
        assert_eq!(sm.poisoned_count(), 0);
    }

    #[test]
    fn shadow_memory_access_valid() {
        let sm = ShadowMemory::new();
        assert!(sm.is_access_valid(0x1000, 8));
    }

    #[test]
    fn shadow_memory_access_invalid() {
        let mut sm = ShadowMemory::new();
        sm.poison(0x2000, 8, ShadowByte::HeapFreed);
        assert!(!sm.is_access_valid(0x2000, 8));
    }

    #[test]
    fn shadow_memory_first_poison() {
        let mut sm = ShadowMemory::new();
        sm.poison(0x3010, 8, ShadowByte::StackRightRedzone);
        let r = sm.first_poison(0x3000, 32);
        assert!(r.is_some());
    }

    // ── AddressValidator ──────────────────────────────────────────────────────

    #[test]
    fn validator_valid_check() {
        let mut v = AddressValidator::new();
        assert!(v.check(0x1000, 4));
        assert_eq!(v.check_count, 1);
        assert_eq!(v.violation_count, 0);
    }

    #[test]
    fn validator_violation_detected() {
        let mut v = AddressValidator::new();
        v.shadow_mut().poison(0x5000, 8, ShadowByte::HeapFreed);
        assert!(!v.check(0x5000, 4));
        assert_eq!(v.violation_count, 1);
    }

    #[test]
    fn validator_violation_rate() {
        let mut v = AddressValidator::new();
        v.check(0x1000, 1); // valid
        v.shadow_mut().poison(0x2000, 8, ShadowByte::UserPoisoned);
        v.check(0x2000, 1); // invalid
        assert!((v.violation_rate() - 0.5).abs() < f64::EPSILON);
    }

    // ── HeapRedzone ───────────────────────────────────────────────────────────

    #[test]
    fn heap_redzone_apply_and_check() {
        let mut sm = ShadowMemory::new();
        let rz = HeapRedzone::new(0x2010, 32);
        rz.apply(&mut sm);
        // User region should be valid
        assert!(sm.is_access_valid(0x2010, 32));
        // Left redzone should be poisoned
        assert!(!sm.is_access_valid(0x2000, 8));
        // Right redzone should be poisoned
        assert!(!sm.is_access_valid(0x2030, 8));
    }

    #[test]
    fn heap_redzone_free() {
        let mut sm = ShadowMemory::new();
        let rz = HeapRedzone::new(0x3000, 16);
        rz.apply(&mut sm);
        rz.free(&mut sm);
        // After free, user region should be poisoned
        assert!(!sm.is_access_valid(0x3000, 16));
    }

    #[test]
    fn heap_redzone_chunk_size() {
        let rz = HeapRedzone::new(0x1000, 100);
        assert_eq!(rz.chunk_size(), 100 + 16 + 16);
    }
}
