//! Address types and arithmetic for the RustRE platform.
//!
//! This module provides strongly-typed address newtypes that prevent accidental
//! mixing of virtual addresses, physical addresses, relative virtual addresses
//! (RVAs), and file offsets.
//!
//! Key types:
//! - [`Address`] — the canonical virtual address (wraps `u64`).
//! - [`VirtualAddress`] — explicit virtual-address newtype (alias semantics).
//! - [`PhysicalAddress`] — explicit physical-address newtype.
//! - [`RVA`] — relative virtual address (`u32`, as in PE files).
//! - [`FileOffset`] — byte offset within the binary file.
//! - [`AddressRange`] — a `[start, end)` half-open range with rich helpers.
//! - [`FileOffsetRange`] — same concept for file offsets.
//! - [`AddressSpace`] — an annotated map of ranges to metadata.
//! - [`AddressTranslation`] — trait for converting between address spaces.
//! - [`SegmentMapping`] — links a virtual range to a file range.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

// ─────────────────────────────────────────────────────────────────────────────
// Address
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual memory address.
///
/// All arithmetic is wrapping to handle 64-bit overflows gracefully.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct Address(pub u64);

impl Address {
    /// The null / zero address.
    pub const NULL: Self = Self(0);

    /// Create an `Address` from a `u64`.
    #[must_use]
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw `u64` value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Apply a signed offset (wrapping arithmetic).
    #[must_use]
    pub const fn offset(self, offset: i64) -> Self {
        if offset >= 0 {
            Self(self.0.wrapping_add(offset.cast_unsigned()))
        } else {
            Self(self.0.wrapping_sub(offset.unsigned_abs()))
        }
    }

    /// Round *up* to the next multiple of `align`.
    ///
    /// Returns `self` unchanged if already aligned or if `align <= 1`.
    #[must_use]
    pub const fn align_up(self, align: u64) -> Self {
        if align <= 1 {
            return self;
        }
        let remainder = self.0 % align;
        if remainder == 0 {
            self
        } else {
            Self(self.0.wrapping_add(align - remainder))
        }
    }

    /// Round *down* to the previous multiple of `align`.
    ///
    /// # Panics
    /// Panics if `align` is not a power of two and `align > 1`.
    #[must_use]
    pub const fn align_down(self, align: u64) -> Self {
        if align <= 1 {
            return self;
        }
        assert!(align.is_power_of_two(), "align must be a power of two");
        Self(self.0 & !(align - 1))
    }

    /// Return `true` if this address is aligned to `align`.
    #[must_use]
    pub const fn is_aligned(self, align: u64) -> bool {
        if align <= 1 {
            true
        } else {
            self.0.is_multiple_of(align)
        }
    }

    /// Checked add: returns `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked sub: returns `None` on underflow.
    #[must_use]
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        match self.0.checked_sub(rhs) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Return `true` if this address is null (zero).
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Distance to another address, or `None` if `other < self`.
    #[must_use]
    pub const fn distance_to(self, other: Self) -> Option<u64> {
        if other.0 >= self.0 {
            Some(other.0 - self.0)
        } else {
            None
        }
    }

    /// Saturating subtraction of two `Address` values.
    #[must_use]
    pub const fn saturating_diff(self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }

    /// Convert to a 32-bit truncated value (useful for 32-bit targets).
    #[must_use]
    pub fn as_u32(self) -> u32 {
        u32::try_from(self.0).unwrap_or(u32::MAX)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Add<u64> for Address {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl AddAssign<u64> for Address {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl Sub<u64> for Address {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl SubAssign<u64> for Address {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_sub(rhs);
    }
}

impl Sub<Self> for Address {
    type Output = u64;
    fn sub(self, rhs: Self) -> u64 {
        self.0.saturating_sub(rhs.0)
    }
}

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<u32> for Address {
    fn from(v: u32) -> Self {
        Self(u64::from(v))
    }
}

impl From<Address> for u64 {
    fn from(a: Address) -> Self {
        a.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualAddress & PhysicalAddress — distinct newtypes
// ─────────────────────────────────────────────────────────────────────────────

/// An explicit virtual (mapped) address.
///
/// Semantically identical to [`Address`] but with a distinct type to prevent
/// accidental mixing with [`PhysicalAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    /// Wrap a raw value.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Convert to an untyped [`Address`].
    #[must_use]
    pub const fn as_address(self) -> Address {
        Address(self.0)
    }
}

impl fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VA(0x{:X})", self.0)
    }
}

impl From<Address> for VirtualAddress {
    fn from(a: Address) -> Self {
        Self(a.0)
    }
}

impl From<VirtualAddress> for Address {
    fn from(v: VirtualAddress) -> Self {
        Self(v.0)
    }
}

/// An explicit physical (hardware) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct PhysicalAddress(pub u64);

impl PhysicalAddress {
    /// Wrap a raw value.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PA(0x{:X})", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RVA — Relative Virtual Address
// ─────────────────────────────────────────────────────────────────────────────

/// A 32-bit relative virtual address (as used in PE files).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct RVA(pub u32);

impl RVA {
    /// Zero / null RVA.
    pub const NULL: Self = Self(0);

    /// Wrap a raw `u32`.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Resolve this RVA against a base address.
    #[must_use]
    pub const fn resolve(self, base: Address) -> Address {
        Address(base.0.wrapping_add(self.0 as u64))
    }

    /// Return `true` if this RVA is zero.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for RVA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RVA(0x{:X})", self.0)
    }
}

impl Add<u32> for RVA {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Sub<u32> for RVA {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileOffset
// ─────────────────────────────────────────────────────────────────────────────

/// A byte offset within a binary file (as opposed to a virtual address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct FileOffset(pub u64);

impl FileOffset {
    /// Zero offset.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw `u64`.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return `true` if this is the zero offset.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Checked add.
    #[must_use]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl fmt::Display for FileOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileOff(0x{:X})", self.0)
    }
}

impl Add<u64> for FileOffset {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Sub<u64> for FileOffset {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl From<u64> for FileOffset {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<FileOffset> for u64 {
    fn from(f: FileOffset) -> Self {
        f.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressRange
// ─────────────────────────────────────────────────────────────────────────────

/// A half-open address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AddressRange {
    /// Inclusive lower bound.
    pub start: Address,
    /// Exclusive upper bound.
    pub end: Address,
}

impl AddressRange {
    /// Construct a range.  `end` may equal `start` (empty range).
    #[must_use]
    pub const fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Create a range from a start and a byte length.
    ///
    /// # Panics
    /// Does not panic; overflow silently wraps.
    #[must_use]
    pub const fn from_len(start: Address, len: u64) -> Self {
        Self {
            start,
            end: Address(start.0.wrapping_add(len)),
        }
    }

    /// Byte length of the range.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    /// Return `true` if the range has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start.0 >= self.end.0
    }

    /// Return `true` if `addr` is contained within `[start, end)`.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr.0 >= self.start.0 && addr.0 < self.end.0
    }

    /// Return `true` if `addr` falls within `[start, end]` (inclusive).
    #[must_use]
    pub const fn contains_inclusive(&self, addr: Address) -> bool {
        addr.0 >= self.start.0 && addr.0 <= self.end.0
    }

    /// Return `true` if `other` overlaps with `self` (non-empty intersection).
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        self.start.0 < other.end.0 && other.start.0 < self.end.0
    }

    /// Alias for `overlaps`.
    #[must_use]
    pub const fn intersects(&self, other: &Self) -> bool {
        self.overlaps(other)
    }

    /// Return `true` if `other` is directly adjacent (either before or after).
    #[must_use]
    pub const fn adjacent(&self, other: &Self) -> bool {
        self.end.0 == other.start.0 || other.end.0 == self.start.0
    }

    /// Return `true` if `other` is completely contained within `self`.
    #[must_use]
    pub const fn contains_range(&self, other: &Self) -> bool {
        other.start.0 >= self.start.0 && other.end.0 <= self.end.0
    }

    /// Return the intersection of `self` and `other`, or `None` if disjoint.
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        let start = if self.start.0 > other.start.0 {
            self.start
        } else {
            other.start
        };
        let end = if self.end.0 < other.end.0 {
            self.end
        } else {
            other.end
        };
        if start.0 < end.0 {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Merge two ranges into their bounding range (hull).
    ///
    /// The result spans from `min(self.start, other.start)` to
    /// `max(self.end, other.end)`.
    #[must_use]
    pub const fn merge(&self, other: &Self) -> Self {
        let start = if self.start.0 < other.start.0 {
            self.start
        } else {
            other.start
        };
        let end = if self.end.0 > other.end.0 {
            self.end
        } else {
            other.end
        };
        Self { start, end }
    }

    /// Split this range at `addr`, returning `(left, right)`.
    ///
    /// `left = [self.start, addr)` and `right = [addr, self.end)`.
    ///
    /// Returns `None` if `addr` is not strictly inside the range.
    #[must_use]
    pub const fn split_at(&self, addr: Address) -> Option<(Self, Self)> {
        if addr.0 <= self.start.0 || addr.0 >= self.end.0 {
            return None;
        }
        Some((
            Self {
                start: self.start,
                end: addr,
            },
            Self {
                start: addr,
                end: self.end,
            },
        ))
    }

    /// Return an iterator over every `Address` in `[start, end)` with a
    /// given step size.
    ///
    /// Use `step = 1` for byte-by-byte iteration, `step = 4` for word-by-word, etc.
    pub fn iter_step(&self, step: u64) -> impl Iterator<Item = Address> {
        let start = self.start.0;
        let end = self.end.0;
        let s = step.max(1);
        (0..)
            .map(move |i| Address(start.wrapping_add(i * s)))
            .take_while(move |a| a.0 < end)
    }

    /// Iterate over every `Address` in `[start, end)` one byte at a time.
    pub fn iter(&self) -> impl Iterator<Item = Address> {
        self.iter_step(1)
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileOffsetRange
// ─────────────────────────────────────────────────────────────────────────────

/// A half-open file-offset range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileOffsetRange {
    /// Inclusive lower bound.
    pub start: FileOffset,
    /// Exclusive upper bound.
    pub end: FileOffset,
}

impl FileOffsetRange {
    /// Construct a file-offset range.
    #[must_use]
    pub const fn new(start: FileOffset, end: FileOffset) -> Self {
        Self { start, end }
    }

    /// Create a range from a start offset and a byte length.
    #[must_use]
    pub const fn from_len(start: FileOffset, len: u64) -> Self {
        Self {
            start,
            end: FileOffset(start.0.wrapping_add(len)),
        }
    }

    /// Byte length of the range.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    /// Return `true` if the range has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start.0 >= self.end.0
    }

    /// Return `true` if `offset` is inside the range.
    #[must_use]
    pub const fn contains(&self, offset: FileOffset) -> bool {
        offset.0 >= self.start.0 && offset.0 < self.end.0
    }
}

impl fmt::Display for FileOffsetRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileRange[{}, {})", self.start, self.end)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SegmentMapping — maps a virtual range to a file range
// ─────────────────────────────────────────────────────────────────────────────

/// Links a virtual-address range to its backing file range.
///
/// This is the core data structure for computing `VA ↔ file_offset`
/// translations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentMapping {
    /// Virtual address range occupied by this segment.
    pub virtual_range: AddressRange,
    /// Corresponding file-offset range (may be smaller than `virtual_range`).
    pub file_range: FileOffsetRange,
    /// Human-readable name (e.g. `".text"`, `"LOAD"`, `"CODE"`).
    pub name: Option<String>,
}

impl SegmentMapping {
    /// Create a new segment mapping.
    #[must_use]
    pub const fn new(virtual_range: AddressRange, file_range: FileOffsetRange) -> Self {
        Self {
            virtual_range,
            file_range,
            name: None,
        }
    }

    /// Attach a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Convert a virtual address within this segment to a file offset.
    ///
    /// Returns `None` if `addr` is not within the virtual range.
    #[must_use]
    pub fn va_to_file_offset(&self, addr: Address) -> Option<FileOffset> {
        if !self.virtual_range.contains(addr) {
            return None;
        }
        let delta = addr.0 - self.virtual_range.start.0;
        let raw = self.file_range.start.0.checked_add(delta)?;
        if raw < self.file_range.end.0 {
            Some(FileOffset(raw))
        } else {
            None
        }
    }

    /// Convert a file offset within this segment to a virtual address.
    ///
    /// Returns `None` if `offset` is not within the file range.
    #[must_use]
    pub fn file_offset_to_va(&self, offset: FileOffset) -> Option<Address> {
        if !self.file_range.contains(offset) {
            return None;
        }
        let delta = offset.0 - self.file_range.start.0;
        let raw = self.virtual_range.start.0.checked_add(delta)?;
        if raw < self.virtual_range.end.0 {
            Some(Address(raw))
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressTranslation trait
// ─────────────────────────────────────────────────────────────────────────────

/// Conversion between address spaces for objects that carry segment mappings
/// (e.g. `BinaryView`, loaders).
pub trait AddressTranslation {
    /// Convert a virtual address to an RVA relative to `image_base`.
    ///
    /// # Errors
    /// Returns `None` if the address is below the image base.
    fn to_rva(&self, addr: Address, image_base: Address) -> Option<RVA>;

    /// Resolve an RVA against `image_base` back to a virtual address.
    fn rva_to_va(&self, rva: RVA, image_base: Address) -> Address;

    /// Translate a virtual address to a file offset using the segment table.
    ///
    /// Returns `None` if no segment covers the address.
    fn to_file_offset(&self, addr: Address) -> Option<FileOffset>;

    /// Translate a file offset back to a virtual address.
    ///
    /// Returns `None` if no segment covers the offset.
    fn file_offset_to_va(&self, offset: FileOffset) -> Option<Address>;
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressSpace — annotated range map
// ─────────────────────────────────────────────────────────────────────────────

/// A metadata entry in an [`AddressSpace`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressSpaceEntry<M> {
    /// The virtual-address range.
    pub range: AddressRange,
    /// Metadata associated with this range.
    pub meta: M,
}

/// A map from address ranges to metadata.
///
/// Backed by a sorted `Vec` for simplicity; suitable for dozens to hundreds
/// of entries (enough for binary sections/segments).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressSpace<M> {
    entries: Vec<AddressSpaceEntry<M>>,
}

impl<M: Clone + std::fmt::Debug> AddressSpace<M> {
    /// Create an empty address space.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a mapping.  Does not check for overlaps.
    pub fn insert(&mut self, range: AddressRange, meta: M) {
        self.entries.push(AddressSpaceEntry { range, meta });
        self.entries.sort_unstable_by_key(|e| e.range.start);
    }

    /// Find the first entry whose range contains `addr`.
    #[must_use]
    pub fn find(&self, addr: Address) -> Option<&AddressSpaceEntry<M>> {
        self.entries.iter().find(|e| e.range.contains(addr))
    }

    /// Find all entries whose range overlaps with `range`.
    #[must_use]
    pub fn find_overlapping(&self, range: &AddressRange) -> Vec<&AddressSpaceEntry<M>> {
        self.entries
            .iter()
            .filter(|e| e.range.overlaps(range))
            .collect()
    }

    /// Iterate over all entries in order.
    pub fn iter(&self) -> impl Iterator<Item = &AddressSpaceEntry<M>> {
        self.entries.iter()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the space has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove the entry containing `addr`.  Returns the removed entry if any.
    pub fn remove_containing(&mut self, addr: Address) -> Option<AddressSpaceEntry<M>> {
        if let Some(idx) = self.entries.iter().position(|e| e.range.contains(addr)) {
            Some(self.entries.remove(idx))
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy TypedAddress (kept for compatibility)
// ─────────────────────────────────────────────────────────────────────────────

/// An address tagged with the address space it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypedAddress {
    /// The address value.
    pub address: Address,
    /// Which address space.
    pub space: AddressSpaceKind,
}

/// Enumeration of well-known address spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AddressSpaceKind {
    /// Default virtual address space.
    Default,
    /// Physical RAM address space.
    Physical,
    /// Memory-mapped I/O space.
    IOSpace,
    /// Stack address space.
    Stack,
    /// Heap address space.
    Heap,
    /// Register file (conceptual space).
    Register,
    /// Architecture / platform specific.
    Custom(u16),
}

impl TypedAddress {
    /// Create a typed address in the default space.
    #[must_use]
    pub const fn new(address: Address, space: AddressSpaceKind) -> Self {
        Self { address, space }
    }

    /// Return `true` if this address is in the default virtual space.
    #[must_use]
    pub const fn is_virtual(self) -> bool {
        matches!(self.space, AddressSpaceKind::Default)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Address ───────────────────────────────────────────────────────────────

    #[test]
    fn address_arithmetic() {
        let a = Address::new(0x1000);
        assert_eq!((a + 0x10).as_u64(), 0x1010);
        assert_eq!((a - 0x10).as_u64(), 0x0FF0);
        assert_eq!(a.offset(0x20).as_u64(), 0x1020);
        assert_eq!(a.offset(-0x20).as_u64(), 0x0FE0);
    }

    #[test]
    fn address_align_up_down() {
        assert_eq!(Address::new(0x1005).align_up(0x10), Address::new(0x1010));
        assert_eq!(Address::new(0x1000).align_up(0x10), Address::new(0x1000));
        assert_eq!(Address::new(0x1005).align_down(0x10), Address::new(0x1000));
        assert_eq!(Address::new(0x1000).align_down(0x10), Address::new(0x1000));
    }

    #[test]
    fn address_is_aligned() {
        assert!(Address::new(0x1000).is_aligned(0x1000));
        assert!(!Address::new(0x1001).is_aligned(2));
        assert!(Address::new(0x1002).is_aligned(2));
    }

    #[test]
    fn address_checked_add_sub() {
        assert_eq!(Address::new(u64::MAX).checked_add(1), None);
        assert_eq!(Address::new(0).checked_sub(1), None);
        assert_eq!(Address::new(10).checked_add(5), Some(Address::new(15)));
        assert_eq!(Address::new(10).checked_sub(5), Some(Address::new(5)));
    }

    #[test]
    fn address_distance_to() {
        assert_eq!(
            Address::new(0x100).distance_to(Address::new(0x200)),
            Some(0x100)
        );
        assert_eq!(Address::new(0x200).distance_to(Address::new(0x100)), None);
    }

    #[test]
    fn address_display() {
        assert_eq!(Address::new(0xDEAD_BEEF).to_string(), "0xDEADBEEF");
    }

    #[test]
    fn address_from_into_u64() {
        let a: Address = 0x1234u64.into();
        let v: u64 = a.into();
        assert_eq!(v, 0x1234);
    }

    #[test]
    fn address_from_u32() {
        let a = Address::from(0xFF_FFu32);
        assert_eq!(a.as_u64(), 0xFF_FF);
    }

    #[test]
    fn address_null() {
        assert!(Address::NULL.is_null());
        assert!(!Address::new(1).is_null());
    }

    // ── VirtualAddress & PhysicalAddress ──────────────────────────────────────

    #[test]
    fn virtual_physical_distinct() {
        let va = VirtualAddress::new(0x4000);
        let pa = PhysicalAddress::new(0x4000);
        assert_eq!(va.as_u64(), pa.as_u64());
        assert_eq!(va.as_address(), Address::new(0x4000));
        let _ = pa.to_string();
        let _ = va.to_string();
    }

    #[test]
    fn virtual_address_from_address() {
        let a = Address::new(0xCAFE);
        let va = VirtualAddress::from(a);
        let back = Address::from(va);
        assert_eq!(a, back);
    }

    // ── RVA ───────────────────────────────────────────────────────────────────

    #[test]
    fn rva_resolve() {
        let rva = RVA::new(0x1000);
        let base = Address::new(0x4000_0000);
        assert_eq!(rva.resolve(base), Address::new(0x4000_1000));
    }

    #[test]
    fn rva_null() {
        assert!(RVA::NULL.is_null());
        assert!(!RVA::new(1).is_null());
    }

    #[test]
    fn rva_arithmetic() {
        let r = RVA::new(0x100) + 0x10;
        assert_eq!(r.as_u32(), 0x110);
        let r2 = r - 0x10;
        assert_eq!(r2, RVA::new(0x100));
    }

    // ── FileOffset ────────────────────────────────────────────────────────────

    #[test]
    fn file_offset_basic() {
        let fo = FileOffset::new(0x200);
        assert_eq!(fo.as_u64(), 0x200);
        assert!(!fo.is_zero());
        assert!(FileOffset::ZERO.is_zero());
    }

    #[test]
    fn file_offset_checked_add() {
        assert_eq!(FileOffset::new(u64::MAX).checked_add(1), None);
        assert_eq!(
            FileOffset::new(100).checked_add(50),
            Some(FileOffset::new(150))
        );
    }

    // ── AddressRange ──────────────────────────────────────────────────────────

    #[test]
    fn range_contains() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        assert!(r.contains(Address::new(0x1000)));
        assert!(r.contains(Address::new(0x1FFF)));
        assert!(!r.contains(Address::new(0x2000)));
        assert!(!r.contains(Address::new(0x0FFF)));
    }

    #[test]
    fn range_len() {
        let r = AddressRange::from_len(Address::new(0x1000), 0x100);
        assert_eq!(r.len(), 0x100);
        assert!(!r.is_empty());
    }

    #[test]
    fn range_empty() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x1000));
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn range_overlaps() {
        let a = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let b = AddressRange::new(Address::new(0x1800), Address::new(0x2800));
        let c = AddressRange::new(Address::new(0x3000), Address::new(0x4000));
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn range_adjacent() {
        let a = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let b = AddressRange::new(Address::new(0x2000), Address::new(0x3000));
        assert!(a.adjacent(&b));
        let c = AddressRange::new(Address::new(0x3000), Address::new(0x4000));
        assert!(!a.adjacent(&c));
    }

    #[test]
    fn range_merge() {
        let a = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let b = AddressRange::new(Address::new(0x1800), Address::new(0x3000));
        let m = a.merge(&b);
        assert_eq!(m.start, Address::new(0x1000));
        assert_eq!(m.end, Address::new(0x3000));
    }

    #[test]
    fn range_split_at() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x3000));
        let (left, right) = r.split_at(Address::new(0x2000)).unwrap();
        assert_eq!(left.end, Address::new(0x2000));
        assert_eq!(right.start, Address::new(0x2000));
        assert_eq!(right.end, Address::new(0x3000));
        assert!(r.split_at(Address::new(0x1000)).is_none());
        assert!(r.split_at(Address::new(0x3000)).is_none());
    }

    #[test]
    fn range_intersection() {
        let a = AddressRange::new(Address::new(0x1000), Address::new(0x3000));
        let b = AddressRange::new(Address::new(0x2000), Address::new(0x4000));
        let i = a.intersection(&b).unwrap();
        assert_eq!(i.start, Address::new(0x2000));
        assert_eq!(i.end, Address::new(0x3000));

        let c = AddressRange::new(Address::new(0x5000), Address::new(0x6000));
        assert!(a.intersection(&c).is_none());
    }

    #[test]
    fn range_contains_range() {
        let outer = AddressRange::new(Address::new(0x1000), Address::new(0x5000));
        let inner = AddressRange::new(Address::new(0x2000), Address::new(0x3000));
        assert!(outer.contains_range(&inner));
        assert!(!inner.contains_range(&outer));
    }

    #[test]
    fn range_iter() {
        let r = AddressRange::new(Address::new(10), Address::new(14));
        let addrs: Vec<u64> = r.iter().map(super::Address::as_u64).collect();
        assert_eq!(addrs, [10, 11, 12, 13]);
    }

    #[test]
    fn range_iter_step() {
        let r = AddressRange::new(Address::new(0), Address::new(12));
        let addrs: Vec<u64> = r.iter_step(4).map(super::Address::as_u64).collect();
        assert_eq!(addrs, [0, 4, 8]);
    }

    #[test]
    fn range_display() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let s = r.to_string();
        assert!(s.contains("0x1000") || s.contains("1000"));
    }

    // ── FileOffsetRange ───────────────────────────────────────────────────────

    #[test]
    fn file_range_basic() {
        let r = FileOffsetRange::from_len(FileOffset::new(0x100), 0x200);
        assert_eq!(r.len(), 0x200);
        assert!(!r.is_empty());
        assert!(r.contains(FileOffset::new(0x150)));
        assert!(!r.contains(FileOffset::new(0x300)));
    }

    // ── SegmentMapping ────────────────────────────────────────────────────────

    #[test]
    fn segment_mapping_va_to_file_offset() {
        let seg = SegmentMapping::new(
            AddressRange::new(Address::new(0x4000_0000), Address::new(0x4000_1000)),
            FileOffsetRange::new(FileOffset::new(0x200), FileOffset::new(0x1200)),
        )
        .with_name(".text");

        let fo = seg.va_to_file_offset(Address::new(0x4000_0400)).unwrap();
        assert_eq!(fo, FileOffset::new(0x600));

        assert!(seg.va_to_file_offset(Address::new(0x5000_0000)).is_none());
    }

    #[test]
    fn segment_mapping_file_offset_to_va() {
        let seg = SegmentMapping::new(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            FileOffsetRange::new(FileOffset::new(0x400), FileOffset::new(0x1400)),
        );

        let va = seg.file_offset_to_va(FileOffset::new(0x800)).unwrap();
        assert_eq!(va, Address::new(0x1400));

        assert!(seg.file_offset_to_va(FileOffset::new(0)).is_none());
    }

    // ── AddressSpace ──────────────────────────────────────────────────────────

    #[test]
    fn address_space_insert_find() {
        let mut space: AddressSpace<&str> = AddressSpace::new();
        space.insert(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            "text",
        );
        space.insert(
            AddressRange::new(Address::new(0x2000), Address::new(0x3000)),
            "data",
        );

        let found = space.find(Address::new(0x1500)).unwrap();
        assert_eq!(found.meta, "text");

        assert!(space.find(Address::new(0x5000)).is_none());
    }

    #[test]
    fn address_space_find_overlapping() {
        let mut space: AddressSpace<u32> = AddressSpace::new();
        space.insert(
            AddressRange::new(Address::new(0x1000), Address::new(0x3000)),
            1,
        );
        space.insert(
            AddressRange::new(Address::new(0x2000), Address::new(0x4000)),
            2,
        );
        space.insert(
            AddressRange::new(Address::new(0x5000), Address::new(0x6000)),
            3,
        );

        let query = AddressRange::new(Address::new(0x2800), Address::new(0x3800));
        let results = space.find_overlapping(&query);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn address_space_remove() {
        let mut space: AddressSpace<i32> = AddressSpace::new();
        space.insert(
            AddressRange::new(Address::new(0x100), Address::new(0x200)),
            42,
        );
        let removed = space.remove_containing(Address::new(0x150)).unwrap();
        assert_eq!(removed.meta, 42);
        assert!(space.is_empty());
    }

    // ── TypedAddress ──────────────────────────────────────────────────────────

    #[test]
    fn typed_address_is_virtual() {
        let ta = TypedAddress::new(Address::new(0x1000), AddressSpaceKind::Default);
        assert!(ta.is_virtual());
        let pa = TypedAddress::new(Address::new(0x1000), AddressSpaceKind::Physical);
        assert!(!pa.is_virtual());
    }
}
