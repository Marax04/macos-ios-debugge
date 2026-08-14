//! VSA-driven jump-table bound recovery and indirect-target enumeration.
//!
//! Value-set analysis abstracts each register as a [`ValueSet`] (a strided
//! interval).  This module applies that abstraction to the two indirect
//! control-flow problems the spec calls out:
//!
//! * **Jump-table bounds** — given the value-set of the switch *index* (already
//!   constrained by a preceding `cmp index, N; ja default`), derive the number
//!   of valid table entries and the byte span of the table.
//! * **Indirect-call / indirect-jump targets** — given the value-set of the
//!   pointer expression `base + index*scale`, enumerate the concrete target
//!   addresses (bounded), reading entries from a backing memory image.
//!
//! It also adds the strided-interval *multiply-by-constant* and *widening*
//! operators that the core `ValueSet` lattice does not yet expose, both of
//! which are needed to model `index * entry_size`.

use crate::ValueSet;
use rustre_core::endian::Endian;

/// Multiply a [`ValueSet`] by a constant scalar, preserving the strided-interval
/// shape (`[lo,hi]/s * c == [lo*c, hi*c]/(s*c)`), with saturating arithmetic.
#[must_use]
pub fn scale(vs: &ValueSet, factor: u64) -> ValueSet {
    match vs {
        ValueSet::Bottom => ValueSet::Bottom,
        ValueSet::Top => ValueSet::Top,
        ValueSet::Concrete(vals) => {
            ValueSet::Concrete(vals.iter().map(|v| v.wrapping_mul(factor)).collect())
        }
        ValueSet::Range { lo, hi, stride } => {
            if factor == 0 {
                return ValueSet::singleton(0);
            }
            ValueSet::strided(
                lo.wrapping_mul(factor),
                hi.wrapping_mul(factor),
                stride.saturating_mul(factor),
            )
        }
    }
}

/// Add a constant offset to a [`ValueSet`] (e.g. table base address).
#[must_use]
pub fn offset(vs: &ValueSet, delta: u64) -> ValueSet {
    match vs {
        ValueSet::Bottom => ValueSet::Bottom,
        ValueSet::Top => ValueSet::Top,
        ValueSet::Concrete(vals) => {
            ValueSet::Concrete(vals.iter().map(|v| v.wrapping_add(delta)).collect())
        }
        ValueSet::Range { lo, hi, stride } => {
            ValueSet::strided(lo.wrapping_add(delta), hi.wrapping_add(delta), *stride)
        }
    }
}

/// The standard VSA *widening* operator `self ▽ other`.
///
/// When a value grows across a loop iteration, widening jumps the unstable
/// bound to the lattice extreme (here `0` or `u64::MAX`) to guarantee
/// termination of the fixpoint.  Stable bounds are preserved.
#[must_use]
pub fn widen(prev: &ValueSet, next: &ValueSet) -> ValueSet {
    match (prev, next) {
        (ValueSet::Bottom, x) | (x, ValueSet::Bottom) => x.clone(),
        (ValueSet::Top, _) | (_, ValueSet::Top) => ValueSet::Top,
        _ => {
            let (plo, phi) = bounds(prev);
            let (nlo, nhi) = bounds(next);
            let lo = if nlo < plo { 0 } else { plo };
            let hi = if nhi > phi { u64::MAX } else { phi };
            // Fold the offset between the two lower bounds into the stride —
            // same defect as `pointer::widen`, second unfixed copy. Without it
            // the widened set omits members of the other operand, and here that
            // feeds jump-table bounds, so real switch targets go missing.
            let stride = match (prev, next) {
                (
                    ValueSet::Range {
                        lo: l1, stride: s1, ..
                    },
                    ValueSet::Range {
                        lo: l2, stride: s2, ..
                    },
                ) => gcd(gcd(*s1, *s2), l1.abs_diff(*l2)),
                _ => 1,
            };
            if lo == hi {
                ValueSet::singleton(lo)
            } else {
                ValueSet::strided(lo, hi, stride)
            }
        }
    }
}

fn bounds(vs: &ValueSet) -> (u64, u64) {
    match vs {
        ValueSet::Bottom => (u64::MAX, 0),
        ValueSet::Top => (0, u64::MAX),
        ValueSet::Concrete(v) => (
            v.iter().copied().min().unwrap_or(0),
            v.iter().copied().max().unwrap_or(0),
        ),
        ValueSet::Range { lo, hi, .. } => (*lo, *hi),
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    let mut a = a;
    let mut b = b;
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

/// The result of bounding a jump table from the index value-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTableBounds {
    /// Inclusive lowest index that can reach the table.
    pub min_index: u64,
    /// Inclusive highest index that can reach the table.
    pub max_index: u64,
    /// Number of distinct entries the index can select.
    pub entry_count: u64,
    /// Byte span occupied by the table (`entry_count * entry_size`).
    pub byte_span: u64,
}

/// Derive jump-table bounds from the abstract value-set of the switch index.
///
/// Returns `None` if the index is unbounded (`Top`) and therefore the table
/// size cannot be recovered.
#[must_use]
pub fn bound_jump_table(index: &ValueSet, entry_size: u64) -> Option<JumpTableBounds> {
    if index.is_top() || index.is_bottom() {
        return None;
    }
    let (lo, hi) = bounds(index);
    let entry_count = hi.saturating_sub(lo).saturating_add(1);
    Some(JumpTableBounds {
        min_index: lo,
        max_index: hi,
        entry_count,
        byte_span: entry_count.saturating_mul(entry_size),
    })
}

/// A backing memory image used to read table entries during target resolution.
#[derive(Debug, Clone)]
pub struct TableImage<'a> {
    /// Virtual address of `bytes[0]`.
    pub base: u64,
    /// Raw bytes.
    pub bytes: &'a [u8],
    /// Endianness of stored entries.
    pub endian: Endian,
}

impl<'a> TableImage<'a> {
    /// Create a new backing image.
    #[must_use]
    pub const fn new(base: u64, bytes: &'a [u8], endian: Endian) -> Self {
        Self {
            base,
            bytes,
            endian,
        }
    }

    /// Read an `entry_size`-byte unsigned value at virtual address `addr`.
    #[must_use]
    pub fn read(&self, addr: u64, entry_size: u8) -> Option<u64> {
        if addr < self.base {
            return None;
        }
        let n = entry_size as usize;
        if n == 0 || n > 8 {
            return None;
        }
        let off = usize::try_from(addr - self.base).ok()?;
        let end = off.checked_add(n)?;
        let slice = self.bytes.get(off..end)?;
        let mut buf = [0u8; 8];
        match self.endian {
            Endian::Little => {
                buf[..n].copy_from_slice(slice);
                Some(u64::from_le_bytes(buf))
            }
            Endian::Big => {
                let mut v = 0u64;
                for &b in slice {
                    v = (v << 8) | u64::from(b);
                }
                Some(v)
            }
        }
    }
}

/// Enumerate the concrete target addresses an indirect jump/call can reach,
///
/// given the value-set of its *pointer* expression (the address the CPU loads
/// the target from) and a backing image to read entries from.
///
/// `entry_size` is the size of each stored target.  Targets are read from each
/// concrete pointer in the value-set, bounded by `limit`.
#[must_use]
pub fn resolve_indirect_targets(
    pointer_vs: &ValueSet,
    image: &TableImage<'_>,
    entry_size: u8,
    limit: usize,
) -> Vec<u64> {
    let Some(ptrs) = pointer_vs.concretize(limit) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for p in ptrs {
        if let Some(t) = image.read(p, entry_size) {
            targets.push(t);
        }
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Compute the pointer value-set `base + index*entry_size` from the index
/// value-set, then resolve the concrete targets in one step.
#[must_use]
pub fn resolve_switch(
    index: &ValueSet,
    table_base: u64,
    entry_size: u8,
    image: &TableImage<'_>,
    limit: usize,
) -> Vec<u64> {
    let scaled = scale(index, u64::from(entry_size));
    let ptr_vs = offset(&scaled, table_base);
    resolve_indirect_targets(&ptr_vs, image, entry_size, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_range() {
        let vs = ValueSet::strided(0, 3, 1); // {0,1,2,3}
        let scaled = scale(&vs, 4);
        // {0,4,8,12}
        assert_eq!(scaled.concretize(16), Some(vec![0, 4, 8, 12]));
    }

    #[test]
    fn scale_zero_collapses() {
        let vs = ValueSet::strided(2, 10, 2);
        assert_eq!(scale(&vs, 0), ValueSet::singleton(0));
    }

    #[test]
    fn offset_shifts() {
        let vs = ValueSet::strided(0, 8, 4); // {0,4,8}
        let shifted = offset(&vs, 0x1000);
        assert_eq!(shifted.concretize(16), Some(vec![0x1000, 0x1004, 0x1008]));
    }

    #[test]
    fn widen_unstable_upper_bound() {
        let prev = ValueSet::interval(0, 4);
        let next = ValueSet::interval(0, 8); // grew upward
        let w = widen(&prev, &next);
        // upper bound jumps to u64::MAX, lower stays 0.
        assert_eq!(bounds(&w), (0, u64::MAX));
    }

    #[test]
    fn widen_stable_is_preserved() {
        let prev = ValueSet::interval(0, 4);
        let next = ValueSet::interval(0, 4);
        let w = widen(&prev, &next);
        assert_eq!(bounds(&w), (0, 4));
    }

    #[test]
    fn bound_jump_table_from_index() {
        // index in [0,7], entry size 4 -> 8 entries, 32-byte table.
        let index = ValueSet::interval(0, 7);
        let b = bound_jump_table(&index, 4).unwrap();
        assert_eq!(b.entry_count, 8);
        assert_eq!(b.byte_span, 32);
        assert_eq!(b.max_index, 7);
    }

    #[test]
    fn bound_jump_table_top_unbounded() {
        assert!(bound_jump_table(&ValueSet::Top, 4).is_none());
        assert!(bound_jump_table(&ValueSet::Bottom, 4).is_none());
    }

    #[test]
    fn table_image_read_le() {
        let data = [0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        let img = TableImage::new(0x4000, &data, Endian::Little);
        assert_eq!(img.read(0x4000, 4), Some(0x10));
        assert_eq!(img.read(0x4004, 4), Some(0x20));
        assert_eq!(img.read(0x4008, 4), None); // OOB
        assert_eq!(img.read(0x3000, 4), None); // below base
    }

    #[test]
    fn table_image_read_be() {
        let data = [0x00, 0x00, 0x00, 0x10];
        let img = TableImage::new(0x4000, &data, Endian::Big);
        assert_eq!(img.read(0x4000, 4), Some(0x10));
    }

    #[test]
    fn table_image_read_rejects_oversized_entry_without_panicking() {
        let data = [0u8; 32];
        let img = TableImage::new(0x4000, &data, Endian::Little);
        assert_eq!(img.read(0x4000, 255), None);
        assert_eq!(img.read(0x4000, 9), None);
        assert_eq!(img.read(0x4000, 0), None);
        assert_eq!(img.read(0x4000, 8), Some(0));
    }

    #[test]
    fn resolve_indirect_targets_from_pointers() {
        // table at 0x4000 with two absolute 4-byte targets.
        let mut data = Vec::new();
        data.extend_from_slice(&0x1100u32.to_le_bytes());
        data.extend_from_slice(&0x1200u32.to_le_bytes());
        let img = TableImage::new(0x4000, &data, Endian::Little);
        let ptr_vs = ValueSet::strided(0x4000, 0x4004, 4); // {0x4000, 0x4004}
        let targets = resolve_indirect_targets(&ptr_vs, &img, 4, 16);
        assert_eq!(targets, vec![0x1100, 0x1200]);
    }

    #[test]
    fn resolve_switch_end_to_end() {
        // index in [0,2], table base 0x4000, 4-byte absolute targets.
        let mut data = Vec::new();
        for t in [0x1100u32, 0x1200, 0x1300] {
            data.extend_from_slice(&t.to_le_bytes());
        }
        let img = TableImage::new(0x4000, &data, Endian::Little);
        let index = ValueSet::interval(0, 2);
        let targets = resolve_switch(&index, 0x4000, 4, &img, 16);
        assert_eq!(targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn resolve_top_pointer_gives_nothing() {
        let img = TableImage::new(0x4000, &[], Endian::Little);
        assert!(resolve_indirect_targets(&ValueSet::Top, &img, 4, 16).is_empty());
    }
}
