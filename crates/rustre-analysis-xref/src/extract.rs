//! Cross-reference *extraction*: turning raw code and data bytes into
//! [`Xref`] records, plus a compact index queryable by target address.
//!
//! The [`XrefDatabase`](crate::XrefDatabase) already provides a rich query
//! surface once xrefs exist.  This module fills the gap before that: it scans
//! a memory region and *produces* the xrefs in the first place, covering all
//! four reference categories required by the spec:
//!
//! * **code → code** — direct `CALL`/`JMP` `rel32` targets.
//! * **code → data** — RIP-relative `LEA`/`MOV` displacements (x86-64).
//! * **data → code** and **data → data** — pointer-sized words in a data
//!   section whose value lands inside a known code or data range.
//!
//! Extraction is intentionally architecture-light (x86-64 opcode shapes) but
//! the [`XrefIndex`] and pointer scanner are architecture-neutral.

use crate::{Xref, XrefKind};
use rustre_core::address::{Address, AddressRange};
use std::collections::HashMap;

/// A region classification used to decide whether a recovered pointer is a
/// code→code, code→data, data→code, or data→data reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionClass {
    /// Executable code.
    Code,
    /// Initialised / read-only data.
    Data,
}

/// A classified address-space region.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    /// Address range `[start, end)`.
    pub range: AddressRange,
    /// Whether the region is code or data.
    pub class: RegionClass,
}

impl Region {
    /// Create a region.
    #[must_use]
    pub const fn new(start: u64, end: u64, class: RegionClass) -> Self {
        Self {
            range: AddressRange::new(Address::new(start), Address::new(end)),
            class,
        }
    }

    /// Whether `addr` falls inside this region.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.range.start.as_u64() && addr.as_u64() < self.range.end.as_u64()
    }
}

/// A memory map used to classify recovered targets.
///
/// `classify`/`is_mapped` are the hot path for [`extract_data_pointers`],
/// which calls them once per pointer-sized word in a data section (can be
/// hundreds of thousands of calls for a large binary). A plain per-call
/// linear scan over `regions` would make that O(words × regions), which is
/// quadratic-or-worse in practice. Instead we lazily build a start-sorted
/// index with a suffix max-end, which lets each query prune to the handful
/// of regions that could possibly contain `addr` (classic interval-overlap
/// pruning), while still giving correct answers for overlapping regions —
/// `add`/`add_code`/`add_data` just invalidate the cached index rather than
/// requiring regions to be non-overlapping or added in order.
#[derive(Debug, Default, Clone)]
pub struct RegionMap {
    regions: Vec<Region>,
    /// Cached `(region_index_in_regions, suffix_max_end)` sorted by start,
    /// rebuilt on first query after a mutation. `None` means stale/unbuilt.
    sorted_index: std::cell::RefCell<Option<Vec<(usize, u64)>>>,
}

impl RegionMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    pub fn add(&mut self, region: Region) {
        self.regions.push(region);
        self.sorted_index.get_mut().take();
    }

    /// Add a code region from raw bounds.
    pub fn add_code(&mut self, start: u64, end: u64) {
        self.add(Region::new(start, end, RegionClass::Code));
    }

    /// Add a data region from raw bounds.
    pub fn add_data(&mut self, start: u64, end: u64) {
        self.add(Region::new(start, end, RegionClass::Data));
    }

    /// Ensure `sorted_index` reflects the current `regions`, then return it.
    fn ensure_index(&self) -> std::cell::Ref<'_, Option<Vec<(usize, u64)>>> {
        {
            let mut cache = self.sorted_index.borrow_mut();
            if cache.is_none() {
                let mut order: Vec<usize> = (0..self.regions.len()).collect();
                order.sort_unstable_by_key(|&i| self.regions[i].range.start.as_u64());
                // Suffix max of end, computed over the start-sorted order.
                let mut suffix_max = 0u64;
                let mut entries: Vec<(usize, u64)> = vec![(0, 0); order.len()];
                for pos in (0..order.len()).rev() {
                    let idx = order[pos];
                    suffix_max = suffix_max.max(self.regions[idx].range.end.as_u64());
                    entries[pos] = (idx, suffix_max);
                }
                *cache = Some(entries);
            }
        }
        self.sorted_index.borrow()
    }

    /// Classify an address, returning its region class if mapped.
    #[must_use]
    pub fn classify(&self, addr: Address) -> Option<RegionClass> {
        let a = addr.as_u64();
        let cache = self.ensure_index();
        let entries = cache.as_ref()?;
        // `entries` is sorted by region start ascending; binary-search for
        // the rightmost region whose start <= a, then scan backwards while
        // the suffix-max-end says an earlier region could still cover `a`.
        let mut lo = 0usize;
        let mut hi = entries.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (idx, _) = entries[mid];
            if self.regions[idx].range.start.as_u64() <= a {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // `lo` is the first index with start > a; candidates are [0, lo).
        for pos in (0..lo).rev() {
            let (idx, suffix_max_end) = entries[pos];
            if suffix_max_end <= a {
                break;
            }
            if self.regions[idx].contains(addr) {
                return Some(self.regions[idx].class);
            }
        }
        None
    }

    /// Whether `addr` is mapped at all.
    #[must_use]
    pub fn is_mapped(&self, addr: Address) -> bool {
        self.classify(addr).is_some()
    }
}

/// Read a little-endian pointer of `ptr_size` bytes from `data` at `off`.
fn read_ptr_le(data: &[u8], off: usize, ptr_size: u8) -> Option<u64> {
    let n = ptr_size as usize;
    if n > 8 || off + n > data.len() {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(&data[off..off + n]);
    Some(u64::from_le_bytes(buf))
}

/// Extract **code → code** xrefs from x86-64 code: direct `CALL rel32` (`E8`)
/// and near `JMP rel32` (`E9`).
#[must_use]
pub fn extract_code_to_code(code_base: Address, code: &[u8]) -> Vec<Xref> {
    // Heuristic: ~1 call/jump per 64 bytes of code on average.
    let mut out = Vec::with_capacity(code.len() / 64);
    let base = code_base.as_u64();
    let mut i = 0usize;
    while i + 5 <= code.len() {
        let op = code[i];
        if op == 0xE8 || op == 0xE9 {
            let rel = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let Some(src) = base.checked_add(i as u64) else {
                i += 1;
                continue;
            };
            let Some(next_ip) = src.checked_add(5) else {
                i += 1;
                continue;
            };
            let target = next_ip.wrapping_add_signed(i64::from(rel));
            let kind = if op == 0xE8 {
                XrefKind::CodeCall
            } else {
                XrefKind::CodeJump
            };
            out.push(Xref::new(
                Address::new(src),
                Address::new(target),
                kind,
                5,
            ));
            i += 5;
        } else {
            i += 1;
        }
    }
    out
}

/// Extract **code → data** xrefs from x86-64 RIP-relative addressing.
///
/// Recognises the common `LEA r64, [rip+disp32]` (`REX.W 8D /r` with `ModRM`
/// mod=00 r/m=101) and `MOV r64, [rip+disp32]` (`REX.W 8B /r`, same `ModRM`)
/// forms, computing the absolute target from the instruction's end IP.
#[must_use]
pub fn extract_code_to_data_riprel(code_base: Address, code: &[u8]) -> Vec<Xref> {
    let mut out = Vec::with_capacity(code.len() / 128);
    let base = code_base.as_u64();
    let mut i = 0usize;
    while i < code.len() {
        // Look for a REX.W prefix (0x48..=0x4F with W bit set) followed by
        // 0x8D (LEA) or 0x8B (MOV r,m) and a RIP-relative ModRM byte.
        if i + 7 <= code.len() && (code[i] & 0xF8) == 0x48 {
            let opcode = code[i + 1];
            let modrm = code[i + 2];
            let is_lea = opcode == 0x8D;
            let is_mov = opcode == 0x8B;
            // mod == 00 and r/m == 101 -> RIP-relative disp32.
            if (is_lea || is_mov) && (modrm & 0xC7) == 0x05 {
                let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                let instr_len = 7u64; // rex + opcode + modrm + disp32
                let Some(next_ip): Option<u64> = base
                    .checked_add(i as u64)
                    .and_then(|a: u64| a.checked_add(instr_len))
                else {
                    i += 1;
                    continue;
                };
                let target = next_ip.wrapping_add_signed(i64::from(disp));
                let kind = if is_lea {
                    XrefKind::DataAddress
                } else {
                    XrefKind::DataRead
                };
                // next_ip - instr_len gives the instruction's own address (already checked above).
                let insn_addr = next_ip - instr_len;
                out.push(Xref::new(
                    Address::new(insn_addr),
                    Address::new(target),
                    kind,
                    7,
                ));
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Scan a **data** region for pointer-sized words and emit `data → code` /
/// `data → data` xrefs for those that land inside a mapped region.
#[must_use]
pub fn extract_data_pointers(
    data_base: Address,
    data: &[u8],
    ptr_size: u8,
    map: &RegionMap,
) -> Vec<Xref> {
    let step = ptr_size as usize;
    // Only 4-byte and 8-byte pointer sizes are meaningful; reject others early
    // to prevent read_ptr_le from silently returning None on every slot.
    if step != 4 && step != 8 {
        return Vec::new();
    }
    // Most pointer-sized words won't land in a mapped region; budget conservatively.
    let mut out = Vec::with_capacity(data.len() / (step * 16).max(1));
    let base = data_base.as_u64();
    let mut off = 0usize;
    while off + step <= data.len() {
        if let Some(value) = read_ptr_le(data, off, ptr_size) {
            let target = Address::new(value);
            if let Some(class) = map.classify(target) {
                let Some(from_raw) = base.checked_add(off as u64) else {
                    off += step;
                    continue;
                };
                let from = Address::new(from_raw);
                // Both forms are stored as DataPointer; the tag records whether
                // the pointee is code or data.
                let mut x = Xref::new(from, target, XrefKind::DataPointer, 0);
                x.tag = Some(match class {
                    RegionClass::Code => "data->code".to_string(),
                    RegionClass::Data => "data->data".to_string(),
                });
                out.push(x);
            }
        }
        off += step;
    }
    out
}

/// A read-optimised index from *target* address to the xrefs pointing at it.
///
/// This complements [`XrefDatabase`](crate::XrefDatabase) by being cheap to
/// build from any `Vec<Xref>` and offering grouped, sorted, by-`to` queries.
#[derive(Debug, Default, Clone)]
pub struct XrefIndex {
    by_to: HashMap<u64, Vec<Xref>>,
    by_from: HashMap<u64, Vec<Xref>>,
    total: usize,
}

impl XrefIndex {
    /// Build an index from a slice of xrefs.
    #[must_use]
    pub fn build(xrefs: &[Xref]) -> Self {
        let mut idx = Self::default();
        for x in xrefs {
            idx.insert(x.clone());
        }
        idx
    }

    /// Insert a single xref.
    pub fn insert(&mut self, x: Xref) {
        self.by_to.entry(x.to.as_u64()).or_default().push(x.clone());
        self.by_from.entry(x.from.as_u64()).or_default().push(x);
        self.total += 1;
    }

    /// All xrefs targeting `addr`.
    #[must_use]
    pub fn to(&self, addr: Address) -> &[Xref] {
        self.by_to.get(&addr.as_u64()).map_or(&[], Vec::as_slice)
    }

    /// All xrefs originating at `addr`.
    #[must_use]
    pub fn from(&self, addr: Address) -> &[Xref] {
        self.by_from.get(&addr.as_u64()).map_or(&[], Vec::as_slice)
    }

    /// Number of distinct targets that have at least one incoming xref.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.by_to.len()
    }

    /// Total xref records held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total
    }

    /// Whether the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Number of incoming references to `addr` of a given kind.
    #[must_use]
    pub fn incoming_of_kind(&self, addr: Address, kind: XrefKind) -> usize {
        self.to(addr).iter().filter(|x| x.kind == kind).count()
    }

    /// The most-referenced targets, descending by incoming count.
    #[must_use]
    pub fn hottest_targets(&self, top_n: usize) -> Vec<(Address, usize)> {
        let mut v: Vec<(Address, usize)> = self
            .by_to
            .iter()
            .map(|(&k, refs)| (Address::new(k), refs.len()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.as_u64().cmp(&b.0.as_u64())));
        v.truncate(top_n);
        v
    }
}

/// Run the full extraction pipeline over a code blob and a data blob, returning
/// a populated [`XrefIndex`].
#[must_use]
pub fn extract_all(
    code_base: Address,
    code: &[u8],
    data_base: Address,
    data: &[u8],
    ptr_size: u8,
    map: &RegionMap,
) -> XrefIndex {
    let mut all = Vec::new();
    all.extend(extract_code_to_code(code_base, code));
    all.extend(extract_code_to_data_riprel(code_base, code));
    all.extend(extract_data_pointers(data_base, data, ptr_size, map));
    XrefIndex::build(&all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_map_classify_unsorted_insertion_order() {
        // Regions added out of start order must still be found correctly by
        // the lazily-built, start-sorted index.
        let mut map = RegionMap::new();
        map.add_data(0x9000, 0xA000);
        map.add_code(0x1000, 0x2000);
        map.add_data(0x3000, 0x4000);
        map.add_code(0x5000, 0x6000);
        assert_eq!(map.classify(Address::new(0x1500)), Some(RegionClass::Code));
        assert_eq!(map.classify(Address::new(0x3500)), Some(RegionClass::Data));
        assert_eq!(map.classify(Address::new(0x5500)), Some(RegionClass::Code));
        assert_eq!(map.classify(Address::new(0x9500)), Some(RegionClass::Data));
        assert_eq!(map.classify(Address::new(0x7000)), None);
    }

    #[test]
    fn region_map_classify_overlapping_regions() {
        // Overlapping regions: a query in the overlap must find a match
        // even though the containing region isn't the one with the latest
        // (or earliest) start.
        let mut map = RegionMap::new();
        map.add_code(0x1000, 0x5000);
        map.add_data(0x2000, 0x2100); // fully nested inside the code region
        map.add_code(0x100, 0x200); // unrelated, before everything
        assert_eq!(map.classify(Address::new(0x2050)), Some(RegionClass::Data));
        assert_eq!(map.classify(Address::new(0x1500)), Some(RegionClass::Code));
        assert_eq!(map.classify(Address::new(0x150)), Some(RegionClass::Code));
        assert_eq!(map.classify(Address::new(0x6000)), None);
    }

    #[test]
    fn region_map_classify() {
        let mut map = RegionMap::new();
        map.add_code(0x1000, 0x2000);
        map.add_data(0x3000, 0x4000);
        assert_eq!(map.classify(Address::new(0x1500)), Some(RegionClass::Code));
        assert_eq!(map.classify(Address::new(0x3500)), Some(RegionClass::Data));
        assert_eq!(map.classify(Address::new(0x9000)), None);
        assert!(map.is_mapped(Address::new(0x1000)));
        assert!(!map.is_mapped(Address::new(0x2000)));
    }

    #[test]
    fn code_to_code_call_and_jmp() {
        // E8 call rel32 at 0: next=0x1005, rel=0x10 -> 0x1015.
        // E9 jmp rel32 at 5: next=0x100A, rel=-0x10 -> 0xFFA.
        let mut code = vec![0xE8, 0x10, 0x00, 0x00, 0x00];
        code.extend_from_slice(&[0xE9]);
        code.extend_from_slice(&(-0x10i32).to_le_bytes());
        let xrefs = extract_code_to_code(Address::new(0x1000), &code);
        assert_eq!(xrefs.len(), 2);
        let call = xrefs.iter().find(|x| x.kind == XrefKind::CodeCall).unwrap();
        assert_eq!(call.to, Address::new(0x1015));
        let jmp = xrefs.iter().find(|x| x.kind == XrefKind::CodeJump).unwrap();
        assert_eq!(jmp.to, Address::new(0xFFA));
    }

    #[test]
    fn code_to_data_lea_riprel() {
        // 48 8D 05 disp32 : lea rax, [rip+disp]. At off 0, instr_len 7,
        // next_ip = 0x2007, disp = 0x100 -> target 0x2107.
        let mut code = vec![0x48, 0x8D, 0x05];
        code.extend_from_slice(&0x100i32.to_le_bytes());
        let xrefs = extract_code_to_data_riprel(Address::new(0x2000), &code);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, XrefKind::DataAddress);
        assert_eq!(xrefs[0].to, Address::new(0x2107));
    }

    #[test]
    fn code_to_data_mov_riprel_is_read() {
        // 48 8B 0D disp32 : mov rcx, [rip+disp].
        let mut code = vec![0x48, 0x8B, 0x0D];
        code.extend_from_slice(&0x40i32.to_le_bytes());
        let xrefs = extract_code_to_data_riprel(Address::new(0x2000), &code);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, XrefKind::DataRead);
        assert_eq!(xrefs[0].to, Address::new(0x2047));
    }

    #[test]
    fn data_pointers_to_code_and_data() {
        let mut map = RegionMap::new();
        map.add_code(0x1000, 0x2000);
        map.add_data(0x3000, 0x4000);
        // Two 8-byte pointers: 0x1500 (code), 0x3500 (data), 0x9999 (unmapped).
        let mut data = Vec::new();
        data.extend_from_slice(&0x1500u64.to_le_bytes());
        data.extend_from_slice(&0x3500u64.to_le_bytes());
        data.extend_from_slice(&0x9999u64.to_le_bytes());
        let xrefs = extract_data_pointers(Address::new(0x3000), &data, 8, &map);
        assert_eq!(xrefs.len(), 2); // unmapped pointer dropped
        assert!(
            xrefs
                .iter()
                .any(|x| x.to == Address::new(0x1500) && x.tag.as_deref() == Some("data->code"))
        );
        assert!(
            xrefs
                .iter()
                .any(|x| x.to == Address::new(0x3500) && x.tag.as_deref() == Some("data->data"))
        );
    }

    #[test]
    fn index_query_by_to() {
        let xrefs = vec![
            Xref::new(
                Address::new(0x10),
                Address::new(0x100),
                XrefKind::CodeCall,
                5,
            ),
            Xref::new(
                Address::new(0x20),
                Address::new(0x100),
                XrefKind::CodeCall,
                5,
            ),
            Xref::new(
                Address::new(0x30),
                Address::new(0x200),
                XrefKind::CodeJump,
                5,
            ),
        ];
        let idx = XrefIndex::build(&xrefs);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.to(Address::new(0x100)).len(), 2);
        assert_eq!(idx.to(Address::new(0x200)).len(), 1);
        assert_eq!(idx.from(Address::new(0x10)).len(), 1);
        assert_eq!(
            idx.incoming_of_kind(Address::new(0x100), XrefKind::CodeCall),
            2
        );
    }

    #[test]
    fn index_hottest_targets() {
        let xrefs = vec![
            Xref::new(Address::new(1), Address::new(0x100), XrefKind::CodeCall, 5),
            Xref::new(Address::new(2), Address::new(0x100), XrefKind::CodeCall, 5),
            Xref::new(Address::new(3), Address::new(0x100), XrefKind::CodeCall, 5),
            Xref::new(Address::new(4), Address::new(0x200), XrefKind::CodeCall, 5),
        ];
        let idx = XrefIndex::build(&xrefs);
        let hot = idx.hottest_targets(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0], (Address::new(0x100), 3));
    }

    #[test]
    fn extract_all_pipeline() {
        let mut map = RegionMap::new();
        map.add_code(0x1000, 0x2000);
        map.add_data(0x3000, 0x4000);
        // Code: a single E8 call to 0x1015.
        let code = vec![0xE8, 0x10, 0x00, 0x00, 0x00];
        // Data: pointer to code 0x1500.
        let data = 0x1500u64.to_le_bytes().to_vec();
        let idx = extract_all(
            Address::new(0x1000),
            &code,
            Address::new(0x3000),
            &data,
            8,
            &map,
        );
        assert!(!idx.is_empty());
        assert_eq!(idx.to(Address::new(0x1015)).len(), 1);
        assert_eq!(idx.to(Address::new(0x1500)).len(), 1);
    }

    #[test]
    fn empty_index() {
        let idx = XrefIndex::build(&[]);
        assert!(idx.is_empty());
        assert_eq!(idx.target_count(), 0);
        assert!(idx.to(Address::new(0)).is_empty());
    }
}
