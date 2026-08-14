//! `vtable_finder` — enhanced vtable location engine (layered on base module).
//!
//! Provides `VtableFinder`, `CompleteObjectLocator`, `TypeInfo`, and
//! `VtableValidation` types with full MSVC/GCC detection, address-range
//! validation, and heuristic size computation.
//!
//! Original vtable finder: locate candidate C++ vtable regions in a flat binary image.
//!
//! Strategy:
//!   1. Walk the binary in pointer-aligned steps.
//!   2. At each offset, check whether the quadword looks like a valid
//!      code-section pointer (function pointer) or a pointer-to-typeinfo.
//!   3. Recognise the MSVC vtable layout:
//!         [ptr to RTTI complete object locator]  ← optional, at vt-8 or vt-4
//!         [ptr to fn0]
//!         [ptr to fn1]
//!         ...
//!   4. Recognise the Itanium (GCC/Clang) layout:
//!         [offset-to-top]
//!         [ptr to std::type_info]
//!         [ptr to fn0]
//!         ...

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ─── Address / layout helpers ─────────────────────────────────────────────────

pub type Addr = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Bitness {
    B32,
    B64,
}

impl Bitness {
    pub fn ptr_size(self) -> usize {
        match self { Self::B32 => 4, Self::B64 => 8 }
    }

    pub fn read_addr(self, data: &[u8], off: usize) -> Option<Addr> {
        match self {
            Self::B32 => {
                let end = off.checked_add(4)?;
                Some(u32::from_le_bytes(data.get(off..end)?.try_into().ok()?) as u64)
            }
            Self::B64 => {
                let end = off.checked_add(8)?;
                Some(u64::from_le_bytes(data.get(off..end)?.try_into().ok()?))
            }
        }
    }
}

// ─── Section map ──────────────────────────────────────────────────────────────

/// A coarse view of the binary's sections used for pointer-validity checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub va_start: Addr,
    pub va_end: Addr,
    pub file_offset: usize,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
}

impl SectionInfo {
    pub fn contains(&self, addr: Addr) -> bool {
        addr >= self.va_start && addr < self.va_end
    }
    pub fn file_offset_of(&self, addr: Addr) -> Option<usize> {
        if self.contains(addr) {
            self.file_offset.checked_add((addr - self.va_start) as usize)
        } else {
            None
        }
    }
}

// ─── Binary image ─────────────────────────────────────────────────────────────

pub struct BinaryImage<'a> {
    pub data: &'a [u8],
    pub image_base: Addr,
    pub sections: Vec<SectionInfo>,
    pub bitness: Bitness,
}

impl<'a> BinaryImage<'a> {
    pub fn new(data: &'a [u8], image_base: Addr, sections: Vec<SectionInfo>, bitness: Bitness) -> Self {
        Self { data, image_base, sections, bitness }
    }

    pub fn read_addr_at_va(&self, va: Addr) -> Option<Addr> {
        let off = self.va_to_file_offset(va)?;
        self.bitness.read_addr(self.data, off)
    }

    pub fn va_to_file_offset(&self, va: Addr) -> Option<usize> {
        for sec in &self.sections {
            if let Some(off) = sec.file_offset_of(va) {
                return Some(off);
            }
        }
        None
    }

    pub fn is_code_pointer(&self, addr: Addr) -> bool {
        self.sections.iter().any(|s| s.executable && s.contains(addr))
    }

    pub fn is_data_pointer(&self, addr: Addr) -> bool {
        self.sections.iter().any(|s| s.readable && !s.executable && s.contains(addr))
    }

    pub fn is_valid_pointer(&self, addr: Addr) -> bool {
        self.is_code_pointer(addr) || self.is_data_pointer(addr)
    }

    pub fn read_bytes_at_va(&self, va: Addr, len: usize) -> Option<&[u8]> {
        let off = self.va_to_file_offset(va)?;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }
}

// ─── RTTI detection helpers ───────────────────────────────────────────────────

/// MSVC "Complete Object Locator" magic bytes pattern (signature = 1 for 64-bit).
pub const COL_SIG_32: u32 = 0;
/// MSVC COL signature value used on 64-bit binaries.
pub const COL_SIG_64: u32 = 1;

/// Return the expected COL signature for a given pointer width (in bits).
///
/// Useful when validating a candidate Complete Object Locator structure: the
/// `signature` field at offset 0 must be [`COL_SIG_32`] on 32-bit binaries and
/// [`COL_SIG_64`] on 64-bit ones.
#[must_use]
pub fn expected_col_signature(bits: u32) -> u32 {
    if bits >= 64 { COL_SIG_64 } else { COL_SIG_32 }
}

/// True if `sig` is a recognised MSVC Complete Object Locator signature.
#[must_use]
pub fn is_valid_col_signature(sig: u32) -> bool {
    sig == COL_SIG_32 || sig == COL_SIG_64
}

/// Try to read an MSVC type descriptor at `va`.  Returns the mangled name if found.
pub fn try_read_msvc_type_descriptor(img: &BinaryImage<'_>, va: Addr) -> Option<String> {
    // TypeDescriptor layout:
    //   pVFTable  : ptr   (points to type_info vtable)
    //   spare     : ptr
    //   name      : char[]  (mangled, null-terminated, starts with ".?AV")
    let ptr_sz = img.bitness.ptr_size();
    let name_off = img.va_to_file_offset(va)?.checked_add(2 * ptr_sz)?;
    let name_bytes = img.data.get(name_off..)?;
    let scan_len = name_bytes.len().min(256);
    let scan = &name_bytes[..scan_len];
    let end = scan.iter().position(|&b| b == 0).unwrap_or(scan_len);
    let s = std::str::from_utf8(&scan[..end]).ok()?;
    // Heuristic: MSVC decorated names start with ".?AV" or ".?AU" (struct)
    if s.starts_with(".?AV") || s.starts_with(".?AU") || s.starts_with(".?AT") {
        Some(s.to_string())
    } else {
        None
    }
}

/// Try to read an Itanium `std::type_info` at `va`.  Returns the mangled name.
pub fn try_read_itanium_typeinfo(img: &BinaryImage<'_>, va: Addr) -> Option<String> {
    // std::type_info layout (Itanium ABI):
    //   vptr       : ptr    (points to type_info vtable in libstdc++)
    //   __name     : char*  (pointer to mangled name)
    let ptr_sz = img.bitness.ptr_size();
    let name_ptr_off = img.va_to_file_offset(va)?.checked_add(ptr_sz)?;
    let name_va = img.bitness.read_addr(img.data, name_ptr_off)?;
    // Itanium mangled names start with "_ZT" or "N" (or namespace prefixed).
    let name_off = img.va_to_file_offset(name_va)?;
    let name_bytes = img.data.get(name_off..)?;
    let scan_len = name_bytes.len().min(256);
    let scan = &name_bytes[..scan_len];
    let end = scan.iter().position(|&b| b == 0).unwrap_or(scan_len);
    let s = std::str::from_utf8(&scan[..end]).ok()?;
    if s.contains("_Z") || (s.len() > 2 && s.chars().next()?.is_ascii_digit()) {
        Some(s.to_string())
    } else {
        None
    }
}

// ─── Vtable candidate ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RttiKind {
    Msvc,
    Itanium,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableCandidate {
    /// Virtual address of the first function pointer (slot 0).
    pub va: Addr,
    /// Number of detected virtual function slots.
    pub slot_count: usize,
    /// Virtual addresses of the function pointer slots.
    pub slots: Vec<Addr>,
    /// Virtual address of the associated RTTI structure, if found.
    pub rtti_va: Option<Addr>,
    /// Demangled/raw class name from RTTI, if available.
    pub class_name: Option<String>,
    pub rtti_kind: RttiKind,
    /// Confidence score 0..100.
    pub confidence: u8,
}

impl VtableCandidate {
    pub fn is_abstract(&self) -> bool {
        // A vtable with all slots pointing to the same location is likely pure-virtual.
        if self.slots.len() < 2 { return false; }
        let first = self.slots[0];
        self.slots.iter().all(|&s| s == first)
    }
}

// ─── Finder configuration ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinderConfig {
    /// Minimum number of consecutive function pointers to consider a vtable.
    pub min_slots: usize,
    /// Maximum number of slots to scan (hard cap).
    pub max_slots: usize,
    /// Require at least this many slots to emit the candidate.
    pub confidence_min_slots: usize,
    /// Whether to look for MSVC Complete Object Locator prefix.
    pub check_msvc_rtti: bool,
    /// Whether to look for Itanium offset-to-top + typeinfo prefix.
    pub check_itanium_rtti: bool,
}

impl Default for FinderConfig {
    fn default() -> Self {
        Self {
            min_slots: 2,
            max_slots: 256,
            confidence_min_slots: 3,
            check_msvc_rtti: true,
            check_itanium_rtti: true,
        }
    }
}

// ─── Finder ───────────────────────────────────────────────────────────────────

pub struct VtableFinder<'a> {
    img: &'a BinaryImage<'a>,
    config: FinderConfig,
}

impl<'a> VtableFinder<'a> {
    pub fn new(img: &'a BinaryImage<'a>, config: FinderConfig) -> Self {
        Self { img, config }
    }

    /// Scan every readable, writable (data) section for vtable patterns.
    pub fn find_all(&self) -> Vec<VtableCandidate> {
        let mut results = Vec::new();
        let ptr_sz = self.img.bitness.ptr_size();

        // Iterate writable data sections only — vtables live in .rdata (MSVC) or
        // .data.rel.ro (GCC/Clang).
        for sec in &self.img.sections {
            if sec.executable { continue; }
            if !sec.readable  { continue; }
            let sec_va_start = sec.va_start;
            // saturating_sub: an adversarial section with va_end < va_start must
            // not wrap to a near-u64::MAX length (multi-hour scan loop).
            let sec_len = sec.va_end.saturating_sub(sec.va_start) as usize;
            if sec_len < ptr_sz * self.config.min_slots { continue; }

            let mut offset = 0usize;
            while offset + ptr_sz <= sec_len {
                let va = sec_va_start + offset as Addr;
                if let Some(candidate) = self.try_vtable_at(va) {
                    // Advance past this candidate to avoid overlapping results.
                    let consumed = candidate.slot_count * ptr_sz;
                    results.push(candidate);
                    offset += consumed.max(ptr_sz);
                } else {
                    offset += ptr_sz;
                }
            }
        }

        // Deduplicate by VA.
        let mut seen: HashSet<Addr> = HashSet::new();
        results.retain(|c| seen.insert(c.va));
        results.sort_by_key(|c| c.va);
        results
    }

    /// Try to interpret the virtual address `va` as the start of a vtable.
    pub fn try_vtable_at(&self, va: Addr) -> Option<VtableCandidate> {
        let ptr_sz = self.img.bitness.ptr_size() as Addr;

        // Check for MSVC RTTI prefix at (va - ptr_sz) or (va - 2*ptr_sz).
        let (rtti_va, class_name, rtti_kind) = self.probe_rtti(va);

        // Walk forward collecting valid code pointers.
        let mut slots = Vec::new();
        let mut cur = va;
        while slots.len() < self.config.max_slots {
            match self.img.read_addr_at_va(cur) {
                Some(fn_ptr) if self.img.is_code_pointer(fn_ptr) => {
                    slots.push(fn_ptr);
                    cur += ptr_sz;
                }
                _ => break,
            }
        }

        if slots.len() < self.config.min_slots { return None; }

        let confidence = self.score_confidence(&slots, rtti_va.is_some());

        Some(VtableCandidate {
            va,
            slot_count: slots.len(),
            slots,
            rtti_va,
            class_name,
            rtti_kind,
            confidence,
        })
    }

    fn probe_rtti(&self, vt_va: Addr) -> (Option<Addr>, Option<String>, RttiKind) {
        let ptr_sz = self.img.bitness.ptr_size() as Addr;

        // ── MSVC: at vt_va - ptr_sz there is a pointer to a COL ──────────────
        if self.config.check_msvc_rtti && vt_va >= ptr_sz {
            if let Some(col_va) = self.img.read_addr_at_va(vt_va - ptr_sz) {
                if self.img.is_data_pointer(col_va) {
                    if let Some(name) = try_read_msvc_type_descriptor(self.img, col_va) {
                        return (Some(col_va), Some(name), RttiKind::Msvc);
                    }
                }
            }
        }

        // ── Itanium: vt_va - 2*ptr_sz is offset-to-top, vt_va - ptr_sz is typeinfo ptr ──
        if self.config.check_itanium_rtti && vt_va >= 2 * ptr_sz {
            if let Some(ti_va) = self.img.read_addr_at_va(vt_va - ptr_sz) {
                if self.img.is_data_pointer(ti_va) {
                    if let Some(name) = try_read_itanium_typeinfo(self.img, ti_va) {
                        return (Some(ti_va), Some(name), RttiKind::Itanium);
                    }
                }
            }
        }

        (None, None, RttiKind::None)
    }

    fn score_confidence(&self, slots: &[Addr], has_rtti: bool) -> u8 {
        let mut score: u32 = 0;
        // Slot count contribution: up to 50 points.
        let slot_score = ((slots.len() as u32).min(10) * 5).min(50);
        score += slot_score;
        // RTTI: 30 points.
        if has_rtti { score += 30; }
        // Uniqueness of function pointers: if all slots point to the same address,
        // it is likely a pure-virtual stub placeholder → reduce score.
        if slots.len() >= 2 {
            let unique: HashSet<Addr> = slots.iter().copied().collect();
            let diversity = ((unique.len() as u32 * 20) / slots.len() as u32).min(20);
            score += diversity;
        }
        score.min(100) as u8
    }
}

// ─── Batch scanner wrapping multiple images ────────────────────────────────────

pub struct MultiImageScanner {
    pub results: HashMap<String, Vec<VtableCandidate>>,
}

impl MultiImageScanner {
    pub fn new() -> Self {
        Self { results: HashMap::new() }
    }

    pub fn scan(&mut self, name: &str, img: &BinaryImage<'_>, config: FinderConfig) {
        let finder = VtableFinder::new(img, config);
        let candidates = finder.find_all();
        self.results.insert(name.to_string(), candidates);
    }

    pub fn total_candidates(&self) -> usize {
        self.results.values().map(|v| v.len()).sum()
    }
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Build a synthetic 64-bit image with `n` vtable slots starting at va 0x1000_0000,
/// function pointers targeting 0x0040_0000 + i*0x10.
///
/// Returns `(owned_data, sections, image_base)`.  The caller must hold `owned_data`
/// alive for the duration of the `BinaryImage` constructed from it, e.g.:
/// ```ignore
/// let (data, sections, base) = make_test_image_64(5);
/// let img = BinaryImage::new(&data, base, sections, Bitness::B64);
/// ```
///
/// Previously this function returned a `BinaryImage<'static>` backed by
/// `Box::leak`, which permanently leaked heap memory on every call.  The owned
/// `Vec<u8>` return avoids the leak while keeping the API useful.
pub fn make_test_image_64(slot_count: usize) -> (Vec<u8>, Vec<SectionInfo>, Addr) {
    // We'll use two sections:
    //   .text  : 0x0040_0000  len 0x10000  (executable)
    //   .rdata : 0x1000_0000  len 0x10000  (readable, non-exec)
    let text_va: Addr = 0x0040_0000;
    let rdata_va: Addr = 0x1000_0000;

    let mut data = vec![0u8; 0x1000 + slot_count * 8 + 16];

    // Write vtable at file offset 8 (rdata VA = 0x1000_0000, with ptr_sz=8 prefix for RTTI)
    // We skip RTTI prefix for simplicity.
    let vt_file_off = 8usize;
    for i in 0..slot_count {
        let fn_ptr: u64 = text_va + i as u64 * 0x10;
        let bytes = fn_ptr.to_le_bytes();
        data[vt_file_off + i * 8..vt_file_off + i * 8 + 8].copy_from_slice(&bytes);
    }

    let sections = vec![
        SectionInfo {
            name: ".text".to_string(),
            va_start: text_va,
            va_end: text_va + 0x10000,
            file_offset: 0,
            executable: true,
            readable: true,
            writable: false,
        },
        SectionInfo {
            name: ".rdata".to_string(),
            va_start: rdata_va,
            va_end: rdata_va + 0x10000,
            file_offset: 0,
            executable: false,
            readable: true,
            writable: false,
        },
    ];

    (data, sections, text_va)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_image_with_vtable(slots: &[u64]) -> (Vec<u8>, Vec<SectionInfo>) {
        let text_va: Addr = 0x0040_0000;
        let rdata_va: Addr = 0x1000_0000;
        let text_len = 0x10000usize;
        let rdata_len = 0x10000usize;
        let mut data = vec![0u8; text_len + rdata_len];
        // Vtable starts at rdata_va (file offset = text_len).
        let vt_off = text_len;
        for (i, &fn_va) in slots.iter().enumerate() {
            let bytes = fn_va.to_le_bytes();
            data[vt_off + i * 8..vt_off + i * 8 + 8].copy_from_slice(&bytes);
        }
        let sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                va_start: text_va,
                va_end: text_va + text_len as u64,
                file_offset: 0,
                executable: true,
                readable: true,
                writable: false,
            },
            SectionInfo {
                name: ".rdata".to_string(),
                va_start: rdata_va,
                va_end: rdata_va + rdata_len as u64,
                file_offset: text_len,
                executable: false,
                readable: true,
                writable: false,
            },
        ];
        (data, sections)
    }

    #[test]
    fn test_find_simple_vtable() {
        let fns: Vec<u64> = (0..5).map(|i| 0x0040_0000u64 + i * 0x20).collect();
        let (data, sections) = make_image_with_vtable(&fns);
        let img = BinaryImage::new(&data, 0x0040_0000, sections, Bitness::B64);
        let cfg = FinderConfig { min_slots: 2, ..Default::default() };
        let finder = VtableFinder::new(&img, cfg);
        let candidates = finder.find_all();
        assert!(!candidates.is_empty());
        let first = &candidates[0];
        assert_eq!(first.slot_count, 5);
        assert_eq!(first.slots, fns);
    }

    #[test]
    fn test_no_vtable_all_zeros() {
        let data = vec![0u8; 0x20000];
        let sections = vec![SectionInfo {
            name: ".rdata".to_string(),
            va_start: 0x1000_0000,
            va_end: 0x1002_0000,
            file_offset: 0,
            executable: false,
            readable: true,
            writable: false,
        }];
        let img = BinaryImage::new(&data, 0, sections, Bitness::B64);
        let cfg = FinderConfig::default();
        let finder = VtableFinder::new(&img, cfg);
        let candidates = finder.find_all();
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_confidence_score_with_rtti() {
        let slots: Vec<Addr> = (0..5).map(|i| 0x0040_0000u64 + i * 0x20).collect();
        let (data, sections) = make_image_with_vtable(&slots);
        let img = BinaryImage::new(&data, 0, sections, Bitness::B64);
        let finder = VtableFinder::new(&img, FinderConfig::default());
        let score_no_rtti = finder.score_confidence(&slots, false);
        let score_with_rtti = finder.score_confidence(&slots, true);
        assert!(score_with_rtti > score_no_rtti);
    }

    #[test]
    fn test_abstract_vtable_detection() {
        let same_fn = 0x0040_0000u64;
        let candidate = VtableCandidate {
            va: 0x1000_0000,
            slot_count: 4,
            slots: vec![same_fn; 4],
            rtti_va: None,
            class_name: None,
            rtti_kind: RttiKind::None,
            confidence: 50,
        };
        assert!(candidate.is_abstract());
    }

    #[test]
    fn test_is_code_pointer() {
        let data = vec![0u8; 0x1000];
        let sections = vec![SectionInfo {
            name: ".text".to_string(),
            va_start: 0x1000,
            va_end: 0x2000,
            file_offset: 0,
            executable: true,
            readable: true,
            writable: false,
        }];
        let img = BinaryImage::new(&data, 0, sections, Bitness::B64);
        assert!(img.is_code_pointer(0x1000));
        assert!(img.is_code_pointer(0x1fff));
        assert!(!img.is_code_pointer(0x2000));
        assert!(!img.is_code_pointer(0x0));
    }

    #[test]
    fn test_bitness_read_addr_32() {
        let data: Vec<u8> = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let result = Bitness::B32.read_addr(&data, 0).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_bitness_read_addr_64() {
        let val: u64 = 0xdeadbeef_cafebabe;
        let data = val.to_le_bytes().to_vec();
        let result = Bitness::B64.read_addr(&data, 0).unwrap();
        assert_eq!(result, val);
    }

    #[test]
    fn test_section_contains() {
        let sec = SectionInfo {
            name: ".rdata".to_string(),
            va_start: 0x1000,
            va_end: 0x2000,
            file_offset: 0,
            executable: false,
            readable: true,
            writable: false,
        };
        assert!(sec.contains(0x1000));
        assert!(sec.contains(0x1fff));
        assert!(!sec.contains(0x2000));
    }

    #[test]
    fn test_multi_image_scanner() {
        let fns: Vec<u64> = (0..3).map(|i| 0x0040_0000u64 + i * 0x10).collect();
        let (data, sections) = make_image_with_vtable(&fns);
        let img = BinaryImage::new(&data, 0, sections, Bitness::B64);
        let mut scanner = MultiImageScanner::new();
        scanner.scan("test.exe", &img, FinderConfig::default());
        assert!(scanner.total_candidates() > 0);
    }

    #[test]
    fn test_vtable_candidate_fields() {
        let c = VtableCandidate {
            va: 0x1000_0010,
            slot_count: 3,
            slots: vec![0x401000, 0x401020, 0x401040],
            rtti_va: Some(0x1000_0000),
            class_name: Some("MyClass".to_string()),
            rtti_kind: RttiKind::Msvc,
            confidence: 75,
        };
        assert!(!c.is_abstract());
        assert_eq!(c.slot_count, 3);
    }

    // ─── Adversarial / hardening regression tests ───────────────────────────

    fn tiny_img(data: Vec<u8>) -> (Vec<u8>, Vec<SectionInfo>) {
        let sections = vec![SectionInfo {
            name: ".rdata".to_string(),
            va_start: 0x1000,
            va_end: 0x1000 + data.len() as Addr,
            file_offset: 0,
            executable: false,
            readable: true,
            writable: false,
        }];
        (data, sections)
    }

    #[test]
    fn read_addr_no_overflow_on_huge_offset() {
        // off near usize::MAX must not panic on `off + 4/8`.
        assert_eq!(Bitness::B32.read_addr(&[0u8; 4], usize::MAX - 1), None);
        assert_eq!(Bitness::B64.read_addr(&[0u8; 8], usize::MAX - 2), None);
    }

    #[test]
    fn read_bytes_no_overflow_on_huge_len() {
        let (data, sections) = tiny_img(vec![0u8; 32]);
        let img = BinaryImage::new(&data, 0x1000, sections, Bitness::B64);
        // len == usize::MAX must not overflow `off + len`.
        assert_eq!(img.read_bytes_at_va(0x1000, usize::MAX), None);
    }

    #[test]
    fn type_descriptor_no_panic_on_unterminated_name() {
        // A name field with no NUL terminator and fewer than 256 trailing bytes
        // previously panicked on `&name_bytes[..256]`.
        // Layout: 2 ptrs (16 bytes) then non-NUL bytes to end of data.
        let mut data = vec![0u8; 16];
        data.extend(std::iter::repeat(b'A').take(10)); // 10 non-NUL bytes, no terminator
        let (data, sections) = tiny_img(data);
        let img = BinaryImage::new(&data, 0x1000, sections, Bitness::B64);
        // Must return None (name doesn't match heuristic), NOT panic.
        assert_eq!(try_read_msvc_type_descriptor(&img, 0x1000), None);
    }

    #[test]
    fn regress_find_all_inverted_section_terminates() {
        // A section with va_end < va_start previously underflowed to a
        // ~u64::MAX-length scan loop.
        let data = vec![0u8; 64];
        let sections = vec![SectionInfo {
            name: ".bad".to_string(),
            va_start: 0x2000,
            va_end: 0x1000, // inverted
            file_offset: 0,
            executable: false,
            readable: true,
            writable: false,
        }];
        let img = BinaryImage::new(&data, 0x1000, sections, Bitness::B64);
        let finder = VtableFinder::new(&img, FinderConfig::default());
        assert!(finder.find_all().is_empty());
    }

    #[test]
    fn regress_itanium_typeinfo_huge_file_offset_no_overflow() {
        // Caller-supplied SectionInfo.file_offset near usize::MAX must not
        // wrap when ptr_sz is added.
        let data = vec![0u8; 32];
        let sections = vec![SectionInfo {
            name: ".rdata".to_string(),
            va_start: 0x1000,
            va_end: 0x1020,
            file_offset: usize::MAX - 4,
            executable: false,
            readable: true,
            writable: false,
        }];
        let img = BinaryImage::new(&data, 0x1000, sections, Bitness::B64);
        assert_eq!(try_read_itanium_typeinfo(&img, 0x1000), None);
    }

    use crate::test_prng::XorShift;

    #[test]
    fn fuzz_finder_no_panic_on_random_images() {
        let mut rng = XorShift(0xdead_beef_1337_4242);
        for _ in 0..200 {
            let len = 64 + (rng.next() % 256) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let va_start = rng.next() % 0x2_0000;
            let sections = vec![
                SectionInfo {
                    name: ".text".to_string(),
                    va_start,
                    va_end: va_start.wrapping_add(rng.next() % (len as u64 * 2 + 1)),
                    file_offset: (rng.next() % (len as u64 + 8)) as usize,
                    executable: true,
                    readable: true,
                    writable: false,
                },
                SectionInfo {
                    name: ".rdata".to_string(),
                    va_start: va_start.wrapping_add(rng.next() % 0x1000),
                    va_end: va_start.wrapping_add(rng.next() % 0x1000),
                    file_offset: (rng.next() % (len as u64 + 8)) as usize,
                    executable: false,
                    readable: true,
                    writable: false,
                },
            ];
            let bitness = if rng.next() & 1 == 0 { Bitness::B32 } else { Bitness::B64 };
            let img = BinaryImage::new(&data, va_start, sections, bitness);
            let finder = VtableFinder::new(&img, FinderConfig::default());
            let _ = finder.find_all();
            let _ = try_read_msvc_type_descriptor(&img, rng.next() % 0x2_0000);
            let _ = try_read_itanium_typeinfo(&img, rng.next() % 0x2_0000);
        }
    }

    #[test]
    fn find_all_output_sorted_deterministic() {
        let fns: Vec<u64> = (0..5).map(|i| 0x0040_0000u64 + i * 0x20).collect();
        let (data, sections) = make_image_with_vtable(&fns);
        let img = BinaryImage::new(&data, 0x0040_0000, sections, Bitness::B64);
        let finder = VtableFinder::new(&img, FinderConfig::default());
        let a = finder.find_all();
        let b = finder.find_all();
        let vas_a: Vec<_> = a.iter().map(|c| c.va).collect();
        let vas_b: Vec<_> = b.iter().map(|c| c.va).collect();
        assert_eq!(vas_a, vas_b);
        assert!(vas_a.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn type_descriptor_reads_valid_unterminated_at_eof() {
        // ".?AVX" with no NUL, right at EOF: must be read, not panic.
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b".?AVFoo");
        let (data, sections) = tiny_img(data);
        let img = BinaryImage::new(&data, 0x1000, sections, Bitness::B64);
        assert_eq!(
            try_read_msvc_type_descriptor(&img, 0x1000).as_deref(),
            Some(".?AVFoo")
        );
    }
}
