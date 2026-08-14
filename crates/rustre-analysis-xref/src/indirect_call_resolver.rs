//! Indirect call resolver.
//!
//! Resolves indirect calls (calls through registers / memory) and vtable dispatches.
//! Tracks function pointer sites and vtable layouts to produce concrete call edges
//! that can be fed into the `XrefCallGraph`.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ResolverError {
    VtableNotFound { address: u64 },
    SlotOutOfRange { vtable: u64, slot: usize, max: usize },
    AmbiguousTarget { site: u64, candidates: usize },
    InvalidVtableLayout { address: u64, reason: &'static str },
    PointerSizeUnsupported { bits: u8 },
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VtableNotFound { address } =>
                write!(f, "vtable not found at 0x{address:016X}"),
            Self::SlotOutOfRange { vtable, slot, max } =>
                write!(f, "vtable 0x{vtable:016X}: slot {slot} >= max {max}"),
            Self::AmbiguousTarget { site, candidates } =>
                write!(f, "indirect call at 0x{site:016X} has {candidates} unresolved candidates"),
            Self::InvalidVtableLayout { address, reason } =>
                write!(f, "invalid vtable at 0x{address:016X}: {reason}"),
            Self::PointerSizeUnsupported { bits } =>
                write!(f, "pointer size {bits}-bit not supported"),
        }
    }
}

impl std::error::Error for ResolverError {}
pub type ResolverResult<T> = Result<T, ResolverError>;

// ---------------------------------------------------------------------------
// VtableEntry
// ---------------------------------------------------------------------------

/// One slot in a C++ virtual function table.
#[derive(Debug, Clone)]
pub struct VtableEntry {
    /// Slot index (0-based).
    pub slot: usize,
    /// Address stored in this slot (the function pointer).
    pub function_address: u64,
    /// Optional mangled or demangled name.
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Vtable
// ---------------------------------------------------------------------------

/// A parsed C++ virtual function table.
#[derive(Debug, Clone)]
pub struct Vtable {
    /// The address of the vtable data (where the pointers are stored).
    pub address: u64,
    /// The class this vtable belongs to (if known).
    pub class_name: Option<String>,
    /// The entries in slot order.
    pub entries: Vec<VtableEntry>,
}

impl Vtable {
    /// Create a new vtable from an address and a list of function-pointer values.
    #[must_use] 
    pub fn new(address: u64, function_pointers: Vec<u64>) -> Self {
        let entries = function_pointers.into_iter().enumerate().map(|(slot, fa)| {
            VtableEntry { slot, function_address: fa, name: None }
        }).collect();
        Self { address, class_name: None, entries }
    }

    /// Parse a vtable from raw bytes at `data_offset` within `data`, reading `slot_count` slots.
    /// `pointer_size` must be 4 or 8.
    ///
    /// # Errors
    ///
    /// Returns `ResolverError` if `pointer_size` is not 4 or 8, or if `data` is too short.
    ///
    /// # Panics
    ///
    /// Panics if a slice-to-array conversion fails (only if bounds check above is bypassed).
    pub fn parse(data: &[u8], data_offset: usize, vtable_address: u64,
                 slot_count: usize, pointer_size: u8) -> ResolverResult<Self> {
        if pointer_size != 4 && pointer_size != 8 {
            return Err(ResolverError::PointerSizeUnsupported { bits: pointer_size });
        }
        let step = pointer_size as usize;
        let needed = slot_count
            .checked_mul(step)
            .and_then(|n| n.checked_add(data_offset));
        if needed.is_none_or(|n| data.len() < n) {
            return Err(ResolverError::InvalidVtableLayout {
                address: vtable_address,
                reason: "data too short for requested slot count",
            });
        }
        let function_pointers: Vec<u64> = (0..slot_count).map(|i| {
            let off = data_offset + i * step;
            if pointer_size == 8 {
                u64::from_le_bytes(data[off..off+8].try_into().unwrap())
            } else {
                u64::from(u32::from_le_bytes(data[off..off+4].try_into().unwrap()))
            }
        }).collect();
        Ok(Self::new(vtable_address, function_pointers))
    }

    /// Resolve the target function address for a given slot.
    ///
    /// # Errors
    ///
    /// Returns `ResolverError::SlotOutOfRange` if `slot` is out of bounds.
    pub fn target_at_slot(&self, slot: usize) -> ResolverResult<u64> {
        self.entries.get(slot)
            .map(|e| e.function_address)
            .ok_or(ResolverError::SlotOutOfRange {
                vtable: self.address,
                slot,
                max: self.entries.len(),
            })
    }

    /// Set the function name for a specific slot.
    pub fn set_slot_name(&mut self, slot: usize, name: impl Into<String>) -> bool {
        if let Some(e) = self.entries.get_mut(slot) {
            e.name = Some(name.into());
            true
        } else {
            false
        }
    }

    #[must_use] 
    pub const fn slot_count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// VtableCall
// ---------------------------------------------------------------------------

/// A resolved vtable call site.
#[derive(Debug, Clone)]
pub struct VtableCall {
    /// Address of the call instruction.
    pub call_site: u64,
    /// Address of the vtable being dispatched through.
    pub vtable_address: u64,
    /// Slot index being called.
    pub slot: usize,
    /// Resolved target function address.
    pub target: u64,
    /// Confidence [0, 100].
    pub confidence: u8,
}

// ---------------------------------------------------------------------------
// FunctionPointerKind
// ---------------------------------------------------------------------------

/// How a function pointer is stored or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionPointerKind {
    /// Global variable containing a function pointer.
    GlobalVariable,
    /// Stack variable containing a function pointer.
    StackVariable,
    /// Field of a struct/class.
    StructField,
    /// Element of an array of function pointers.
    ArrayElement,
    /// Argument passed to a function.
    FunctionArgument,
    /// Return value of a function.
    ReturnValue,
}

// ---------------------------------------------------------------------------
// FunctionPointerSite
// ---------------------------------------------------------------------------

/// A site where a function pointer is used for an indirect call.
#[derive(Debug, Clone)]
pub struct FunctionPointerSite {
    /// Address of the indirect call instruction.
    pub call_site: u64,
    /// Address of the operand that holds the pointer (register resolved to memory, etc.).
    pub pointer_address: Option<u64>,
    /// How the pointer is stored.
    pub kind: FunctionPointerKind,
    /// Concrete target addresses that have been resolved for this site.
    pub resolved_targets: Vec<u64>,
    /// Confidence in the resolution [0, 100].
    pub confidence: u8,
    /// Whether the resolver considers this site fully resolved.
    pub is_resolved: bool,
}

impl FunctionPointerSite {
    #[must_use] 
    pub const fn new(call_site: u64, kind: FunctionPointerKind) -> Self {
        Self {
            call_site,
            pointer_address: None,
            kind,
            resolved_targets: Vec::new(),
            confidence: 0,
            is_resolved: false,
        }
    }

    #[must_use] 
    pub const fn with_pointer_address(mut self, addr: u64) -> Self {
        self.pointer_address = Some(addr);
        self
    }

    pub fn add_target(&mut self, target: u64, confidence: u8) {
        if !self.resolved_targets.contains(&target) {
            self.resolved_targets.push(target);
        }
        self.confidence = self.confidence.max(confidence);
        self.is_resolved = !self.resolved_targets.is_empty();
    }
}

// ---------------------------------------------------------------------------
// IndirectCallResolver
// ---------------------------------------------------------------------------

/// Resolves indirect calls by tracking vtables and function pointer assignment sites.
pub struct IndirectCallResolver {
    /// Known vtables by their data address.
    vtables: HashMap<u64, Vtable>,
    /// Known indirect call sites.
    fp_sites: Vec<FunctionPointerSite>,
    /// Resolved vtable calls.
    vtable_calls: Vec<VtableCall>,
    /// Maps data address → set of function addresses written to it.
    /// Used for simple "global function pointer" resolution.
    global_fp_writes: HashMap<u64, Vec<(u64, u8)>>, // data_addr → [(target, confidence)]
    pointer_size: u8,
}

impl IndirectCallResolver {
    #[must_use] 
    pub fn new(pointer_size: u8) -> Self {
        Self {
            vtables: HashMap::new(),
            fp_sites: Vec::new(),
            vtable_calls: Vec::new(),
            global_fp_writes: HashMap::new(),
            pointer_size,
        }
    }

    /// Register a vtable.
    pub fn add_vtable(&mut self, vtable: Vtable) {
        self.vtables.insert(vtable.address, vtable);
    }

    /// Parse and register a vtable from raw data.
    ///
    /// # Errors
    ///
    /// Returns `ResolverError` if the vtable cannot be parsed from `data`.
    pub fn parse_vtable(&mut self, data: &[u8], data_offset: usize,
                         vtable_address: u64, slot_count: usize) -> ResolverResult<()> {
        let vt = Vtable::parse(data, data_offset, vtable_address, slot_count, self.pointer_size)?;
        self.vtables.insert(vtable_address, vt);
        Ok(())
    }

    /// Register that a write of `target_function` to `data_address` was observed.
    pub fn record_fp_write(&mut self, data_address: u64, target_function: u64, confidence: u8) {
        self.global_fp_writes
            .entry(data_address)
            .or_default()
            .push((target_function, confidence));
    }

    /// Record an indirect call site (not yet resolved).
    pub fn add_fp_site(&mut self, site: FunctionPointerSite) {
        self.fp_sites.push(site);
    }

    /// Resolve a vtable call: given a call instruction at `call_site` that calls through
    /// `vtable_address[slot]`, find the concrete target and record the resolution.
    ///
    /// # Errors
    ///
    /// Returns `ResolverError` if the vtable is not found or the slot is out of range.
    pub fn resolve_vtable_call(&mut self, call_site: u64, vtable_address: u64,
                                slot: usize, confidence: u8) -> ResolverResult<u64> {
        let vt = self.vtables.get(&vtable_address)
            .ok_or(ResolverError::VtableNotFound { address: vtable_address })?;
        let target = vt.target_at_slot(slot)?;
        self.vtable_calls.push(VtableCall {
            call_site,
            vtable_address,
            slot,
            target,
            confidence,
        });
        Ok(target)
    }

    /// Attempt to resolve an indirect call site that goes through a known global fp address.
    pub fn resolve_global_fp(&mut self, call_site: u64, fp_address: u64) -> Vec<(u64, u8)> {
        let targets = self.global_fp_writes
            .get(&fp_address)
            .cloned()
            .unwrap_or_default();
        // Find or update the fp_site
        if let Some(site) = self.fp_sites.iter_mut().find(|s| s.call_site == call_site) {
            for (target, conf) in &targets {
                site.add_target(*target, *conf);
            }
        } else {
            let mut site = FunctionPointerSite::new(call_site, FunctionPointerKind::GlobalVariable)
                .with_pointer_address(fp_address);
            for (target, conf) in &targets {
                site.add_target(*target, *conf);
            }
            self.fp_sites.push(site);
        }
        targets
    }

    /// Run all registered `fp_sites` against known `global_fp_writes`.
    pub fn batch_resolve_global_fps(&mut self) {
        for site in &mut self.fp_sites {
            let Some(pa) = site.pointer_address else { continue };
            let Some(writes) = self.global_fp_writes.get(&pa) else { continue };
            for (target, conf) in writes.clone() {
                site.add_target(target, conf);
            }
        }
    }

    /// Return all successfully resolved vtable calls.
    #[must_use] 
    pub fn resolved_vtable_calls(&self) -> &[VtableCall] {
        &self.vtable_calls
    }

    /// Return all function-pointer sites.
    #[must_use] 
    pub fn fp_sites(&self) -> &[FunctionPointerSite] {
        &self.fp_sites
    }

    /// Return resolved function-pointer sites only.
    #[must_use] 
    pub fn resolved_fp_sites(&self) -> Vec<&FunctionPointerSite> {
        self.fp_sites.iter().filter(|s| s.is_resolved).collect()
    }

    /// Return unresolved function-pointer sites.
    #[must_use] 
    pub fn unresolved_fp_sites(&self) -> Vec<&FunctionPointerSite> {
        self.fp_sites.iter().filter(|s| !s.is_resolved).collect()
    }

    /// Enumerate all (`call_site`, target) pairs from both vtable and fp resolutions.
    #[must_use] 
    pub fn all_resolved_edges(&self) -> Vec<(u64, u64, u8)> {
        let mut edges: Vec<(u64, u64, u8)> = Vec::new();
        for vc in &self.vtable_calls {
            edges.push((vc.call_site, vc.target, vc.confidence));
        }
        for site in &self.fp_sites {
            for &target in &site.resolved_targets {
                edges.push((site.call_site, target, site.confidence));
            }
        }
        edges
    }

    /// Return the vtable at a given address (if registered).
    #[must_use] 
    pub fn vtable(&self, address: u64) -> Option<&Vtable> {
        self.vtables.get(&address)
    }

    /// Return all registered vtables.
    pub fn vtables(&self) -> impl Iterator<Item = &Vtable> {
        self.vtables.values()
    }

    /// Statistics summary.
    #[must_use] 
    pub fn summary(&self) -> IndirectCallStats {
        IndirectCallStats {
            vtable_count: self.vtables.len(),
            total_vtable_slots: self.vtables.values().map(Vtable::slot_count).sum(),
            resolved_vtable_calls: self.vtable_calls.len(),
            fp_site_count: self.fp_sites.len(),
            resolved_fp_sites: self.fp_sites.iter().filter(|s| s.is_resolved).count(),
            unresolved_fp_sites: self.fp_sites.iter().filter(|s| !s.is_resolved).count(),
        }
    }
}

/// Statistics about the resolver's state.
#[derive(Debug, Clone)]
pub struct IndirectCallStats {
    pub vtable_count: usize,
    pub total_vtable_slots: usize,
    pub resolved_vtable_calls: usize,
    pub fp_site_count: usize,
    pub resolved_fp_sites: usize,
    pub unresolved_fp_sites: usize,
}

impl fmt::Display for IndirectCallStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "vtables={} slots={} vtable_calls_resolved={} fp_sites={} fp_resolved={} fp_unresolved={}",
            self.vtable_count, self.total_vtable_slots,
            self.resolved_vtable_calls,
            self.fp_site_count, self.resolved_fp_sites, self.unresolved_fp_sites,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vtable_bytes_64(entries: &[u64]) -> Vec<u8> {
        let mut data = Vec::with_capacity(entries.len() * 8);
        for &e in entries {
            data.extend_from_slice(&e.to_le_bytes());
        }
        data
    }

    fn make_vtable_bytes_32(entries: &[u32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(entries.len() * 4);
        for &e in entries {
            data.extend_from_slice(&e.to_le_bytes());
        }
        data
    }

    #[test]
    fn vtable_parse_64bit() {
        let targets = vec![0x1000u64, 0x2000, 0x3000];
        let data = make_vtable_bytes_64(&targets);
        let vt = Vtable::parse(&data, 0, 0x5000, 3, 8).unwrap();
        assert_eq!(vt.slot_count(), 3);
        assert_eq!(vt.target_at_slot(0).unwrap(), 0x1000);
        assert_eq!(vt.target_at_slot(2).unwrap(), 0x3000);
    }

    #[test]
    fn vtable_parse_32bit() {
        let targets = vec![0x1000u32, 0x2000];
        let data = make_vtable_bytes_32(&targets);
        let vt = Vtable::parse(&data, 0, 0x4000, 2, 4).unwrap();
        assert_eq!(vt.target_at_slot(0).unwrap(), 0x1000);
        assert_eq!(vt.target_at_slot(1).unwrap(), 0x2000);
    }

    #[test]
    fn vtable_slot_out_of_range() {
        let vt = Vtable::new(0x1000, vec![0x9000]);
        assert!(matches!(vt.target_at_slot(5), Err(ResolverError::SlotOutOfRange { .. })));
    }

    #[test]
    fn vtable_set_slot_name() {
        let mut vt = Vtable::new(0x1000, vec![0x9000, 0xA000]);
        assert!(vt.set_slot_name(0, "destructor"));
        assert_eq!(vt.entries[0].name.as_deref(), Some("destructor"));
        assert!(!vt.set_slot_name(5, "oob")); // out of range, should return false
    }

    #[test]
    fn resolve_vtable_call() {
        let mut resolver = IndirectCallResolver::new(8);
        let vt = Vtable::new(0x5000, vec![0xA000, 0xB000, 0xC000]);
        resolver.add_vtable(vt);
        let target = resolver.resolve_vtable_call(0x1234, 0x5000, 1, 95).unwrap();
        assert_eq!(target, 0xB000);
        assert_eq!(resolver.resolved_vtable_calls().len(), 1);
    }

    #[test]
    fn resolve_vtable_call_not_found() {
        let mut resolver = IndirectCallResolver::new(8);
        assert!(matches!(
            resolver.resolve_vtable_call(0x1234, 0x9999, 0, 90),
            Err(ResolverError::VtableNotFound { .. })
        ));
    }

    #[test]
    fn global_fp_resolution() {
        let mut resolver = IndirectCallResolver::new(8);
        // Record two writes to global fp at 0xDEAD
        resolver.record_fp_write(0xDEAD, 0x1000, 80);
        resolver.record_fp_write(0xDEAD, 0x2000, 60);
        // Register a call site using that fp
        let site = FunctionPointerSite::new(0x5678, FunctionPointerKind::GlobalVariable)
            .with_pointer_address(0xDEAD);
        resolver.add_fp_site(site);
        resolver.batch_resolve_global_fps();

        let resolved = resolver.resolved_fp_sites();
        assert_eq!(resolved.len(), 1);
        let targets = &resolved[0].resolved_targets;
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x2000));
    }

    #[test]
    fn all_resolved_edges() {
        let mut resolver = IndirectCallResolver::new(8);
        let vt = Vtable::new(0x5000, vec![0xA000]);
        resolver.add_vtable(vt);
        resolver.resolve_vtable_call(0x100, 0x5000, 0, 100).unwrap();
        resolver.record_fp_write(0x200, 0x3000, 75);
        resolver.resolve_global_fp(0x300, 0x200);

        let edges = resolver.all_resolved_edges();
        assert!(edges.iter().any(|&(cs, tgt, _)| cs == 0x100 && tgt == 0xA000));
        assert!(edges.iter().any(|&(cs, tgt, _)| cs == 0x300 && tgt == 0x3000));
    }

    #[test]
    fn stats_summary() {
        let mut resolver = IndirectCallResolver::new(8);
        resolver.add_vtable(Vtable::new(0x1000, vec![0x9000, 0xA000]));
        resolver.add_vtable(Vtable::new(0x2000, vec![0xB000]));
        resolver.resolve_vtable_call(0x100, 0x1000, 0, 100).unwrap();
        let stats = resolver.summary();
        assert_eq!(stats.vtable_count, 2);
        assert_eq!(stats.total_vtable_slots, 3);
        assert_eq!(stats.resolved_vtable_calls, 1);
        let s = stats.to_string();
        assert!(s.contains("vtables=2"));
        assert!(s.contains("slots=3"));
    }

    #[test]
    fn fp_site_add_target_deduplicates() {
        let mut site = FunctionPointerSite::new(0x1000, FunctionPointerKind::StructField);
        site.add_target(0xAAAA, 80);
        site.add_target(0xAAAA, 90); // duplicate
        site.add_target(0xBBBB, 70);
        assert_eq!(site.resolved_targets.len(), 2);
        assert_eq!(site.confidence, 90); // max confidence
        assert!(site.is_resolved);
    }

    #[test]
    fn unresolved_site_stays_unresolved() {
        let resolver = {
            let mut r = IndirectCallResolver::new(8);
            let site = FunctionPointerSite::new(0x9999, FunctionPointerKind::StackVariable);
            r.add_fp_site(site);
            r
        };
        assert_eq!(resolver.unresolved_fp_sites().len(), 1);
        assert_eq!(resolver.resolved_fp_sites().len(), 0);
    }

    #[test]
    fn vtable_parse_unsupported_pointer_size() {
        let data = vec![0u8; 16];
        assert!(matches!(
            Vtable::parse(&data, 0, 0x1000, 2, 3),
            Err(ResolverError::PointerSizeUnsupported { bits: 3 })
        ));
    }

    #[test]
    fn vtable_parse_data_too_short() {
        // 3 slots * 8 bytes = 24 bytes needed, only provide 16
        let data = vec![0u8; 16];
        assert!(matches!(
            Vtable::parse(&data, 0, 0x1000, 3, 8),
            Err(ResolverError::InvalidVtableLayout { .. })
        ));
    }

    #[test]
    fn vtable_parse_with_offset_exact_fit() {
        // Regression check for the offset+size boundary: offset 8, 2 slots * 8 = 16,
        // total needed 24 bytes exactly.
        let targets = vec![0x1111u64, 0x2222];
        let mut data = vec![0u8; 8]; // padding before the vtable
        data.extend(make_vtable_bytes_64(&targets));
        let vt = Vtable::parse(&data, 8, 0x7000, 2, 8).unwrap();
        assert_eq!(vt.target_at_slot(0).unwrap(), 0x1111);
        assert_eq!(vt.target_at_slot(1).unwrap(), 0x2222);
    }

    #[test]
    fn resolver_parse_vtable_method() {
        let mut resolver = IndirectCallResolver::new(8);
        let data = make_vtable_bytes_64(&[0xAAAA, 0xBBBB]);
        resolver.parse_vtable(&data, 0, 0x9000, 2).unwrap();
        let vt = resolver.vtable(0x9000).expect("vtable should be registered");
        assert_eq!(vt.target_at_slot(1).unwrap(), 0xBBBB);
    }

    #[test]
    fn resolver_vtable_getter_missing() {
        let resolver = IndirectCallResolver::new(8);
        assert!(resolver.vtable(0x1234).is_none());
    }

    #[test]
    fn resolver_vtables_iterator() {
        let mut resolver = IndirectCallResolver::new(8);
        resolver.add_vtable(Vtable::new(0x1000, vec![0xA]));
        resolver.add_vtable(Vtable::new(0x2000, vec![0xB]));
        let addrs: Vec<u64> = resolver.vtables().map(|v| v.address).collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x2000));
    }

    #[test]
    fn resolve_global_fp_with_no_writes_stays_unresolved() {
        let mut resolver = IndirectCallResolver::new(8);
        let targets = resolver.resolve_global_fp(0x5555, 0xBEEF);
        assert!(targets.is_empty());
        let unresolved = resolver.unresolved_fp_sites();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].call_site, 0x5555);
    }

    #[test]
    fn resolver_error_display_all_variants() {
        let e = ResolverError::VtableNotFound { address: 0x1000 };
        assert!(e.to_string().contains("vtable not found"));

        let e = ResolverError::SlotOutOfRange { vtable: 0x2000, slot: 4, max: 2 };
        let s = e.to_string();
        assert!(s.contains("slot 4"));
        assert!(s.contains("max 2"));

        let e = ResolverError::AmbiguousTarget { site: 0x3000, candidates: 3 };
        assert!(e.to_string().contains("3 unresolved candidates"));

        let e = ResolverError::InvalidVtableLayout { address: 0x4000, reason: "bad" };
        assert!(e.to_string().contains("bad"));

        let e = ResolverError::PointerSizeUnsupported { bits: 16 };
        assert!(e.to_string().contains("16-bit"));
    }

    #[test]
    fn function_pointer_site_builder() {
        let site = FunctionPointerSite::new(0x1000, FunctionPointerKind::ArrayElement)
            .with_pointer_address(0x2000);
        assert_eq!(site.call_site, 0x1000);
        assert_eq!(site.pointer_address, Some(0x2000));
        assert!(!site.is_resolved);
        assert_eq!(site.confidence, 0);
    }
}
