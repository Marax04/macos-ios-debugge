//! `vtable_recovery` — C++ vtable detection, validation, and class recovery.
//!
//! Provides:
//! * [`VtableRecovery`]       — top-level coordinator.
//! * [`VtableCandidate`]      — a potential vtable (addr + function pointer list).
//! * [`VtableValidator`]      — checks that all entries are valid function pointers.
//! * [`ClassReconstructor`]   — builds a class skeleton from a vtable.
//! * [`VtableInheritance`]    — infers inheritance from vtable overlaps.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// VtableCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate vtable found in a binary.
#[derive(Debug, Clone, PartialEq)]
pub struct VtableCandidate {
    /// Address of the first function pointer in the vtable.
    pub addr: u64,
    /// Ordered list of function pointer values read from the vtable.
    pub function_ptrs: Vec<u64>,
    /// True when the validator has confirmed all entries are valid.
    pub validated: bool,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Optional class name derived from RTTI.
    pub class_name: Option<String>,
    /// RTTI pointer (points to `__type_info` or `RTTICompleteObjectLocator`).
    pub rtti_ptr: Option<u64>,
}

impl VtableCandidate {
    #[must_use] 
    pub const fn new(addr: u64, function_ptrs: Vec<u64>) -> Self {
        Self {
            addr,
            function_ptrs,
            validated: false,
            confidence: 0.5,
            class_name: None,
            rtti_ptr: None,
        }
    }

    #[must_use] 
    pub const fn with_confidence(mut self, c: f32) -> Self {
        self.confidence = c;
        self
    }

    #[must_use]
    pub fn with_class_name(mut self, name: impl Into<String>) -> Self {
        self.class_name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn with_rtti(mut self, ptr: u64) -> Self {
        self.rtti_ptr = Some(ptr);
        self
    }

    /// Number of virtual method slots.
    #[must_use] 
    pub const fn slot_count(&self) -> usize {
        self.function_ptrs.len()
    }

    /// True if this vtable is "large enough" to be interesting.
    #[must_use] 
    pub const fn is_substantive(&self) -> bool {
        self.function_ptrs.len() >= 2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scans a binary image for candidate vtables.
///
/// Strategy: scan the `.rodata` / `.rdata` section for 8-byte-aligned
/// sequences of 64-bit values that all point into executable sections.
pub struct VtableScanner {
    /// Address ranges considered "executable" (functions may reside here).
    pub exec_ranges: Vec<(u64, u64)>,
    /// Minimum vtable slot count.
    pub min_slots: usize,
    /// Maximum vtable slot count (safety limit).
    pub max_slots: usize,
}

impl VtableScanner {
    #[must_use] 
    pub const fn new(exec_ranges: Vec<(u64, u64)>) -> Self {
        Self {
            exec_ranges,
            min_slots: 1,
            max_slots: 256,
        }
    }

    /// True when `addr` falls within a known executable range.
    #[must_use] 
    pub fn is_executable(&self, addr: u64) -> bool {
        self.exec_ranges
            .iter()
            .any(|(lo, hi)| addr >= *lo && addr < *hi)
    }

    /// Scan `data` (loaded at `base`) for vtable candidates.
    /// `data` should be a read-only data segment (`.rodata`/`.rdata`).
    ///
    /// # Panics
    /// Panics if a 8-byte slice cannot be converted to `[u8; 8]` (never in practice).
    #[must_use]
    pub fn scan(&self, base: u64, data: &[u8]) -> Vec<VtableCandidate> {
        let mut candidates = Vec::new();
        let len = data.len();
        // Align to 8 bytes.
        let mut i = 0;
        while i + 8 <= len {
            // Read a potential pointer.
            let ptr = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
            if !self.is_executable(ptr) {
                i += 8;
                continue;
            }
            // We found at least one valid function pointer. Collect as many as possible.
            let start_off = i;
            let mut ptrs = Vec::new();
            while i + 8 <= len && ptrs.len() < self.max_slots {
                let p = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
                if !self.is_executable(p) {
                    break;
                }
                ptrs.push(p);
                i += 8;
            }
            if ptrs.len() >= self.min_slots {
                let vtbl_addr = base + start_off as u64;
                candidates.push(VtableCandidate::new(vtbl_addr, ptrs));
            }
        }
        candidates
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates vtable candidates by checking that all entries are valid
/// function pointers (i.e. they point to known executable regions and
/// optionally match known function starts).
pub struct VtableValidator {
    /// Set of known function start addresses.
    pub known_functions: HashSet<u64>,
    /// Executable ranges.
    pub exec_ranges: Vec<(u64, u64)>,
    /// Minimum fraction of entries that must be confirmed functions (0.0–1.0).
    pub min_function_fraction: f32,
}

impl VtableValidator {
    #[must_use] 
    pub const fn new(known_functions: HashSet<u64>, exec_ranges: Vec<(u64, u64)>) -> Self {
        Self {
            known_functions,
            exec_ranges,
            min_function_fraction: 0.5,
        }
    }

    fn is_in_exec(&self, addr: u64) -> bool {
        self.exec_ranges
            .iter()
            .any(|(lo, hi)| addr >= *lo && addr < *hi)
    }

    /// Validate a single candidate. Returns a score in `[0.0, 1.0]`.
    #[must_use] 
    pub fn validate(&self, candidate: &VtableCandidate) -> f32 {
        if candidate.function_ptrs.is_empty() {
            return 0.0;
        }
        let to_f32 = |n: usize| f32::from(u16::try_from(n).unwrap_or(u16::MAX));
        let total = to_f32(candidate.function_ptrs.len());
        let in_exec = to_f32(
            candidate
                .function_ptrs
                .iter()
                .filter(|&&p| self.is_in_exec(p))
                .count(),
        );
        let known_funcs = to_f32(
            candidate
                .function_ptrs
                .iter()
                .filter(|&&p| self.known_functions.contains(&p))
                .count(),
        );
        // Weight: in-exec is required, known functions add confidence.
        let exec_fraction = in_exec / total;
        if exec_fraction < 0.8 {
            return exec_fraction * 0.5;
        }
        let known_fraction = known_funcs / total;
        exec_fraction.mul_add(0.6, known_fraction * 0.4)
    }

    /// Validate all candidates in-place, updating `validated` and `confidence`.
    pub fn validate_all(&self, candidates: &mut [VtableCandidate]) {
        for c in candidates.iter_mut() {
            let score = self.validate(c);
            c.confidence = score;
            c.validated = score >= self.min_function_fraction;
        }
    }

    /// Filter to only validated candidates.
    #[must_use] 
    pub fn filter_valid(&self, candidates: Vec<VtableCandidate>) -> Vec<VtableCandidate> {
        candidates.into_iter().filter(|c| c.validated).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructedClass
// ─────────────────────────────────────────────────────────────────────────────

/// A C++ class reconstructed from a vtable.
#[derive(Debug, Clone)]
pub struct ReconstructedClass {
    pub name: String,
    pub vtable_addr: u64,
    pub virtual_methods: Vec<VirtualMethod>,
    pub parent_name: Option<String>,
    pub estimated_object_size: Option<usize>,
}

/// One entry in a vtable (virtual method slot).
#[derive(Debug, Clone)]
pub struct VirtualMethod {
    pub slot: usize,
    pub function_ptr: u64,
    pub name: Option<String>,
    pub is_pure_virtual: bool,
}

impl ReconstructedClass {
    pub fn new(name: impl Into<String>, vtable_addr: u64) -> Self {
        Self {
            name: name.into(),
            vtable_addr,
            virtual_methods: Vec::new(),
            parent_name: None,
            estimated_object_size: None,
        }
    }

    /// Number of virtual method slots.
    #[must_use] 
    pub const fn slot_count(&self) -> usize {
        self.virtual_methods.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassReconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// Builds [`ReconstructedClass`] instances from validated vtable candidates.
pub struct ClassReconstructor {
    /// Mapping of function address → demangled name (optional).
    pub function_names: HashMap<u64, String>,
    /// Sentinel address used as a pure-virtual placeholder.
    pub pure_virtual_addr: u64,
}

impl ClassReconstructor {
    #[must_use] 
    pub const fn new(function_names: HashMap<u64, String>, pure_virtual_addr: u64) -> Self {
        Self {
            function_names,
            pure_virtual_addr,
        }
    }

    /// Reconstruct a class from a single validated vtable candidate.
    #[must_use] 
    pub fn reconstruct(&self, candidate: &VtableCandidate) -> ReconstructedClass {
        let name = candidate
            .class_name
            .clone()
            .unwrap_or_else(|| format!("Class_{:08x}", candidate.addr));

        let virtual_methods: Vec<VirtualMethod> = candidate
            .function_ptrs
            .iter()
            .enumerate()
            .map(|(i, &ptr)| VirtualMethod {
                slot: i,
                function_ptr: ptr,
                name: self.function_names.get(&ptr).cloned(),
                is_pure_virtual: ptr == self.pure_virtual_addr,
            })
            .collect();

        let mut cls = ReconstructedClass::new(name, candidate.addr);
        cls.virtual_methods = virtual_methods;
        cls
    }

    /// Reconstruct all classes from a list of candidates.
    #[must_use] 
    pub fn reconstruct_all(&self, candidates: &[VtableCandidate]) -> Vec<ReconstructedClass> {
        candidates.iter().map(|c| self.reconstruct(c)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableInheritance
// ─────────────────────────────────────────────────────────────────────────────

/// Infers inheritance relationships from vtable overlap.
///
/// If vtable B's first N slots are identical to vtable A's N slots,
/// B is likely a subclass of A.
#[derive(Debug, Clone, Default)]
pub struct VtableInheritance {
    /// `parent[child_addr] = parent_addr`.
    pub parent: HashMap<u64, u64>,
    /// `children[parent_addr] = [child_addr, ...]`.
    pub children: HashMap<u64, Vec<u64>>,
}

impl VtableInheritance {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Infer inheritance from a set of vtable candidates.
    ///
    /// A is the parent of B if A's function pointers are a prefix of B's.
    #[must_use] 
    pub fn infer(candidates: &[VtableCandidate]) -> Self {
        let mut inh = Self::new();
        for (i, child) in candidates.iter().enumerate() {
            let mut best_parent: Option<u64> = None;
            let mut best_prefix_len = 0;
            for (j, parent) in candidates.iter().enumerate() {
                if i == j || parent.slot_count() >= child.slot_count() {
                    continue;
                }
                let prefix_len =
                    Self::common_prefix_len(&parent.function_ptrs, &child.function_ptrs);
                if prefix_len == parent.slot_count() && prefix_len > best_prefix_len {
                    best_prefix_len = prefix_len;
                    best_parent = Some(parent.addr);
                }
            }
            if let Some(p_addr) = best_parent {
                inh.parent.insert(child.addr, p_addr);
                inh.children.entry(p_addr).or_default().push(child.addr);
            }
        }
        inh
    }

    fn common_prefix_len(a: &[u64], b: &[u64]) -> usize {
        a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
    }

    /// Is `child_addr` a descendant of `ancestor_addr`?
    #[must_use] 
    pub fn is_descendant(&self, child_addr: u64, ancestor_addr: u64) -> bool {
        let mut cur = child_addr;
        let mut visited: HashSet<u64> = HashSet::new();
        loop {
            if cur == ancestor_addr {
                return true;
            }
            if !visited.insert(cur) {
                return false;
            }
            match self.parent.get(&cur) {
                Some(&p) => cur = p,
                None => return false,
            }
        }
    }

    /// All classes in depth-first order from `root`.
    #[must_use] 
    pub fn class_hierarchy(&self, root: u64) -> Vec<u64> {
        let mut result = Vec::new();
        let mut stack = vec![root];
        let mut visited = HashSet::new();
        while let Some(addr) = stack.pop() {
            if !visited.insert(addr) {
                continue;
            }
            result.push(addr);
            if let Some(children) = self.children.get(&addr) {
                stack.extend(children.iter().copied());
            }
        }
        result
    }

    /// All classes in breadth-first order from `root` (level-by-level traversal).
    ///
    /// Useful for layered class browsers where direct children should be visited
    /// before grandchildren.
    #[must_use] 
    pub fn class_hierarchy_bfs(&self, root: u64) -> Vec<u64> {
        let mut result = Vec::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(root);
        let mut visited = HashSet::new();
        while let Some(addr) = queue.pop_front() {
            if !visited.insert(addr) {
                continue;
            }
            result.push(addr);
            if let Some(children) = self.children.get(&addr) {
                for &c in children {
                    queue.push_back(c);
                }
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableRecovery — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for vtable recovery.
#[derive(Debug, Clone)]
pub struct VtableRecoveryConfig {
    pub min_vtable_slots: usize,
    pub min_validation_score: f32,
    pub infer_inheritance: bool,
    pub reconstruct_classes: bool,
}

impl Default for VtableRecoveryConfig {
    fn default() -> Self {
        Self {
            min_vtable_slots: 1,
            min_validation_score: 0.5,
            infer_inheritance: true,
            reconstruct_classes: true,
        }
    }
}

/// Summary of a vtable recovery run.
#[derive(Debug, Clone)]
pub struct VtableRecoverySummary {
    pub candidates_found: usize,
    pub validated: usize,
    pub classes_reconstructed: usize,
    pub inheritance_edges: usize,
}

/// Top-level vtable recovery coordinator.
pub struct VtableRecovery {
    config: VtableRecoveryConfig,
}

impl VtableRecovery {
    #[must_use] 
    pub const fn new(config: VtableRecoveryConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn default_config() -> Self {
        Self::new(VtableRecoveryConfig::default())
    }

    /// Run full vtable recovery on a binary image.
    ///
    /// * `rodata_base` / `rodata` — the read-only data section.
    /// * `exec_ranges` — executable address ranges (for pointer validation).
    /// * `known_functions` — optional set of confirmed function starts.
    #[must_use] 
    pub fn recover(
        &self,
        rodata_base: u64,
        rodata: &[u8],
        exec_ranges: Vec<(u64, u64)>,
        known_functions: HashSet<u64>,
    ) -> (
        Vec<ReconstructedClass>,
        VtableInheritance,
        VtableRecoverySummary,
    ) {
        // Scan.
        let mut scanner = VtableScanner::new(exec_ranges.clone());
        scanner.min_slots = self.config.min_vtable_slots;
        let mut candidates = scanner.scan(rodata_base, rodata);

        // Validate.
        let validator = VtableValidator::new(known_functions, exec_ranges);
        validator.validate_all(&mut candidates);
        let validated_count = candidates.iter().filter(|c| c.validated).count();

        // Keep only validated candidates.
        candidates.retain(|c| c.confidence >= self.config.min_validation_score);

        // Reconstruct classes.
        let classes = if self.config.reconstruct_classes {
            let reconstructor = ClassReconstructor::new(HashMap::new(), 0);
            reconstructor.reconstruct_all(&candidates)
        } else {
            Vec::new()
        };

        // Infer inheritance.
        let inheritance = if self.config.infer_inheritance {
            VtableInheritance::infer(&candidates)
        } else {
            VtableInheritance::new()
        };

        let summary = VtableRecoverySummary {
            candidates_found: candidates.len(),
            validated: validated_count,
            classes_reconstructed: classes.len(),
            inheritance_edges: inheritance.parent.len(),
        };

        (classes, inheritance, summary)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_ranges() -> Vec<(u64, u64)> {
        vec![(0x1000, 0x5000)]
    }

    fn make_vtable_data(ptrs: &[u64]) -> Vec<u8> {
        ptrs.iter().flat_map(|p| p.to_le_bytes()).collect()
    }

    // 1. VtableCandidate basic.
    #[test]
    fn test_candidate_basic() {
        let c = VtableCandidate::new(0x2000, vec![0x1100, 0x1200, 0x1300]);
        assert_eq!(c.addr, 0x2000);
        assert_eq!(c.slot_count(), 3);
        assert!(!c.validated);
    }

    // 2. VtableCandidate with_confidence.
    #[test]
    fn test_candidate_confidence() {
        let c = VtableCandidate::new(0x2000, vec![0x1100]).with_confidence(0.9);
        assert!((c.confidence - 0.9).abs() < 1e-5);
    }

    // 3. VtableCandidate with_class_name.
    #[test]
    fn test_candidate_class_name() {
        let c = VtableCandidate::new(0x2000, vec![0x1100]).with_class_name("Foo");
        assert_eq!(c.class_name.as_deref(), Some("Foo"));
    }

    // 4. VtableCandidate is_substantive.
    #[test]
    fn test_is_substantive() {
        assert!(!VtableCandidate::new(0, vec![0x1100]).is_substantive());
        assert!(VtableCandidate::new(0, vec![0x1100, 0x1200]).is_substantive());
    }

    // 5. VtableScanner::scan finds candidate.
    #[test]
    fn test_scanner_scan() {
        let base = 0x3000u64;
        let data = make_vtable_data(&[0x1100, 0x1200, 0x1300]);
        let scanner = VtableScanner::new(exec_ranges());
        let candidates = scanner.scan(base, &data);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].addr, base);
        assert_eq!(candidates[0].slot_count(), 3);
    }

    // 6. VtableScanner ignores non-executable pointers.
    #[test]
    fn test_scanner_ignores_non_exec() {
        let base = 0x3000u64;
        // Pointers outside exec range.
        let data = make_vtable_data(&[0x9000, 0xA000]);
        let scanner = VtableScanner::new(exec_ranges());
        let candidates = scanner.scan(base, &data);
        assert!(candidates.is_empty());
    }

    // 7. VtableScanner: mixed executable and non-executable.
    #[test]
    fn test_scanner_mixed() {
        let base = 0x3000u64;
        // First two are executable, third is not → vtable of size 2.
        let data = make_vtable_data(&[0x1100, 0x1200, 0x9000]);
        let scanner = VtableScanner::new(exec_ranges());
        let candidates = scanner.scan(base, &data);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].slot_count(), 2);
    }

    // 8. VtableValidator::validate all-known → high score.
    #[test]
    fn test_validator_all_known() {
        let funcs: HashSet<u64> = [0x1100u64, 0x1200, 0x1300].into();
        let validator = VtableValidator::new(funcs, exec_ranges());
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200, 0x1300]);
        let score = validator.validate(&c);
        assert!(score >= 0.9, "expected high score, got {score}");
    }

    // 9. VtableValidator::validate no known functions.
    #[test]
    fn test_validator_no_known() {
        let validator = VtableValidator::new(HashSet::new(), exec_ranges());
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
        let score = validator.validate(&c);
        // In-exec but not known → medium score.
        assert!(score > 0.0 && score <= 1.0);
    }

    // 10. VtableValidator::validate_all updates candidates.
    #[test]
    fn test_validator_validate_all() {
        let funcs: HashSet<u64> = [0x1100u64, 0x1200].into();
        let validator = VtableValidator::new(funcs, exec_ranges());
        let mut candidates = vec![VtableCandidate::new(0x3000, vec![0x1100, 0x1200])];
        validator.validate_all(&mut candidates);
        assert!(candidates[0].validated);
    }

    // 11. VtableValidator::validate empty vtable → 0.
    #[test]
    fn test_validator_empty() {
        let validator = VtableValidator::new(HashSet::new(), exec_ranges());
        let c = VtableCandidate::new(0x3000, vec![]);
        assert_eq!(validator.validate(&c), 0.0);
    }

    // 12. ClassReconstructor::reconstruct.
    #[test]
    fn test_class_reconstruct() {
        let mut names = HashMap::new();
        names.insert(0x1100u64, "Foo::method1".into());
        let reconstructor = ClassReconstructor::new(names, 0xDEAD);
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]).with_class_name("Foo");
        let cls = reconstructor.reconstruct(&c);
        assert_eq!(cls.name, "Foo");
        assert_eq!(cls.vtable_addr, 0x3000);
        assert_eq!(cls.slot_count(), 2);
        assert_eq!(cls.virtual_methods[0].name.as_deref(), Some("Foo::method1"));
    }

    // 13. ClassReconstructor: default name from address.
    #[test]
    fn test_class_default_name() {
        let reconstructor = ClassReconstructor::new(HashMap::new(), 0);
        let c = VtableCandidate::new(0xABCD_1234, vec![0x1100]);
        let cls = reconstructor.reconstruct(&c);
        assert!(cls.name.starts_with("Class_"));
    }

    // 14. VirtualMethod pure_virtual detection.
    #[test]
    fn test_pure_virtual() {
        let reconstructor = ClassReconstructor::new(HashMap::new(), 0xDEAD);
        let c = VtableCandidate::new(0x3000, vec![0xDEAD, 0x1100]);
        let cls = reconstructor.reconstruct(&c);
        assert!(cls.virtual_methods[0].is_pure_virtual);
        assert!(!cls.virtual_methods[1].is_pure_virtual);
    }

    // 15. VtableInheritance::infer: child inherits parent.
    #[test]
    fn test_inheritance_infer() {
        let parent = VtableCandidate::new(0x2000, vec![0x1100, 0x1200]);
        let child = VtableCandidate::new(0x3000, vec![0x1100, 0x1200, 0x1300]);
        let inh = VtableInheritance::infer(&[parent, child]);
        assert_eq!(inh.parent.get(&0x3000), Some(&0x2000));
    }

    // 16. VtableInheritance::infer: no inheritance for unrelated.
    #[test]
    fn test_inheritance_no_match() {
        let a = VtableCandidate::new(0x2000, vec![0x1100, 0x1200]);
        let b = VtableCandidate::new(0x3000, vec![0x1300, 0x1400]);
        let inh = VtableInheritance::infer(&[a, b]);
        assert!(inh.parent.is_empty());
    }

    // 17. VtableInheritance::is_descendant.
    #[test]
    fn test_is_descendant() {
        let grandparent = VtableCandidate::new(0x1000, vec![0x1100]);
        let parent = VtableCandidate::new(0x2000, vec![0x1100, 0x1200]);
        let child = VtableCandidate::new(0x3000, vec![0x1100, 0x1200, 0x1300]);
        let inh = VtableInheritance::infer(&[grandparent, parent, child]);
        assert!(inh.is_descendant(0x3000, 0x2000));
        assert!(!inh.is_descendant(0x2000, 0x3000));
    }

    // 18. VtableInheritance::class_hierarchy.
    #[test]
    fn test_class_hierarchy() {
        let parent = VtableCandidate::new(0x2000, vec![0x1100]);
        let child = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
        let inh = VtableInheritance::infer(&[parent, child]);
        let hier = inh.class_hierarchy(0x2000);
        assert!(hier.contains(&0x2000));
        assert!(hier.contains(&0x3000));
    }

    // 19. VtableRecovery::recover integration.
    #[test]
    fn test_vtable_recovery_run() {
        let base = 0x3000u64;
        let data = make_vtable_data(&[0x1100, 0x1200, 0x1300]);
        let funcs: HashSet<u64> = [0x1100u64, 0x1200, 0x1300].into();
        let r = VtableRecovery::default_config();
        let (classes, _, summary) = r.recover(base, &data, exec_ranges(), funcs);
        assert_eq!(summary.candidates_found, 1);
        assert!(!classes.is_empty());
    }

    // 20. VtableRecoveryConfig defaults.
    #[test]
    fn test_recovery_config_defaults() {
        let cfg = VtableRecoveryConfig::default();
        assert_eq!(cfg.min_vtable_slots, 1);
        assert!(cfg.infer_inheritance);
        assert!(cfg.reconstruct_classes);
    }

    // 21. VtableCandidate with_rtti.
    #[test]
    fn test_candidate_rtti() {
        let c = VtableCandidate::new(0x2000, vec![0x1100]).with_rtti(0x8000);
        assert_eq!(c.rtti_ptr, Some(0x8000));
    }

    // 22. ClassReconstructor::reconstruct_all.
    #[test]
    fn test_reconstruct_all() {
        let reconstructor = ClassReconstructor::new(HashMap::new(), 0);
        let candidates = vec![
            VtableCandidate::new(0x3000, vec![0x1100]).with_class_name("A"),
            VtableCandidate::new(0x4000, vec![0x1200]).with_class_name("B"),
        ];
        let classes = reconstructor.reconstruct_all(&candidates);
        assert_eq!(classes.len(), 2);
    }

    // 23. VtableValidator::filter_valid.
    #[test]
    fn test_filter_valid() {
        let funcs: HashSet<u64> = [0x1100u64, 0x1200].into();
        let validator = VtableValidator::new(funcs, exec_ranges());
        let mut candidates = vec![
            VtableCandidate::new(0x3000, vec![0x1100, 0x1200]),
            VtableCandidate::new(0x4000, vec![0x9000, 0xA000]), // non-executable
        ];
        validator.validate_all(&mut candidates);
        let valid = validator.filter_valid(candidates);
        assert_eq!(valid.len(), 1);
    }

    // 24. VtableScanner::is_executable.
    #[test]
    fn test_is_executable() {
        let scanner = VtableScanner::new(exec_ranges());
        assert!(scanner.is_executable(0x1100));
        assert!(!scanner.is_executable(0x9000));
        assert!(!scanner.is_executable(0x0FFF));
    }

    // 25. VtableInheritance children map.
    #[test]
    fn test_inheritance_children() {
        let parent = VtableCandidate::new(0x2000, vec![0x1100]);
        let child1 = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
        let child2 = VtableCandidate::new(0x4000, vec![0x1100, 0x1300]);
        let inh = VtableInheritance::infer(&[parent, child1, child2]);
        let children = inh.children.get(&0x2000).unwrap();
        assert_eq!(children.len(), 2);
    }

    // 26. VirtualMethod slot indices.
    #[test]
    fn test_virtual_method_slots() {
        let reconstructor = ClassReconstructor::new(HashMap::new(), 0);
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200, 0x1300]);
        let cls = reconstructor.reconstruct(&c);
        for (i, m) in cls.virtual_methods.iter().enumerate() {
            assert_eq!(m.slot, i);
        }
    }

    // 27. ReconstructedClass slot_count.
    #[test]
    fn test_class_slot_count() {
        let cls = {
            let reconstructor = ClassReconstructor::new(HashMap::new(), 0);
            let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
            reconstructor.reconstruct(&c)
        };
        assert_eq!(cls.slot_count(), 2);
    }

    // 28. VtableScanner max_slots limit.
    #[test]
    fn test_scanner_max_slots() {
        let mut scanner = VtableScanner::new(exec_ranges());
        scanner.max_slots = 2;
        let ptrs: Vec<u64> = (0..5).map(|i| 0x1100 + i * 0x10).collect();
        let data = make_vtable_data(&ptrs);
        let candidates = scanner.scan(0x3000, &data);
        assert!(candidates.iter().all(|c| c.slot_count() <= 2));
    }

    // 29. VtableInheritance empty input.
    #[test]
    fn test_inheritance_empty() {
        let inh = VtableInheritance::infer(&[]);
        assert!(inh.parent.is_empty());
    }

    // 30. VtableRecoverySummary fields.
    #[test]
    fn test_recovery_summary() {
        let summary = VtableRecoverySummary {
            candidates_found: 5,
            validated: 3,
            classes_reconstructed: 3,
            inheritance_edges: 2,
        };
        assert_eq!(summary.candidates_found, 5);
        assert_eq!(summary.validated, 3);
    }

    // 31. VtableValidator with low min_function_fraction.
    #[test]
    fn test_validator_low_threshold() {
        let mut validator = VtableValidator::new(HashSet::new(), exec_ranges());
        validator.min_function_fraction = 0.1;
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
        validator.validate_all(&mut [c.clone()]);
        // Should now be validated since threshold is low.
        let mut candidates = vec![c];
        validator.validate_all(&mut candidates);
        assert!(candidates[0].validated);
    }

    // 32. VtableScanner empty data.
    #[test]
    fn test_scanner_empty() {
        let scanner = VtableScanner::new(exec_ranges());
        let candidates = scanner.scan(0x3000, &[]);
        assert!(candidates.is_empty());
    }

    // 33. ClassReconstructor method names map.
    #[test]
    fn test_class_method_names() {
        let mut names = HashMap::new();
        names.insert(0x1100u64, "Base::virt1".into());
        names.insert(0x1200u64, "Base::virt2".into());
        let reconstructor = ClassReconstructor::new(names, 0);
        let c = VtableCandidate::new(0x3000, vec![0x1100, 0x1200]);
        let cls = reconstructor.reconstruct(&c);
        assert_eq!(cls.virtual_methods[0].name.as_deref(), Some("Base::virt1"));
        assert_eq!(cls.virtual_methods[1].name.as_deref(), Some("Base::virt2"));
    }

    // 34. VtableInheritance no self-parent.
    #[test]
    fn test_no_self_parent() {
        let single = VtableCandidate::new(0x2000, vec![0x1100, 0x1200]);
        let inh = VtableInheritance::infer(&[single]);
        assert!(!inh.parent.contains_key(&0x2000));
    }

    // 35. VtableRecovery no exec_ranges → 0 validated.
    #[test]
    fn test_recovery_no_exec() {
        let base = 0x3000u64;
        let data = make_vtable_data(&[0x1100, 0x1200]);
        let r = VtableRecovery::default_config();
        let (_, _, summary) = r.recover(base, &data, vec![], HashSet::new());
        assert_eq!(summary.validated, 0);
    }

    // 36. VtableScanner candidate addr matches start.
    #[test]
    fn test_scanner_candidate_addr() {
        let base = 0x8000u64;
        let data = make_vtable_data(&[0x1500, 0x1600]);
        let scanner = VtableScanner::new(vec![(0x1000, 0x2000)]);
        let candidates = scanner.scan(base, &data);
        assert_eq!(candidates[0].addr, base);
    }
}
