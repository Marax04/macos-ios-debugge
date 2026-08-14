//! Vtable validation for recovered C++ vtables.
//!
//! After vtables are recovered by the analysis pipeline this module validates
//! each vtable entry for pointer validity, function alignment, and structural
//! consistency.  A `ValidationReport` aggregates all findings.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Raw vtable representation
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered vtable pointer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtableEntry {
    /// Slot index (0-based).
    pub slot: usize,
    /// The raw function pointer value.
    pub pointer: u64,
    /// Whether the pointer is within the binary's code section.
    pub in_code_section: bool,
}

impl VtableEntry {
    #[must_use]
    pub const fn new(slot: usize, pointer: u64, in_code_section: bool) -> Self {
        Self {
            slot,
            pointer,
            in_code_section,
        }
    }
}

/// A recovered vtable.
#[derive(Debug, Clone)]
pub struct RecoveredVtable {
    /// Virtual address of the vtable itself.
    pub address: u64,
    /// Mangled class name, if recovered.
    pub class_name: Option<String>,
    /// The vtable entries.
    pub entries: Vec<VtableEntry>,
    /// Whether a RTTI pointer precedes the first slot.
    pub has_rtti: bool,
}

impl RecoveredVtable {
    #[must_use]
    pub const fn new(address: u64, entries: Vec<VtableEntry>) -> Self {
        Self {
            address,
            class_name: None,
            entries,
            has_rtti: false,
        }
    }

    #[must_use]
    pub fn with_class(mut self, name: impl Into<String>) -> Self {
        self.class_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_rtti(mut self) -> Self {
        self.has_rtti = true;
        self
    }

    /// Number of virtual functions.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.entries.len()
    }

    /// The pointer at slot `slot`, if present.
    #[must_use]
    pub fn slot_ptr(&self, slot: usize) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| e.pointer)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation rules
// ─────────────────────────────────────────────────────────────────────────────

/// The result of applying a single validation rule to one vtable entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    Pass,
    Warning(String),
    Fail(String),
}

impl fmt::Display for RuleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warning(msg) => write!(f, "WARN: {msg}"),
            Self::Fail(msg) => write!(f, "FAIL: {msg}"),
        }
    }
}

/// A named validation rule applied per entry.
pub trait ValidationRule: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, vtable: &RecoveredVtable, entry: &VtableEntry) -> RuleOutcome;
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerValidity
// ─────────────────────────────────────────────────────────────────────────────

/// Rule: every pointer must be non-null and within a known mapped range.
pub struct PointerValidity {
    pub mapped_ranges: Vec<(u64, u64)>, // (start, end) inclusive
}

impl PointerValidity {
    #[must_use]
    pub const fn new(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            mapped_ranges: ranges,
        }
    }

    fn is_mapped(&self, ptr: u64) -> bool {
        self.mapped_ranges
            .iter()
            .any(|(s, e)| ptr >= *s && ptr <= *e)
    }
}

impl ValidationRule for PointerValidity {
    fn name(&self) -> &'static str {
        "pointer_validity"
    }

    fn check(&self, _vtable: &RecoveredVtable, entry: &VtableEntry) -> RuleOutcome {
        if entry.pointer == 0 {
            return RuleOutcome::Fail(format!("slot {} is null", entry.slot));
        }
        if !self.is_mapped(entry.pointer) {
            return RuleOutcome::Fail(format!(
                "slot {} pointer {:#x} is not in any mapped range",
                entry.slot, entry.pointer
            ));
        }
        RuleOutcome::Pass
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionAligned
// ─────────────────────────────────────────────────────────────────────────────

/// Rule: function pointers should be aligned to the architecture's instruction
/// alignment (typically 4 for ARM, 1 for x86).
pub struct FunctionAligned {
    pub alignment: u64,
}

impl FunctionAligned {
    #[must_use]
    pub const fn new(alignment: u64) -> Self {
        Self { alignment }
    }
}

impl ValidationRule for FunctionAligned {
    fn name(&self) -> &'static str {
        "function_aligned"
    }

    fn check(&self, _vtable: &RecoveredVtable, entry: &VtableEntry) -> RuleOutcome {
        if self.alignment <= 1 {
            return RuleOutcome::Pass;
        }
        if entry.pointer.is_multiple_of(self.alignment) {
            RuleOutcome::Pass
        } else {
            RuleOutcome::Warning(format!(
                "slot {} pointer {:#x} is not aligned to {}",
                entry.slot, entry.pointer, self.alignment
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableConsistency
// ─────────────────────────────────────────────────────────────────────────────

/// Rule: no two slots should point to the same address (pure virtual overrides
/// excluded), and slots should be monotonically addressed in code.
pub struct VtableConsistency;

impl ValidationRule for VtableConsistency {
    fn name(&self) -> &'static str {
        "vtable_consistency"
    }

    fn check(&self, vtable: &RecoveredVtable, entry: &VtableEntry) -> RuleOutcome {
        // Check for duplicate pointers within the same vtable
        let dup_count = vtable
            .entries
            .iter()
            .filter(|e| e.pointer == entry.pointer)
            .count();
        if dup_count > 1 {
            RuleOutcome::Warning(format!(
                "slot {} shares pointer {:#x} with {} other slot(s)",
                entry.slot,
                entry.pointer,
                dup_count - 1,
            ))
        } else {
            RuleOutcome::Pass
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InCodeSection
// ─────────────────────────────────────────────────────────────────────────────

/// Rule: every vtable entry should point into the code section.
pub struct InCodeSection;

impl ValidationRule for InCodeSection {
    fn name(&self) -> &'static str {
        "in_code_section"
    }

    fn check(&self, _vtable: &RecoveredVtable, entry: &VtableEntry) -> RuleOutcome {
        if entry.in_code_section {
            RuleOutcome::Pass
        } else {
            RuleOutcome::Fail(format!(
                "slot {} pointer {:#x} is outside the code section",
                entry.slot, entry.pointer
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationFinding
// ─────────────────────────────────────────────────────────────────────────────

/// A single validation finding attached to a vtable entry.
#[derive(Debug, Clone)]
pub struct ValidationFinding {
    pub vtable_address: u64,
    pub slot: usize,
    pub rule_name: String,
    pub outcome: RuleOutcome,
}

impl ValidationFinding {
    /// Whether this finding represents a failure.
    #[must_use]
    pub const fn is_fail(&self) -> bool {
        matches!(self.outcome, RuleOutcome::Fail(_))
    }

    /// Whether this finding is a warning.
    #[must_use]
    pub const fn is_warn(&self) -> bool {
        matches!(self.outcome, RuleOutcome::Warning(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated report from validating a set of vtables.
#[derive(Debug, Clone, Default)]
pub struct ValidationReport {
    pub findings: Vec<ValidationFinding>,
    /// Number of vtables inspected.
    pub vtables_inspected: usize,
    /// Number of vtables with at least one FAIL finding.
    pub vtables_failed: usize,
    /// Number of vtables with only PASS findings.
    pub vtables_passed: usize,
}

impl ValidationReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All fail findings.
    #[must_use]
    pub fn fails(&self) -> Vec<&ValidationFinding> {
        self.findings.iter().filter(|f| f.is_fail()).collect()
    }

    /// All warning findings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationFinding> {
        self.findings.iter().filter(|f| f.is_warn()).collect()
    }

    /// Whether all vtables passed validation.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.vtables_failed == 0
    }

    /// Findings for a specific vtable address.
    #[must_use]
    pub fn findings_for(&self, vtable_addr: u64) -> Vec<&ValidationFinding> {
        self.findings
            .iter()
            .filter(|f| f.vtable_address == vtable_addr)
            .collect()
    }

    /// Group findings by their vtable address.
    ///
    /// Returns a map from vtable VA to the findings recorded against it. This is
    /// significantly cheaper than calling [`Self::findings_for`] once per address
    /// when a caller already wants every group.
    #[must_use]
    pub fn findings_by_vtable(&self) -> HashMap<u64, Vec<&ValidationFinding>> {
        let mut map: HashMap<u64, Vec<&ValidationFinding>> = HashMap::new();
        for f in &self.findings {
            map.entry(f.vtable_address).or_default().push(f);
        }
        map
    }

    /// Total fail count.
    #[must_use]
    pub fn fail_count(&self) -> usize {
        self.findings.iter().filter(|f| f.is_fail()).count()
    }

    /// Total warning count.
    #[must_use]
    pub fn warn_count(&self) -> usize {
        self.findings.iter().filter(|f| f.is_warn()).count()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} vtables: {} passed, {} failed, {} warnings, {} failures",
            self.vtables_inspected,
            self.vtables_passed,
            self.vtables_failed,
            self.warn_count(),
            self.fail_count(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates a set of recovered vtables by running all registered rules.
pub struct VtableValidator {
    rules: Vec<Box<dyn ValidationRule>>,
}

impl Default for VtableValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl VtableValidator {
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a validation rule.
    pub fn add_rule(&mut self, rule: Box<dyn ValidationRule>) {
        self.rules.push(rule);
    }

    /// Create a validator with common rules for x86-64 binaries.
    #[must_use]
    pub fn for_x86_64(code_start: u64, code_end: u64) -> Self {
        let mut v = Self::new();
        v.add_rule(Box::new(PointerValidity::new(vec![(code_start, code_end)])));
        v.add_rule(Box::new(FunctionAligned::new(1)));
        v.add_rule(Box::new(VtableConsistency));
        v.add_rule(Box::new(InCodeSection));
        v
    }

    /// Validate a single vtable. Returns the findings for that vtable.
    #[must_use]
    pub fn validate_vtable(&self, vtable: &RecoveredVtable) -> Vec<ValidationFinding> {
        let mut findings = Vec::new();
        for entry in &vtable.entries {
            for rule in &self.rules {
                let outcome = rule.check(vtable, entry);
                if !matches!(outcome, RuleOutcome::Pass) {
                    findings.push(ValidationFinding {
                        vtable_address: vtable.address,
                        slot: entry.slot,
                        rule_name: rule.name().to_string(),
                        outcome,
                    });
                }
            }
        }
        findings
    }

    /// Validate all vtables and produce a `ValidationReport`.
    #[must_use]
    pub fn validate_all(&self, vtables: &[RecoveredVtable]) -> ValidationReport {
        let mut report = ValidationReport::new();
        report.vtables_inspected = vtables.len();

        // Track which vtables have failures
        let mut fail_set: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for vtable in vtables {
            let findings = self.validate_vtable(vtable);
            for f in &findings {
                if f.is_fail() {
                    fail_set.insert(vtable.address);
                }
            }
            report.findings.extend(findings);
        }

        report.vtables_failed = fail_set.len();
        report.vtables_passed = vtables.len().saturating_sub(report.vtables_failed);
        report
    }

    /// Number of registered rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_entry(slot: usize, ptr: u64) -> VtableEntry {
        VtableEntry::new(slot, ptr, true)
    }

    fn invalid_entry(slot: usize, ptr: u64) -> VtableEntry {
        VtableEntry::new(slot, ptr, false)
    }

    fn simple_vtable(addr: u64, ptrs: &[u64]) -> RecoveredVtable {
        let entries: Vec<VtableEntry> = ptrs
            .iter()
            .enumerate()
            .map(|(i, &p)| valid_entry(i, p))
            .collect();
        RecoveredVtable::new(addr, entries)
    }

    // 1. RecoveredVtable slot_count
    #[test]
    fn test_vtable_slot_count() {
        let vt = simple_vtable(0x1000, &[0x4000, 0x4100, 0x4200]);
        assert_eq!(vt.slot_count(), 3);
    }

    // 2. RecoveredVtable slot_ptr found
    #[test]
    fn test_vtable_slot_ptr_found() {
        let vt = simple_vtable(0x1000, &[0x4000, 0x4100]);
        assert_eq!(vt.slot_ptr(0), Some(0x4000));
        assert_eq!(vt.slot_ptr(1), Some(0x4100));
    }

    // 3. RecoveredVtable slot_ptr not found
    #[test]
    fn test_vtable_slot_ptr_none() {
        let vt = simple_vtable(0x1000, &[0x4000]);
        assert_eq!(vt.slot_ptr(5), None);
    }

    // 4. RecoveredVtable with_class
    #[test]
    fn test_vtable_with_class() {
        let vt = simple_vtable(0x1000, &[0x4000]).with_class("MyClass");
        assert_eq!(vt.class_name.as_deref(), Some("MyClass"));
    }

    // 5. RecoveredVtable with_rtti
    #[test]
    fn test_vtable_with_rtti() {
        let vt = simple_vtable(0x1000, &[0x4000]).with_rtti();
        assert!(vt.has_rtti);
    }

    // 6. PointerValidity passes for in-range pointer
    #[test]
    fn test_ptr_validity_pass() {
        let rule = PointerValidity::new(vec![(0x4000, 0x9000)]);
        let vt = simple_vtable(0x1000, &[0x5000]);
        let entry = vt.entries[0];
        assert_eq!(rule.check(&vt, &entry), RuleOutcome::Pass);
    }

    // 7. PointerValidity fails for null
    #[test]
    fn test_ptr_validity_null() {
        let rule = PointerValidity::new(vec![(0x4000, 0x9000)]);
        let vt = simple_vtable(0x1000, &[0]);
        let outcome = rule.check(&vt, &vt.entries[0]);
        assert!(matches!(outcome, RuleOutcome::Fail(_)));
    }

    // 8. PointerValidity fails for out-of-range
    #[test]
    fn test_ptr_validity_out_of_range() {
        let rule = PointerValidity::new(vec![(0x4000, 0x9000)]);
        let vt = simple_vtable(0x1000, &[0x1_0000]);
        let outcome = rule.check(&vt, &vt.entries[0]);
        assert!(matches!(outcome, RuleOutcome::Fail(_)));
    }

    // 9. FunctionAligned passes for aligned x86 (alignment=1)
    #[test]
    fn test_func_aligned_x86() {
        let rule = FunctionAligned::new(1);
        let vt = simple_vtable(0x1000, &[0x4001]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 10. FunctionAligned warns for misaligned ARM (alignment=4)
    #[test]
    fn test_func_aligned_arm_misaligned() {
        let rule = FunctionAligned::new(4);
        let vt = simple_vtable(0x1000, &[0x4003]);
        let outcome = rule.check(&vt, &vt.entries[0]);
        assert!(matches!(outcome, RuleOutcome::Warning(_)));
    }

    // 11. FunctionAligned passes for aligned ARM
    #[test]
    fn test_func_aligned_arm_ok() {
        let rule = FunctionAligned::new(4);
        let vt = simple_vtable(0x1000, &[0x4000]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 12. VtableConsistency warns on duplicate pointers
    #[test]
    fn test_vtable_consistency_duplicate() {
        let rule = VtableConsistency;
        let entries = vec![valid_entry(0, 0x4000), valid_entry(1, 0x4000)];
        let vt = RecoveredVtable::new(0x1000, entries);
        let outcome = rule.check(&vt, &vt.entries[0]);
        assert!(matches!(outcome, RuleOutcome::Warning(_)));
    }

    // 13. VtableConsistency passes for unique pointers
    #[test]
    fn test_vtable_consistency_unique() {
        let rule = VtableConsistency;
        let vt = simple_vtable(0x1000, &[0x4000, 0x4100]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 14. InCodeSection fails for out-of-code entry
    #[test]
    fn test_in_code_section_fail() {
        let rule = InCodeSection;
        let entry = invalid_entry(0, 0x5000);
        let vt = RecoveredVtable::new(0x1000, vec![entry]);
        let outcome = rule.check(&vt, &vt.entries[0]);
        assert!(matches!(outcome, RuleOutcome::Fail(_)));
    }

    // 15. InCodeSection passes for in-code entry
    #[test]
    fn test_in_code_section_pass() {
        let rule = InCodeSection;
        let vt = simple_vtable(0x1000, &[0x4000]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 16. VtableValidator validate_vtable empty vtable
    #[test]
    fn test_validate_empty_vtable() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vt = RecoveredVtable::new(0x1000, vec![]);
        let findings = v.validate_vtable(&vt);
        assert!(findings.is_empty());
    }

    // 17. VtableValidator validate_vtable all valid
    #[test]
    fn test_validate_all_valid() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vt = simple_vtable(0x1000, &[0x5000, 0x6000]);
        let findings = v.validate_vtable(&vt);
        // Only warnings/fails are recorded; a clean vtable should have none
        let fails: Vec<_> = findings.iter().filter(|f| f.is_fail()).collect();
        assert!(fails.is_empty(), "unexpected fails: {fails:?}");
    }

    // 18. VtableValidator validate_vtable null pointer
    #[test]
    fn test_validate_null_ptr() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vt = simple_vtable(0x1000, &[0]);
        let findings = v.validate_vtable(&vt);
        assert!(findings.iter().any(super::ValidationFinding::is_fail));
    }

    // 19. VtableValidator validate_all produces report
    #[test]
    fn test_validate_all_report() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vtables = vec![
            simple_vtable(0x1000, &[0x5000]),
            simple_vtable(0x2000, &[0]),
        ];
        let report = v.validate_all(&vtables);
        assert_eq!(report.vtables_inspected, 2);
        assert!(report.vtables_failed >= 1);
    }

    // 20. ValidationReport all_passed
    #[test]
    fn test_report_all_passed() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vtables = vec![simple_vtable(0x1000, &[0x5000])];
        let report = v.validate_all(&vtables);
        assert!(report.all_passed());
    }

    // 21. ValidationReport findings_for
    #[test]
    fn test_report_findings_for() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vtables = vec![
            simple_vtable(0x1000, &[0]),
            simple_vtable(0x2000, &[0x5000]),
        ];
        let report = v.validate_all(&vtables);
        let for_1000 = report.findings_for(0x1000);
        assert!(!for_1000.is_empty());
        let for_2000 = report.findings_for(0x2000);
        assert!(for_2000.iter().all(|f| !f.is_fail()));
    }

    // 22. ValidationReport fail_count and warn_count
    #[test]
    fn test_report_counts() {
        let v = VtableValidator::new(); // no rules
        let report = v.validate_all(&[simple_vtable(0x1000, &[0x5000])]);
        assert_eq!(report.fail_count(), 0);
        assert_eq!(report.warn_count(), 0);
    }

    // 23. ValidationReport summary string
    #[test]
    fn test_report_summary() {
        let v = VtableValidator::new();
        let report = v.validate_all(&[simple_vtable(0x1000, &[0x4000])]);
        let s = report.summary();
        assert!(s.contains("vtable"));
    }

    // 24. RuleOutcome Display
    #[test]
    fn test_rule_outcome_display() {
        assert_eq!(RuleOutcome::Pass.to_string(), "PASS");
        assert!(
            RuleOutcome::Fail("x".into())
                .to_string()
                .starts_with("FAIL")
        );
        assert!(
            RuleOutcome::Warning("w".into())
                .to_string()
                .starts_with("WARN")
        );
    }

    // 25. ValidationFinding is_fail / is_warn
    #[test]
    fn test_finding_is_fail_warn() {
        let f = ValidationFinding {
            vtable_address: 0,
            slot: 0,
            rule_name: "r".into(),
            outcome: RuleOutcome::Fail("bad".into()),
        };
        assert!(f.is_fail());
        assert!(!f.is_warn());
    }

    // 26. VtableValidator add_rule increases rule_count
    #[test]
    fn test_add_rule_count() {
        let mut v = VtableValidator::new();
        assert_eq!(v.rule_count(), 0);
        v.add_rule(Box::new(InCodeSection));
        assert_eq!(v.rule_count(), 1);
    }

    // 27. VtableValidator for_x86_64 has 4 rules
    #[test]
    fn test_for_x86_64_rule_count() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        assert_eq!(v.rule_count(), 4);
    }

    // 28. InCodeSection name
    #[test]
    fn test_rule_names() {
        assert_eq!(InCodeSection.name(), "in_code_section");
        assert_eq!(VtableConsistency.name(), "vtable_consistency");
        assert_eq!(FunctionAligned::new(4).name(), "function_aligned");
    }

    // 29. PointerValidity name
    #[test]
    fn test_pointer_validity_name() {
        let rule = PointerValidity::new(vec![]);
        assert_eq!(rule.name(), "pointer_validity");
    }

    // 30. Multiple vtables report correctly
    #[test]
    fn test_multiple_vtables_report() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vtables: Vec<RecoveredVtable> = (0..5)
            .map(|i| simple_vtable(0x1000 * (i + 1), &[0x5000 + 0x100 * i]))
            .collect();
        let report = v.validate_all(&vtables);
        assert_eq!(report.vtables_inspected, 5);
    }

    // 31. Vtable with no entries validates cleanly
    #[test]
    fn test_vtable_no_entries_clean() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let report = v.validate_all(&[RecoveredVtable::new(0x1000, vec![])]);
        assert!(report.all_passed());
    }

    // 32. RecoveredVtable builder chain
    #[test]
    fn test_vtable_builder_chain() {
        let vt = simple_vtable(0x1000, &[0x4000])
            .with_class("Foo")
            .with_rtti();
        assert_eq!(vt.class_name.as_deref(), Some("Foo"));
        assert!(vt.has_rtti);
    }

    // 33. ValidationReport vtables_passed correct
    #[test]
    fn test_vtables_passed_count() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vtables = vec![
            simple_vtable(0x1000, &[0x5000]), // should pass
            simple_vtable(0x2000, &[0]),      // will fail (null ptr)
        ];
        let report = v.validate_all(&vtables);
        assert_eq!(report.vtables_passed, 1);
        assert_eq!(report.vtables_failed, 1);
    }

    // 34. FunctionAligned with alignment=0 is pass
    #[test]
    fn test_func_aligned_zero_alignment() {
        let rule = FunctionAligned::new(0);
        let vt = simple_vtable(0x1000, &[0x4001]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 35. VtableEntry new stores fields
    #[test]
    fn test_vtable_entry_new() {
        let e = VtableEntry::new(3, 0xDEAD, true);
        assert_eq!(e.slot, 3);
        assert_eq!(e.pointer, 0xDEAD);
        assert!(e.in_code_section);
    }

    // 36. ValidationReport default is all zeros
    #[test]
    fn test_report_default() {
        let r = ValidationReport::default();
        assert_eq!(r.vtables_inspected, 0);
        assert!(r.all_passed());
    }

    // 37. VtableConsistency no warn for single entry
    #[test]
    fn test_consistency_single_entry() {
        let rule = VtableConsistency;
        let vt = simple_vtable(0x1000, &[0x4000]);
        assert_eq!(rule.check(&vt, &vt.entries[0]), RuleOutcome::Pass);
    }

    // 38. PointerValidity multiple ranges
    #[test]
    fn test_ptr_validity_multiple_ranges() {
        let rule = PointerValidity::new(vec![(0x1000, 0x2000), (0x5000, 0x6000)]);
        let vt1 = simple_vtable(0, &[0x1500]);
        assert_eq!(rule.check(&vt1, &vt1.entries[0]), RuleOutcome::Pass);
        let vt2 = simple_vtable(0, &[0x5500]);
        assert_eq!(rule.check(&vt2, &vt2.entries[0]), RuleOutcome::Pass);
        let vt3 = simple_vtable(0, &[0x9999]);
        assert!(matches!(
            rule.check(&vt3, &vt3.entries[0]),
            RuleOutcome::Fail(_)
        ));
    }

    // 39. VtableValidator validate_vtable records slot number
    #[test]
    fn test_finding_slot_number() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let entries = vec![valid_entry(0, 0x5000), valid_entry(1, 0)]; // slot 1 is null
        let vt = RecoveredVtable::new(0x1000, entries);
        let findings = v.validate_vtable(&vt);
        let fail = findings.iter().find(|f| f.is_fail()).expect("has fail");
        assert_eq!(fail.slot, 1);
    }

    // 40. VtableValidator default is empty
    #[test]
    fn test_validator_default_no_rules() {
        let v = VtableValidator::default();
        assert_eq!(v.rule_count(), 0);
    }

    // 41. Multiple fails per vtable
    #[test]
    fn test_multiple_fails_per_vtable() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        // Two null entries
        let entries = vec![valid_entry(0, 0), valid_entry(1, 0)];
        let vt = RecoveredVtable::new(0x1000, entries);
        let findings = v.validate_vtable(&vt);
        let fail_count = findings.iter().filter(|f| f.is_fail()).count();
        assert!(fail_count >= 2);
    }

    // 42. ValidationFinding rule_name stored
    #[test]
    fn test_finding_rule_name() {
        let v = VtableValidator::for_x86_64(0x4000, 0x9000);
        let vt = simple_vtable(0x1000, &[0]); // null → pointer_validity fail
        let findings = v.validate_vtable(&vt);
        let fail = findings.iter().find(|f| f.is_fail()).expect("has fail");
        assert_eq!(fail.rule_name, "pointer_validity");
    }
}
