//! Vtable integrity checking for `rustre-analysis-vtable`.
//!
//! Validates that every slot in a recovered vtable points to valid executable
//! code, detects patterns that indicate vtable corruption (a common exploit
//! primitive), verifies thunk chains, and performs simplified CFI
//! (control-flow integrity) analysis.
//!
//! ## Integrity checks performed
//!
//! 1. **Null slot** — a vtable entry is zero.
//! 2. **Non-executable target** — the target address falls in a data section,
//!    not a code section.
//! 3. **Out-of-bounds target** — the target address is outside all known
//!    sections.
//! 4. **Duplicate slot** — two different virtual methods resolve to the same
//!    address (unusual but legal for pure virtual stubs).
//! 5. **Thunk chain validation** — if a slot points to a thunk, the thunk
//!    target must also be in a code section.
//! 6. **Pointer overwrite detection** — the vtable pointer stored in an object
//!    header (`*obj`) points to a different vtable than expected (heap spray /
//!    vtable overwrite indicator).
//! 7. **CFI set check** — each vtable slot must belong to the declared CFI
//!    valid-target set for the call site.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Section descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal description of a binary section or segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDesc {
    /// Start virtual address.
    pub start: u64,
    /// Exclusive end virtual address.
    pub end: u64,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
    /// Section name (e.g. `.text`, `.rdata`).
    pub name: String,
}

impl SectionDesc {
    /// Return `true` if `addr` falls inside this section.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integrity issue kinds
// ─────────────────────────────────────────────────────────────────────────────

/// A specific integrity violation found in a vtable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityIssueKind {
    /// The vtable slot contains a null pointer.
    NullSlot,
    /// The slot target is in a non-executable section.
    NonExecutableTarget {
        /// Section name where the target resides.
        section: String,
    },
    /// The slot target is outside all known sections.
    OutOfBoundsTarget,
    /// Two slots point to the same address (may indicate a pure-virtual stub).
    DuplicateSlot {
        /// The other slot index that has the same target.
        other_slot: usize,
    },
    /// A thunk chain contains a hop to a non-executable address.
    InvalidThunkTarget { hop: usize, target: u64 },
    /// The vtable pointer in an object header was overwritten.
    VtablePointerCorrupted {
        /// Expected vtable address.
        expected_vtable: u64,
        /// Observed vtable address.
        observed_vtable: u64,
    },
    /// A slot target is not in the CFI valid-target set for this call site.
    CfiViolation {
        /// The set identifier.
        set_id: u32,
    },
}

/// One integrity issue found at a vtable slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityIssue {
    /// Virtual address of the vtable.
    pub vtable_va: u64,
    /// Slot index (0-based) where the issue was found.
    pub slot_index: usize,
    /// Target address stored in the slot.
    pub slot_target: u64,
    /// What kind of issue was detected.
    pub kind: IntegrityIssueKind,
    /// Severity: `true` = exploit-relevant.
    pub is_security_relevant: bool,
}

impl IntegrityIssue {
    /// Short label describing this issue.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match &self.kind {
            IntegrityIssueKind::NullSlot => "NULL_SLOT",
            IntegrityIssueKind::NonExecutableTarget { .. } => "NON_EXEC_TARGET",
            IntegrityIssueKind::OutOfBoundsTarget => "OOB_TARGET",
            IntegrityIssueKind::DuplicateSlot { .. } => "DUPLICATE_SLOT",
            IntegrityIssueKind::InvalidThunkTarget { .. } => "INVALID_THUNK",
            IntegrityIssueKind::VtablePointerCorrupted { .. } => "VTABLE_OVERWRITE",
            IntegrityIssueKind::CfiViolation { .. } => "CFI_VIOLATION",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vtable integrity checker
// ─────────────────────────────────────────────────────────────────────────────

/// Validates vtable integrity given a set of section descriptors.
pub struct VtableIntegrityChecker {
    /// Known sections of the binary.
    pub sections: Vec<SectionDesc>,
    /// CFI valid-target sets: `set_id` → set of valid target addresses.
    pub cfi_sets: HashMap<u32, HashSet<u64>>,
}

impl VtableIntegrityChecker {
    /// Create a checker with the given sections and no CFI sets.
    #[must_use]
    pub fn new(sections: Vec<SectionDesc>) -> Self {
        Self {
            sections,
            cfi_sets: HashMap::new(),
        }
    }

    /// Add a CFI valid-target set.
    pub fn add_cfi_set(&mut self, set_id: u32, targets: impl IntoIterator<Item = u64>) {
        self.cfi_sets
            .entry(set_id)
            .or_default()
            .extend(targets);
    }

    /// Check all slots of a vtable.
    ///
    /// `vtable_va` — virtual address of the vtable.
    /// `slots` — list of target addresses, in slot order.
    /// `cfi_set_id` — if `Some`, check each target against the CFI set.
    #[must_use]
    pub fn check_vtable(
        &self,
        vtable_va: u64,
        slots: &[u64],
        cfi_set_id: Option<u32>,
    ) -> Vec<IntegrityIssue> {
        let mut issues = Vec::new();
        let mut seen_targets: HashMap<u64, usize> = HashMap::new();

        for (idx, &target) in slots.iter().enumerate() {
            // Null check.
            if target == 0 {
                issues.push(IntegrityIssue {
                    vtable_va,
                    slot_index: idx,
                    slot_target: 0,
                    kind: IntegrityIssueKind::NullSlot,
                    is_security_relevant: true,
                });
                continue;
            }

            // Section membership check.
            match self.classify_address(target) {
                AddressClass::Executable => {}
                AddressClass::NonExecutable(section) => {
                    issues.push(IntegrityIssue {
                        vtable_va,
                        slot_index: idx,
                        slot_target: target,
                        kind: IntegrityIssueKind::NonExecutableTarget { section },
                        is_security_relevant: true,
                    });
                }
                AddressClass::OutOfBounds => {
                    issues.push(IntegrityIssue {
                        vtable_va,
                        slot_index: idx,
                        slot_target: target,
                        kind: IntegrityIssueKind::OutOfBoundsTarget,
                        is_security_relevant: true,
                    });
                }
            }

            // Duplicate detection.
            if let Some(prev_idx) = seen_targets.insert(target, idx) {
                issues.push(IntegrityIssue {
                    vtable_va,
                    slot_index: idx,
                    slot_target: target,
                    kind: IntegrityIssueKind::DuplicateSlot { other_slot: prev_idx },
                    is_security_relevant: false,
                });
            }

            // CFI check.
            if let Some(set_id) = cfi_set_id
                && let Some(valid_set) = self.cfi_sets.get(&set_id)
                && !valid_set.contains(&target)
            {
                issues.push(IntegrityIssue {
                    vtable_va,
                    slot_index: idx,
                    slot_target: target,
                    kind: IntegrityIssueKind::CfiViolation { set_id },
                    is_security_relevant: true,
                });
            }
        }

        issues
    }

    /// Verify a thunk chain starting at `thunk_addr`.
    ///
    /// Reads up to `max_hops` JMP instructions from `code`, following the
    /// chain and checking that each hop lands in an executable section.
    #[must_use]
    pub fn verify_thunk_chain(
        &self,
        vtable_va: u64,
        slot_index: usize,
        thunk_start: u64,
        code: &[u8],
        code_base: u64,
        max_hops: usize,
    ) -> Vec<IntegrityIssue> {
        let mut issues = Vec::new();
        let mut current = thunk_start;

        for hop in 0..max_hops {
            let offset = match current.checked_sub(code_base).and_then(|off| usize::try_from(off).ok()) {
                Some(off) if off < code.len() => off,
                _ => break,
            };

            let b = code[offset];

            // JMP rel32 (E9)
            if b == 0xE9 && offset.checked_add(5).map_or(false, |end| end <= code.len()) {
                let disp = i32::from_le_bytes([
                    code[offset + 1],
                    code[offset + 2],
                    code[offset + 3],
                    code[offset + 4],
                ]);
                let next_pc = code_base.wrapping_add(offset as u64 + 5);
                let target = next_pc.wrapping_add_signed(i64::from(disp));

                if matches!(self.classify_address(target), AddressClass::Executable) {
                    current = target;
                } else {
                    issues.push(IntegrityIssue {
                        vtable_va,
                        slot_index,
                        slot_target: thunk_start,
                        kind: IntegrityIssueKind::InvalidThunkTarget { hop, target },
                        is_security_relevant: true,
                    });
                    break;
                }
                continue;
            }

            // Not a JMP — end of chain.
            break;
        }

        issues
    }

    /// Classify `addr` as executable, non-executable, or out-of-bounds.
    fn classify_address(&self, addr: u64) -> AddressClass {
        for sec in &self.sections {
            if sec.contains(addr) {
                return if sec.executable {
                    AddressClass::Executable
                } else {
                    AddressClass::NonExecutable(sec.name.clone())
                };
            }
        }
        AddressClass::OutOfBounds
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Address classification (internal)
// ─────────────────────────────────────────────────────────────────────────────

enum AddressClass {
    Executable,
    NonExecutable(String),
    OutOfBounds,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vtable pointer overwrite detection
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of an object's vtable pointer at a point during execution
/// (or from memory dump analysis).
#[derive(Debug, Clone)]
pub struct ObjectSnapshot {
    /// Address of the object on the heap.
    pub object_addr: u64,
    /// The vtable pointer currently stored at `*object_addr`.
    pub observed_vtable_ptr: u64,
    /// The vtable pointer expected for this class.
    pub expected_vtable_ptr: u64,
}

impl ObjectSnapshot {
    /// Return `true` if the vtable pointer has been overwritten.
    #[must_use]
    pub const fn is_corrupted(&self) -> bool {
        self.observed_vtable_ptr != self.expected_vtable_ptr
    }

    /// Generate an integrity issue if the vtable pointer is corrupted.
    #[must_use]
    pub const fn check(&self) -> Option<IntegrityIssue> {
        if !self.is_corrupted() {
            return None;
        }
        Some(IntegrityIssue {
            vtable_va: self.expected_vtable_ptr,
            slot_index: 0,
            slot_target: self.observed_vtable_ptr,
            kind: IntegrityIssueKind::VtablePointerCorrupted {
                expected_vtable: self.expected_vtable_ptr,
                observed_vtable: self.observed_vtable_ptr,
            },
            is_security_relevant: true,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch integrity report
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate integrity report across all vtables.
#[derive(Debug, Default)]
pub struct IntegrityReport {
    /// All issues found across all vtables.
    pub issues: Vec<IntegrityIssue>,
    /// Number of vtables checked.
    pub vtables_checked: usize,
    /// Number of slots checked.
    pub slots_checked: usize,
}

impl IntegrityReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add all issues from checking one vtable.
    pub fn add_vtable(&mut self, slot_count: usize, mut new_issues: Vec<IntegrityIssue>) {
        self.vtables_checked += 1;
        self.slots_checked += slot_count;
        self.issues.append(&mut new_issues);
    }

    /// Return only security-relevant issues.
    #[must_use]
    pub fn security_issues(&self) -> Vec<&IntegrityIssue> {
        self.issues.iter().filter(|i| i.is_security_relevant).collect()
    }

    /// Total number of issues.
    #[must_use]
    pub const fn issue_count(&self) -> usize {
        self.issues.len()
    }

    /// Whether any security-relevant issue was found.
    #[must_use]
    pub fn has_security_issues(&self) -> bool {
        self.issues.iter().any(|i| i.is_security_relevant)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn text_section() -> SectionDesc {
        SectionDesc {
            start: 0x1000,
            end: 0x5000,
            executable: true,
            writable: false,
            name: ".text".into(),
        }
    }

    fn data_section() -> SectionDesc {
        SectionDesc {
            start: 0x6000,
            end: 0x8000,
            executable: false,
            writable: true,
            name: ".data".into(),
        }
    }

    fn checker() -> VtableIntegrityChecker {
        VtableIntegrityChecker::new(vec![text_section(), data_section()])
    }

    #[test]
    fn null_slot_detected() {
        let c = checker();
        let issues = c.check_vtable(0xA000, &[0x1000, 0, 0x2000], None);
        assert!(issues.iter().any(|i| i.kind == IntegrityIssueKind::NullSlot));
        assert!(issues.iter().find(|i| i.kind == IntegrityIssueKind::NullSlot).unwrap().is_security_relevant);
    }

    #[test]
    fn non_exec_target_detected() {
        let c = checker();
        let issues = c.check_vtable(0xA000, &[0x6500], None); // .data section
        assert!(issues.iter().any(|i| matches!(i.kind, IntegrityIssueKind::NonExecutableTarget { .. })));
    }

    #[test]
    fn oob_target_detected() {
        let c = checker();
        let issues = c.check_vtable(0xA000, &[0xFFFF_FFFF], None);
        assert!(issues.iter().any(|i| i.kind == IntegrityIssueKind::OutOfBoundsTarget));
    }

    #[test]
    fn duplicate_slot_detected() {
        let c = checker();
        let issues = c.check_vtable(0xA000, &[0x1000, 0x2000, 0x1000], None);
        assert!(issues.iter().any(|i| matches!(i.kind, IntegrityIssueKind::DuplicateSlot { .. })));
    }

    #[test]
    fn valid_slots_no_issues() {
        let c = checker();
        let issues = c.check_vtable(0xA000, &[0x1000, 0x2000, 0x3000], None);
        let security: Vec<_> = issues.iter().filter(|i| i.is_security_relevant).collect();
        assert!(security.is_empty(), "unexpected security issues: {security:?}");
    }

    #[test]
    fn cfi_violation_detected() {
        let mut c = checker();
        c.add_cfi_set(1, [0x1000, 0x2000]);
        let issues = c.check_vtable(0xA000, &[0x3000], Some(1)); // 0x3000 not in set
        assert!(issues.iter().any(|i| matches!(i.kind, IntegrityIssueKind::CfiViolation { .. })));
    }

    #[test]
    fn cfi_ok_when_in_set() {
        let mut c = checker();
        c.add_cfi_set(1, [0x1000, 0x2000]);
        let issues = c.check_vtable(0xA000, &[0x1000], Some(1));
        let cfi: Vec<_> = issues.iter().filter(|i| matches!(i.kind, IntegrityIssueKind::CfiViolation { .. })).collect();
        assert!(cfi.is_empty());
    }

    #[test]
    fn thunk_chain_valid() {
        // JMP rel32 at code_base+0 → code_base+5+0x1000 = 0x11005 (not in our sections)
        // → should flag invalid thunk target.
        let mut code = vec![0x90u8; 16];
        let disp: i32 = 0x1000;
        code[0] = 0xE9;
        code[1..5].copy_from_slice(&disp.to_le_bytes());

        let c = checker();
        let issues = c.verify_thunk_chain(0xA000, 0, 0x1000, &code, 0x1000, 3);
        // The JMP lands at 0x1000 + 5 + 0x1000 = 0x2005 which is in .text → no issue.
        assert!(issues.is_empty(), "expected no issues: {issues:?}");
    }

    #[test]
    fn thunk_chain_invalid_target() {
        // JMP rel32 that lands in .data (non-executable).
        let code_base = 0x1000u64;
        let target = 0x6500u64; // .data
        let next_pc = code_base + 5;
        let disp = (target as i64 - next_pc as i64) as i32;
        let mut code = vec![0x90u8; 32];
        code[0] = 0xE9;
        code[1..5].copy_from_slice(&disp.to_le_bytes());

        let c = checker();
        let issues = c.verify_thunk_chain(0xA000, 0, code_base, &code, code_base, 3);
        assert!(issues.iter().any(|i| matches!(i.kind, IntegrityIssueKind::InvalidThunkTarget { .. })));
    }

    #[test]
    fn object_snapshot_corruption_detected() {
        let snap = ObjectSnapshot {
            object_addr: 0x10000,
            observed_vtable_ptr: 0xDEAD,
            expected_vtable_ptr: 0x1000,
        };
        assert!(snap.is_corrupted());
        let issue = snap.check().unwrap();
        assert!(issue.is_security_relevant);
        assert!(matches!(issue.kind, IntegrityIssueKind::VtablePointerCorrupted { .. }));
    }

    #[test]
    fn integrity_report_aggregation() {
        let c = checker();
        let mut report = IntegrityReport::new();
        let issues = c.check_vtable(0xA000, &[0], None); // null → 1 issue
        report.add_vtable(1, issues);
        assert_eq!(report.vtables_checked, 1);
        assert_eq!(report.issue_count(), 1);
        assert!(report.has_security_issues());
    }

    // ─── Adversarial / hardening tests ───────────────────────────────────────

    use crate::test_prng::XorShift;

    #[test]
    fn fuzz_thunk_chain_no_panic_on_garbage() {
        let mut rng = XorShift(0xc0de_c0de_c0de_c0de);
        let c = checker();
        for _ in 0..500 {
            let len = (rng.next() % 64) as usize;
            let code: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let code_base = match rng.next() % 3 {
                0 => rng.next() % 0x1_0000,
                1 => u64::MAX - (rng.next() % 64),
                _ => rng.next(),
            };
            let thunk = code_base.wrapping_add(rng.next() % 128);
            let _ = c.verify_thunk_chain(0xA000, 0, thunk, &code, code_base, 8);
            let slots: Vec<u64> = (0..(rng.next() % 8)).map(|_| rng.next()).collect();
            let _ = c.check_vtable(rng.next(), &slots, Some((rng.next() % 4) as u32));
        }
    }

    #[test]
    fn check_vtable_issue_order_deterministic() {
        let c = checker();
        let slots = [0u64, 0x6500, 0xFFFF_FFFF, 0x1000, 0x1000];
        let a = c.check_vtable(0xA000, &slots, None);
        let b = c.check_vtable(0xA000, &slots, None);
        let idx_a: Vec<_> = a.iter().map(|i| (i.slot_index, i.label())).collect();
        let idx_b: Vec<_> = b.iter().map(|i| (i.slot_index, i.label())).collect();
        assert_eq!(idx_a, idx_b);
        assert!(idx_a.windows(2).all(|w| w[0].0 <= w[1].0), "slot-ordered");
    }
}
