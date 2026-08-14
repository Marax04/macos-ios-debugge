//! Feature K — propagate library classification from FLIRT recognition
//! results into the authoritative [`FunctionTable`].
//!
//! `apply_library_marks` walks the [`LibraryMark`] list produced by the
//! `rustre-flirt-apply` projection helper and flips `is_library = true` on the
//! matching `FunctionDef`. The pass is purely a labelling step: it never
//! invents new functions and never overrides a function that the table does
//! not already know about.
//!
//! When the optional `thunk_targets` slice is non-empty (paired with the
//! structural [`FunctionClass::Thunk`] detection in `function_classifier`),
//! the jump target of each thunk is also marked as library code — a thunk
//! into an import is, by definition, library glue, and the imported routine
//! itself is library code too.

use rustre_core::address::Address;
use rustre_core::binary_view::FunctionTable;
use rustre_flirt_apply::LibraryMark;

/// Summary of a single [`apply_library_marks`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibraryPropagationStats {
    /// Number of `LibraryMark` entries inspected.
    pub considered: usize,
    /// Number of [`FunctionDef`] entries flipped to `is_library = true`.
    pub marked: usize,
    /// Number of marks whose address did not exist in the [`FunctionTable`].
    pub missing: usize,
    /// Number of thunk targets additionally marked as library code.
    pub thunk_targets_marked: usize,
}

/// Propagate library classification from `marks` into `table`.
///
/// Idempotent: a function already classified as library is counted under
/// `marked` exactly once per call but its state remains correct on repeat
/// invocations.
///
/// `thunk_targets` is an optional `&[(thunk_addr, target_addr)]` list — for
/// every thunk whose entry was successfully marked, the target is also
/// marked under the same library origin (when the target lives in the
/// table; otherwise silently skipped).
pub fn apply_library_marks(
    table: &mut FunctionTable,
    marks: &[LibraryMark],
    thunk_targets: &[(u64, u64)],
) -> LibraryPropagationStats {
    let mut stats = LibraryPropagationStats {
        considered: marks.len(),
        ..Default::default()
    };

    for m in marks {
        let addr = Address::new(m.address);
        if table.mark_library(addr, &m.lib_name) {
            stats.marked += 1;

            for (thunk_addr, target_addr) in thunk_targets {
                if *thunk_addr == m.address
                    && *target_addr != 0
                    && table.mark_library(Address::new(*target_addr), &m.lib_name)
                {
                    stats.thunk_targets_marked += 1;
                }
            }
        } else {
            stats.missing += 1;
        }
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::binary_view::FunctionDef;

    fn mk_table() -> FunctionTable {
        let mut t = FunctionTable::new();
        t.add_function(FunctionDef::new(Address::new(0x1000), "sub_1000"));
        t.add_function(FunctionDef::new(Address::new(0x2000), "sub_2000"));
        t.add_function(FunctionDef::new(Address::new(0x3000), "user_main"));
        t
    }

    #[test]
    fn marks_propagate_to_table() {
        let mut t = mk_table();
        let marks = vec![
            LibraryMark { address: 0x1000, lib_name: "msvcrt".into() },
            LibraryMark { address: 0x2000, lib_name: "msvcrt".into() },
        ];
        let stats = apply_library_marks(&mut t, &marks, &[]);
        assert_eq!(stats.considered, 2);
        assert_eq!(stats.marked, 2);
        assert_eq!(stats.missing, 0);
        assert_eq!(t.count_library(), 2);
        assert_eq!(t.count_user(), 1);
        let f = t.get_function_at(Address::new(0x1000)).unwrap();
        assert_eq!(f.library_origin.as_deref(), Some("msvcrt"));
    }

    #[test]
    fn marks_missing_addresses_counted() {
        let mut t = mk_table();
        let marks = vec![
            LibraryMark { address: 0xDEAD, lib_name: "msvcrt".into() },
            LibraryMark { address: 0x1000, lib_name: "msvcrt".into() },
        ];
        let stats = apply_library_marks(&mut t, &marks, &[]);
        assert_eq!(stats.marked, 1);
        assert_eq!(stats.missing, 1);
    }

    #[test]
    fn thunk_target_is_propagated() {
        let mut t = mk_table();
        // 0x1000 is a thunk into 0x2000; both should end up library.
        let marks = vec![LibraryMark { address: 0x1000, lib_name: "kernel32".into() }];
        let thunks = vec![(0x1000u64, 0x2000u64)];
        let stats = apply_library_marks(&mut t, &marks, &thunks);
        assert_eq!(stats.marked, 1);
        assert_eq!(stats.thunk_targets_marked, 1);
        assert!(t.get_function_at(Address::new(0x2000)).unwrap().is_library);
        assert_eq!(
            t.get_function_at(Address::new(0x2000))
                .unwrap()
                .library_origin
                .as_deref(),
            Some("kernel32"),
        );
    }

    #[test]
    fn thunk_target_outside_table_skipped() {
        let mut t = mk_table();
        let marks = vec![LibraryMark { address: 0x1000, lib_name: "kernel32".into() }];
        // Target 0xCAFE is not in the table — must be silently skipped.
        let thunks = vec![(0x1000u64, 0xCAFEu64)];
        let stats = apply_library_marks(&mut t, &marks, &thunks);
        assert_eq!(stats.thunk_targets_marked, 0);
        assert_eq!(t.count_library(), 1);
    }

    #[test]
    fn idempotent_repeat_mark() {
        let mut t = mk_table();
        let marks = vec![LibraryMark { address: 0x1000, lib_name: "msvcrt".into() }];
        let _ = apply_library_marks(&mut t, &marks, &[]);
        let stats2 = apply_library_marks(&mut t, &marks, &[]);
        assert_eq!(stats2.marked, 1);
        assert_eq!(t.count_library(), 1);
    }
}
