//! Invariants the Windows syscall tables must satisfy.
//!
//! `WinSyscallDb::lookup` and `lookup_by_name` both use `Iterator::find`, which
//! returns the FIRST match. A duplicated SSN or name is therefore not a loud
//! error: the wrong entry is returned, silently, and every caller downstream
//! resolves a syscall number to the wrong function. These tables are
//! hand-transcribed per Windows build, which is exactly where a transcription
//! slip hides.

use rustre_syscalls_windows::{WinArch, WinSyscallDb};

const ARCHES: [WinArch; 2] = [WinArch::X64, WinArch::X86];

/// Looking an entry up by its own SSN must return that same entry.
#[test]
fn ssn_lookup_round_trips() {
    let db = WinSyscallDb::new();
    for arch in ARCHES {
        let Some(entries) = db.all_for_arch(arch) else {
            continue;
        };
        for e in entries {
            let found = db.lookup(arch, e.ssn).unwrap_or_else(|| {
                panic!("{arch}: SSN {:#x} ({}) is in the table but not findable", e.ssn, e.name)
            });
            assert_eq!(
                found.name, e.name,
                "{arch}: SSN {:#x} resolves to {} but the table also lists it as {}",
                e.ssn, found.name, e.name
            );
        }
    }
}

/// No two entries in one architecture may share an SSN.
///
/// `lookup` takes the first match, so a duplicate silently shadows the other.
#[test]
fn ssns_are_unique_per_arch() {
    let db = WinSyscallDb::new();
    for arch in ARCHES {
        let Some(entries) = db.all_for_arch(arch) else {
            continue;
        };
        let mut seen: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
        for e in entries {
            if let Some(prev) = seen.insert(e.ssn, &e.name) {
                panic!("{arch}: SSN {:#x} is claimed by both {} and {}", e.ssn, prev, e.name);
            }
        }
    }
}

/// No two entries in one architecture may share a name.
#[test]
fn names_are_unique_per_arch() {
    let db = WinSyscallDb::new();
    for arch in ARCHES {
        let Some(entries) = db.all_for_arch(arch) else {
            continue;
        };
        let mut seen: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        for e in entries {
            if let Some(prev) = seen.insert(&e.name, e.ssn) {
                panic!(
                    "{arch}: name {} is claimed by both SSN {:#x} and {:#x}",
                    e.name, prev, e.ssn
                );
            }
        }
    }
}

/// The `zw_name` alias must be the `Nt` name with the prefix swapped.
///
/// The field documents itself as "Zw-prefixed alias (e.g. `ZwReadFile` for
/// `NtReadFile`)", so this is the stated contract, not a guess.
#[test]
fn zw_alias_matches_the_nt_name() {
    let db = WinSyscallDb::new();
    for arch in ARCHES {
        let Some(entries) = db.all_for_arch(arch) else {
            continue;
        };
        for e in entries {
            let Some(stem) = e.name.strip_prefix("Nt") else {
                continue; // not an Nt* syscall; the convention does not apply
            };
            assert_eq!(
                e.zw_name,
                format!("Zw{stem}"),
                "{arch}: {} has zw_name {} — expected Zw{stem}",
                e.name,
                e.zw_name
            );
        }
    }
}

/// Guards the tests above against passing vacuously on empty tables.
#[test]
fn the_tables_are_actually_populated() {
    let db = WinSyscallDb::new();
    let total: usize = ARCHES.iter().map(|a| db.arch_count(*a)).sum();
    assert!(
        total >= 20,
        "only {total} syscalls across all arches — the invariants above would \
         hold without examining anything"
    );
}
