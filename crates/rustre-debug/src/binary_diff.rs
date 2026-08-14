//! Cross-run patch/binary diffing (Tier 3, item 9 of `rustre_debug_enhancement_plan.md`).
//!
//! Correlates symbol tables across two versions of the same binary (BinDiff-style,
//! but by matched symbol name rather than graph-isomorphism matching — cheap and
//! exact whenever debug info/exports are present) directly inside a live debug
//! session, and migrates breakpoint addresses from the old binary to the new one
//! so a regression-triage session can carry breakpoints across a rebuild.

use std::collections::HashMap;

use rustre_core::address::Address;

use crate::Symbol;

/// The result of diffing two symbol tables from different builds of the same binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BinaryDiff {
    /// Symbols present only in the new build.
    pub added: Vec<Symbol>,
    /// Symbols present only in the old build.
    pub removed: Vec<Symbol>,
    /// Same-named symbols whose address changed (old, new).
    pub moved: Vec<(Symbol, Symbol)>,
    /// Same-named, same-address symbols whose size changed (old, new) — usually
    /// means the function body was edited without moving.
    pub resized: Vec<(Symbol, Symbol)>,
    /// Same-named symbols that are byte-for-byte identical (address + size).
    pub unchanged_count: usize,
}

fn by_name(symbols: &[Symbol]) -> HashMap<&str, &Symbol> {
    symbols.iter().map(|s| (s.name.as_str(), s)).collect()
}

/// Diff two symbol tables from different builds of the same binary, matching by
/// symbol name.
#[must_use]
pub fn diff_binaries(old: &[Symbol], new: &[Symbol]) -> BinaryDiff {
    let old_by_name = by_name(old);
    let new_by_name = by_name(new);

    let mut diff = BinaryDiff::default();

    for old_sym in old {
        match new_by_name.get(old_sym.name.as_str()) {
            None => diff.removed.push(old_sym.clone()),
            Some(&new_sym) => {
                if old_sym.address != new_sym.address {
                    diff.moved.push((old_sym.clone(), new_sym.clone()));
                } else if old_sym.size != new_sym.size {
                    diff.resized.push((old_sym.clone(), new_sym.clone()));
                } else {
                    diff.unchanged_count += 1;
                }
            }
        }
    }
    for new_sym in new {
        if !old_by_name.contains_key(new_sym.name.as_str()) {
            diff.added.push(new_sym.clone());
        }
    }
    diff
}

/// Outcome of migrating one breakpoint address from an old build to a new one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BreakpointMigration {
    /// Migrated cleanly: the containing symbol still exists in the new build
    /// and the offset within it still fits, so `new_address` is the same
    /// logical location.
    Migrated { symbol: String, new_address: Address },
    /// The breakpoint's containing symbol no longer exists in the new build.
    SymbolRemoved { symbol: String },
    /// The symbol still exists but shrank enough that the old offset now
    /// falls outside it — the breakpoint likely targeted code that was
    /// deleted or moved to another function.
    OffsetOutOfRange { symbol: String, offset: u64, new_size: u64 },
    /// The symbol still exists but the new build does not record its SIZE, so
    /// the offset could not be validated.
    ///
    /// The address is still the caller's best lead — same symbol, same offset —
    /// but nothing confirmed the offset still lands inside the function. This
    /// used to be reported as [`Self::Migrated`], whose documentation promises
    /// "the same logical location": with a size of 0 the range check was
    /// skipped entirely, so a breakpoint could be placed well past the end of a
    /// function that had shrunk, and the caller was told the migration was
    /// clean. Size-0 symbols are ordinary — stripped or partial symbol tables,
    /// assembly labels, PE exports without sizes — so this is the common case,
    /// not the exotic one.
    MigratedUnverified {
        symbol: String,
        new_address: Address,
        offset: u64,
    },
    /// The old address didn't fall inside any known symbol; nothing to migrate.
    UnknownSymbol,
    /// The symbol exists but `base + offset` would leave the address space.
    AddressOverflow { symbol: String, offset: u64 },
}

/// Find the symbol in `symbols` that contains `address`, if any.
fn containing_symbol<'a>(symbols: &'a [Symbol], address: Address) -> Option<&'a Symbol> {
    let addr = address.as_u64();
    symbols
        .iter()
        .find(|s| s.size > 0 && addr >= s.address && addr - s.address < s.size)
}

/// Migrate a single breakpoint address set on `old` to its equivalent location
/// in `new`, by finding the containing symbol in `old`, computing the
/// in-function byte offset, and re-applying that offset to the same-named
/// symbol in `new`.
#[must_use]
pub fn migrate_breakpoint(old_address: Address, old: &[Symbol], new: &[Symbol]) -> BreakpointMigration {
    let Some(old_sym) = containing_symbol(old, old_address) else {
        return BreakpointMigration::UnknownSymbol;
    };
    let offset = old_address.as_u64() - old_sym.address;

    let new_by_name = by_name(new);
    let Some(&new_sym) = new_by_name.get(old_sym.name.as_str()) else {
        return BreakpointMigration::SymbolRemoved { symbol: old_sym.name.clone() };
    };
    if new_sym.size > 0 && offset >= new_sym.size {
        return BreakpointMigration::OffsetOutOfRange {
            symbol: old_sym.name.clone(),
            offset,
            new_size: new_sym.size,
        };
    }
    let Some(new_address) = new_sym.address.checked_add(offset) else {
        return BreakpointMigration::AddressOverflow {
            symbol: old_sym.name.clone(),
            offset,
        };
    };
    if new_sym.size == 0 {
        // The offset could not be checked against anything. Reporting this as
        // a clean migration is the defect: see `MigratedUnverified`.
        return BreakpointMigration::MigratedUnverified {
            symbol: old_sym.name.clone(),
            new_address: Address(new_address),
            offset,
        };
    }
    BreakpointMigration::Migrated {
        symbol: old_sym.name.clone(),
        new_address: Address(new_address),
    }
}

/// Migrate a batch of breakpoint addresses at once — convenience wrapper
/// around [`migrate_breakpoint`] preserving input order.
#[must_use]
pub fn migrate_breakpoints(addresses: &[Address], old: &[Symbol], new: &[Symbol]) -> Vec<BreakpointMigration> {
    addresses.iter().map(|&addr| migrate_breakpoint(addr, old, new)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &str, address: u64, size: u64) -> Symbol {
        Symbol { name: name.into(), address, size, module: None }
    }

    #[test]
    fn detects_added_and_removed_symbols() {
        let old = vec![sym("a", 0x1000, 0x10), sym("b", 0x2000, 0x10)];
        let new = vec![sym("a", 0x1000, 0x10), sym("c", 0x3000, 0x10)];
        let diff = diff_binaries(&old, &new);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "b");
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "c");
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn detects_moved_and_resized() {
        let old = vec![sym("f", 0x1000, 0x10), sym("g", 0x2000, 0x20)];
        let new = vec![sym("f", 0x1100, 0x10), sym("g", 0x2000, 0x30)];
        let diff = diff_binaries(&old, &new);
        assert_eq!(diff.moved.len(), 1);
        assert_eq!(diff.moved[0].0.name, "f");
        assert_eq!(diff.moved[0].1.address, 0x1100);
        assert_eq!(diff.resized.len(), 1);
        assert_eq!(diff.resized[0].0.name, "g");
        assert_eq!(diff.resized[0].1.size, 0x30);
    }

    #[test]
    fn migrates_breakpoint_within_moved_function() {
        let old = vec![sym("f", 0x1000, 0x20)];
        let new = vec![sym("f", 0x5000, 0x20)];
        let result = migrate_breakpoint(Address(0x1008), &old, &new);
        assert_eq!(result, BreakpointMigration::Migrated { symbol: "f".into(), new_address: Address(0x5008) });
    }

    #[test]
    fn reports_symbol_removed() {
        let old = vec![sym("f", 0x1000, 0x20)];
        let new = vec![sym("g", 0x1000, 0x20)];
        let result = migrate_breakpoint(Address(0x1008), &old, &new);
        assert_eq!(result, BreakpointMigration::SymbolRemoved { symbol: "f".into() });
    }

    #[test]
    fn reports_offset_out_of_range_when_function_shrinks() {
        let old = vec![sym("f", 0x1000, 0x20)];
        let new = vec![sym("f", 0x1000, 0x8)];
        let result = migrate_breakpoint(Address(0x1010), &old, &new);
        assert_eq!(result, BreakpointMigration::OffsetOutOfRange { symbol: "f".into(), offset: 0x10, new_size: 0x8 });
    }

    #[test]
    fn unknown_address_reports_unknown_symbol() {
        let old = vec![sym("f", 0x1000, 0x20)];
        let new = vec![sym("f", 0x1000, 0x20)];
        let result = migrate_breakpoint(Address(0x9999), &old, &new);
        assert_eq!(result, BreakpointMigration::UnknownSymbol);
    }

    #[test]
    fn migrate_batch_preserves_order() {
        let old = vec![sym("f", 0x1000, 0x10), sym("g", 0x2000, 0x10)];
        let new = vec![sym("f", 0x1000, 0x10), sym("g", 0x2000, 0x10)];
        let results = migrate_breakpoints(&[Address(0x1004), Address(0x2004)], &old, &new);
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], BreakpointMigration::Migrated { .. }));
        assert!(matches!(results[1], BreakpointMigration::Migrated { .. }));
    }

    /// A symbol whose new size is unknown cannot be reported as a CLEAN
    /// migration.
    ///
    /// The range check was `new_sym.size > 0 && offset >= new_sym.size`, so a
    /// size of 0 skipped it entirely and the breakpoint was placed at
    /// `base + offset` and reported as `Migrated` — whose documentation
    /// promises "the same logical location". If the function shrank, the
    /// breakpoint lands past its end, in whatever follows, and the user is
    /// told the migration was clean. Size-0 symbols are the ordinary case
    /// (stripped or partial symbol tables, assembly labels, PE exports),
    /// not an exotic one.
    #[test]
    fn an_unsized_new_symbol_migrates_but_says_it_could_not_be_checked() {
        let old = vec![sym("work", 0x1000, 0x80)];
        // Same name, relocated, size unknown in the new build.
        let new = vec![sym("work", 0x5000, 0)];

        let m = migrate_breakpoint(Address(0x1040), &old, &new);
        match m {
            BreakpointMigration::MigratedUnverified { ref symbol, new_address, offset } => {
                assert_eq!(symbol, "work");
                assert_eq!(new_address, Address(0x5040));
                assert_eq!(offset, 0x40);
            }
            other => panic!("an unsized target must not pass for a checked migration: {other:?}"),
        }

        // With a real size the migration IS verified, so the new variant is
        // not simply swallowing every case.
        let new = vec![sym("work", 0x5000, 0x80)];
        assert_eq!(
            migrate_breakpoint(Address(0x1040), &old, &new),
            BreakpointMigration::Migrated {
                symbol: "work".to_string(),
                new_address: Address(0x5040),
            }
        );
        // ...and a shrunk function still reports the offset as out of range.
        let new = vec![sym("work", 0x5000, 0x20)];
        assert!(matches!(
            migrate_breakpoint(Address(0x1040), &old, &new),
            BreakpointMigration::OffsetOutOfRange { .. }
        ));
    }

    /// `base + offset` must not wrap the address space.
    #[test]
    fn a_migration_that_would_wrap_the_address_space_is_refused() {
        let old = vec![sym("edge", 0x1000, 0x100)];
        let new = vec![sym("edge", u64::MAX - 0x10, 0)];
        assert!(matches!(
            migrate_breakpoint(Address(0x1080), &old, &new),
            BreakpointMigration::AddressOverflow { .. }
        ));
    }

}
