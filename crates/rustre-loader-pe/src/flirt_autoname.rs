//! FLIRT autoname hook for the PE loader.
//!
//! Scans the executable sections of a freshly-mapped PE image with a built-in
//! set of [`SignaturePack`]s (MSVC CRT, Rust stdlib) plus any caller-provided
//! packs, and returns the resolved `(address, symbol_name, lib, confidence)`
//! list ready to be committed to the [`BinaryView`]'s symbol table.

use rustre_core::binary_view::Memory;
use rustre_core::permissions::Permissions;
use rustre_flirt_apply::{
    FlirtMatch, FlirtScanner, ResolveStats, ResolvedRename, SignaturePack, resolve_renames,
};

/// Built-in baseline signature pack for the MSVC C runtime on x64.
pub const BASELINE_MSVCRT_X64: &str = include_str!(
    "../assets/baseline/msvcrt-x64.sigpack"
);

/// Built-in baseline signature pack for the Rust standard library on x64.
pub const BASELINE_RUST_STDLIB_X64: &str = include_str!(
    "../assets/baseline/rust-stdlib-x64.sigpack"
);

/// Default minimum confidence used when applying FLIRT matches during loading.
///
/// The threshold is tuned to admit the short, wildcard-heavy prologue
/// signatures shipped in the baseline `msvcrt-x64` / `rust-stdlib-x64` packs.
/// `compute_sig_confidence` blends a concrete-byte ratio (80 % weight) with a
/// length bonus (20 % weight, capped at 16 bytes), so a 23-byte pattern with
/// 9 concrete bytes scores around 51. A floor of 70 silently discarded every
/// baseline match, presenting the user with a "0 matches" result even on a
/// stock Rust + MSVC binary. 50 keeps high-quality matches while still
/// rejecting near-random hits.
pub const DEFAULT_MIN_CONFIDENCE: u8 = 50;

/// Decode all built-in baseline packs.
///
/// Failure to parse any single pack is silently ignored (the loader must not
/// abort an analysis session because a baseline pack was malformed); the
/// packs that parsed cleanly are returned.
#[must_use]
pub fn baseline_packs() -> Vec<SignaturePack> {
    let mut out = Vec::new();
    for text in [BASELINE_MSVCRT_X64, BASELINE_RUST_STDLIB_X64] {
        if let Ok(p) = SignaturePack::parse(text) {
            out.push(p);
        }
    }
    out
}

/// Walk every executable segment of `mem` and run `scanner` against it.
///
/// Each segment is scanned independently with its own base address, so matches
/// carry absolute virtual addresses suitable for symbol-table insertion.
#[must_use]
pub fn scan_executable_segments(scanner: &FlirtScanner, mem: &Memory) -> Vec<FlirtMatch> {
    let mut all = Vec::new();
    for seg in &mem.segments {
        if !seg.permissions.contains(Permissions::EXECUTE) {
            continue;
        }
        let base = seg.range.start.as_u64();
        let mut hits = scanner.scan_fast(&seg.data, base);
        all.append(&mut hits);
    }
    all
}

/// Apply the built-in baseline packs to `mem` and return the resolved rename
/// list plus scan statistics.
///
/// This is the canonical loader hook: call it once after the section map has
/// been populated and feed the returned [`ResolvedRename`]s into
/// [`rustre_core::binary_view::SymbolTable::add_symbol`].
#[must_use]
pub fn apply_default_packs(mem: &Memory) -> (Vec<ResolvedRename>, ResolveStats) {
    let packs = baseline_packs();
    let scanner = FlirtScanner::from_packs(&packs);
    let matches = scan_executable_segments(&scanner, mem);
    resolve_renames(&matches, DEFAULT_MIN_CONFIDENCE)
}

/// Apply `packs` to `mem` with an explicit confidence threshold.
#[must_use]
pub fn apply_packs(
    mem: &Memory,
    packs: &[SignaturePack],
    min_confidence: u8,
) -> (Vec<ResolvedRename>, ResolveStats) {
    let mut scanner = FlirtScanner::from_packs(packs);
    // Align the scanner's internal floor with the caller's request so we do
    // not silently drop candidates below the default (60) when the caller
    // explicitly asked for a lower threshold.
    scanner.set_min_confidence(min_confidence);
    let matches = scan_executable_segments(&scanner, mem);
    resolve_renames(&matches, min_confidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::{Address, AddressRange};
    use rustre_core::binary_view::Segment;

    fn make_segment(base: u64, data: Vec<u8>, perms: Permissions) -> Segment {
        let len = data.len() as u64;
        Segment {
            range: AddressRange::new(Address::new(base), Address::new(base + len)),
            permissions: perms,
            data,
        }
    }

    #[test]
    fn test_baseline_packs_parse() {
        let packs = baseline_packs();
        assert!(!packs.is_empty(), "at least one baseline pack must parse");
        assert!(packs.iter().any(|p| p.name.contains("msvcrt")));
    }

    #[test]
    fn test_apply_default_packs_no_match_on_zero_image() {
        let mut mem = Memory::new();
        mem.add_segment(make_segment(
            0x1_4000_0000,
            vec![0u8; 4096],
            Permissions::READ | Permissions::EXECUTE,
        ));
        let (renames, _stats) = apply_default_packs(&mem);
        assert!(renames.is_empty());
    }

    #[test]
    fn test_scan_skips_non_executable_segments() {
        // Build a pack that would otherwise match a known prologue.
        let pack_text = "SIGPACK 1\npack t\n---\n558BEC83EC10 | 0 0 0000 6 | t | fn\n";
        let pack = SignaturePack::parse(pack_text).unwrap();
        let scanner = FlirtScanner::from_pack(&pack);

        let mut mem = Memory::new();
        // Place the matching bytes in a NON-executable segment.
        mem.add_segment(make_segment(
            0x1000,
            vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00, 0x00],
            Permissions::READ,
        ));
        let hits = scan_executable_segments(&scanner, &mem);
        assert!(hits.is_empty(), "non-executable segments must be skipped");

        // Now mark it executable and the match should appear.
        let mut mem2 = Memory::new();
        mem2.add_segment(make_segment(
            0x1000,
            vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00, 0x00],
            Permissions::READ | Permissions::EXECUTE,
        ));
        let hits2 = scan_executable_segments(&scanner, &mem2);
        assert_eq!(hits2.len(), 1);
        assert_eq!(hits2[0].address, 0x1000);
    }

    #[test]
    fn test_apply_packs_threshold_respected() {
        let pack_text = "SIGPACK 1\npack t\n---\n558BEC83EC10 | 0 0 0000 6 | t | fn\n";
        let pack = SignaturePack::parse(pack_text).unwrap();
        let mut mem = Memory::new();
        mem.add_segment(make_segment(
            0x1000,
            vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10],
            Permissions::READ | Permissions::EXECUTE,
        ));
        let (renames_low, _) = apply_packs(&mem, std::slice::from_ref(&pack), 0);
        assert_eq!(renames_low.len(), 1);
        let (renames_high, _) = apply_packs(&mem, std::slice::from_ref(&pack), 101);
        assert!(renames_high.is_empty());
    }
}
