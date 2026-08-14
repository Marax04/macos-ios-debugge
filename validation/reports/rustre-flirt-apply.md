# rustre-flirt-apply

## Overview
Apply FLIRT (Fast Library Identification and Recognition Technology) signatures to identify library functions inside a binary. Provides parsers for IDA `.pat`/`.sig` files, multiple scanner backends (linear and Aho-Corasick accelerated), confidence scoring, conflict resolution, and name propagation.

## Cargo.toml
- name: `rustre-flirt-apply` v0.1.0, edition 2024
- Dependencies: `rustre-flirt` (path), `ahash`, `aho-corasick` 1, `thiserror`, `serde`, `serde_json`
- Dev: `tempfile` 3
- Workspace lints inherited

## Modules (24)
`apply_engine`, `applied_names_store`, `batch_applicator`, `batch_applier`, `bulk_applier`, `casts` (pub(crate)), `collision_resolution`, `confidence_scorer`, `disambig`, `flirt_applicator`, `ida_sig_compat`, `match_conflict_resolver`, `match_scorer`, `match_validator`, `name_propagator`, `pat_parser`, `recognition_session`, `rename_propagator`, `sig_file_loader`, `sig_pack`, `sig_parser`, `sig_priority`, `trie_index`.

## Core Public API (lib.rs)

### Types
- `FlirtError` (thiserror enum): `InvalidSigFile`, `PatternTooShort(usize)`, `Io(io::Error)`, `Parse(String)`.
- `FlirtPattern { bytes: Vec<Option<u8>>, name, lib_name, version, crc_offset:u16, crc_len:u16, crc:u16, public_names, local_names, references }` — `Option<u8>` byte form with `None` = wildcard.
- `FlirtMatch { address:u64, function_name, lib_name, confidence:u8 (0–100), pattern_length:usize }`.
- `LibraryMark { address:u64, lib_name }` — minimal projection used by feature K to mark FunctionTable entries as library code.
- `FlirtSigDb` — collection of `FlirtPattern`s.
- `FlirtApplier { db, min_confidence }` — runs scans over `&[u8]`.
- `FlirtSignature { bytes, mask, name, lib_name, crc_offset, crc_len, crc }` — mask-based form used by the fast scanner.
- `WildcardPattern { fixed_bytes, mask }` — concrete-prefix key (≤32 bytes) for Aho-Corasick indexing.
- `AhoCorasickIndex` — multi-pattern index of concrete prefixes; `search` returns candidate `(offset, sig_idx)` pairs.
- `FlirtScanner { sigs, index, min_confidence }` — fast scanner combining Aho-Corasick with full verification.

### Key Functions
- `library_marks_from_matches(&[FlirtMatch]) -> Vec<LibraryMark>` — filters out empty `lib_name`.
- `crc16_flirt(&[u8]) -> u16` — CRC-16/MCRF4XX (poly 0x8408 reflected) as used by IDA FLIRT.
- `FlirtPattern::new`, `pattern_len`, `matches(&[u8]) -> bool`, `from_pattern_str(pattern, name, lib)` — parses `"55 8B EC ?? ?? 8B"`, errors if <4 bytes or invalid token.
- `FlirtSigDb::new`, `add_pattern`, `pattern_count`, `load_demo_sigs()` — built-in CRT/Win32 demo set (memcpy, memset, strlen, strcpy, strcmp, malloc, free, printf, sprintf, puts, exit, abort, memmove, fopen, fclose, UPX_decompress, NtAllocateVirtualMemory, HeapAlloc_thunk).
- `FlirtApplier::new(db)` (min_confidence=60), `set_min_confidence(u8)`.
- `FlirtApplier::apply(&self, data, sig_path, base_addr) -> Result<Vec<(u64,String,u8)>, FlirtError>` — auto-detects `.sig` (binary, magic `IDASGN`) vs `.pat` (text); loads via `load_auto`, builds db, scans.
- `FlirtApplier::scan_bytes(data, sigs, base_addr, min_conf) -> Vec<(u64,String,u8)>` — static; per-pattern overlapping-window scan with optional CRC-16 mid-region check.
- `FlirtApplier::scan(&self, data, base_addr) -> Vec<FlirtMatch>` — full sliding window scan with CRC verification.
- `FlirtApplier::scan_at_addresses(&self, data, base_addr, func_addrs:&[u64]) -> Vec<FlirtMatch>` — only at given function starts.
- `FlirtApplier::match_count(data, base_addr) -> usize`.
- `FlirtSignature::from_flirt_pattern(&FlirtPattern)`, `matches_at(&[u8])`.
- `WildcardPattern::from_signature(&FlirtSignature)`, `prefix()` — leading concrete run up to `PREFIX_CAP=32`.
- `AhoCorasickIndex::build(&[FlirtSignature])`, `search(data, sigs) -> Vec<(usize,usize)>`, `is_built()`.
- `FlirtScanner::from_pack(&SignaturePack)`, `from_packs(&[SignaturePack])`, `new_linear`, `new_fast`, `signature_count`, `set_min_confidence`, `scan_fast(data, base_addr) -> Vec<FlirtMatch>` — uses Aho-Corasick when built, falls back to linear.

### Re-exports
- `sig_pack::SignaturePack`
- `applied_names_store::{AppliedName, AppliedNamesStore, CommitStats, NameOrigin, StoreConfig}`
- `name_propagator::{NameBinding, NameConflictResolver, NamePropagator, PropagationResult, XrefGraph, is_placeholder}`
- Numeric cast helpers from `casts` (`f32_from_f64_bits`, `f64_to_u8`, etc.) — internal-use safe conversions.

## Modules — Roles & Signatures

- `pat_parser` — parses IDA `.pat` text files (`load_pat_file`, `parse_pat_line`).
- `sig_parser` — parses IDA `.sig` binary files (header magic `IDASGN`, node tree).
- `sig_file_loader` — `load_auto(path)` dispatches by magic; common loader entrypoint.
- `ida_sig_compat` — IDA compatibility helpers (header parsing, version bits).
- `sig_pack::SignaturePack` — owned collection of `FlirtPattern`s with metadata (`patterns`, `lib_name`, etc.); used by `FlirtScanner::from_pack(s)`.
- `apply_engine` — orchestrates pattern matching pipeline.
- `flirt_applicator` — higher-level applier coordinating loading + scanning + naming.
- `bulk_applier` / `batch_applier` / `batch_applicator` — process many binaries or many sigs in one pass.
- `recognition_session` — stateful session tracking matches across passes.
- `trie_index` — alternative trie-based prefix index.
- `confidence_scorer` / `match_scorer` — scoring of matches; richer than `compute_confidence` (length + concrete ratio).
- `match_validator` — post-match verification (CRC, references).
- `collision_resolution` / `match_conflict_resolver` — picks a winner when several patterns hit the same address.
- `disambig` — disambiguates name conflicts via context.
- `sig_priority` — priority/ordering of signature sources.
- `name_propagator` / `rename_propagator` — propagate matched library names through xrefs (`XrefGraph`), with `NameConflictResolver` and `is_placeholder(&str)` helper.
- `applied_names_store` — persistent store of applied names with `NameOrigin`, `CommitStats`, `StoreConfig`.
- `casts` — checked numeric conversions used throughout the crate.

## I/O
- Inputs: byte slices (`&[u8]`) representing loaded binary data, `&std::path::Path` to `.pat`/`.sig` files, `base_addr: u64` (VA where data starts), `func_addrs: &[u64]` for targeted scans, `SignaturePack`s constructed via the loaders.
- Outputs: `Vec<FlirtMatch>` (rich) or `Vec<(u64,String,u8)>` (tuple), `Vec<LibraryMark>` for downstream FunctionTable labelling, `Result<_, FlirtError>` on parse/IO failures.
- File format auto-detection by magic `IDASGN` (binary) → otherwise treated as `.pat` text.

## Behavior
- Wildcard handling: `??`, `.`, `..` tokens in `.pat` parsing → `None`; per-byte mask (`0xff`/`0x00`) in `FlirtSignature`.
- Minimum 4 bytes required when parsing pattern strings.
- Confidence: `compute_confidence(pat)` blends concrete-byte ratio (×80) with a length bonus (up to 20 for ≥16 bytes), capped at 100. Default minimum threshold is 60.
- CRC verification: when `crc_len > 0`, after the pattern body, the bytes `[crc_offset .. crc_offset+crc_len]` are CRC-16-checked using `crc16_flirt` (poly 0x8408 reflected, init 0xFFFF). Mismatch suppresses the match.
- Scanning strategies:
  - `FlirtApplier::scan` / `scan_bytes`: O(n·m) sliding-window per pattern with wildcard + CRC.
  - `FlirtApplier::scan_at_addresses`: only at known function starts.
  - `FlirtScanner::scan_fast`: builds an Aho-Corasick index over the longest concrete prefix (≤32 bytes) of each signature; candidates are fully verified (wildcard + CRC + min confidence) before being returned. Falls back to linear scan when the automaton is empty (all-wildcard patterns).
- Library-mark projection drops entries whose `lib_name` is empty (origin required).
- Name propagation: `NamePropagator` walks an `XrefGraph` and applies library-derived names, deferring to `NameConflictResolver` on collisions and skipping placeholders (`is_placeholder`).
- Demo signatures provide an out-of-the-box CRT/Win32 baseline useful for tests and smoke checks.

## Testability
The crate ships with an extensive inline `#[cfg(test)] mod tests` in `lib.rs` covering pattern parsing, wildcard semantics, scanner correctness, CRC pass/fail, demo-sig matching, `apply()` round-trip with a temp `.pat` file (`tempfile` dev-dep), and confidence-score edge cases. All public types and key functions are exercisable from external tests; no hidden global state.
