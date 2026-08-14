# rustre-patch — Analysis

## Purpose
Binary patching layer for RustRE: validate, apply, and roll back patches on binary files and in-memory buffers. Supports raw byte ops at file offsets and at PE virtual addresses, NOP/XOR/asm patches, code cave discovery, PE security flag toggles + checksum recompute, binary delta diffing, and hot-patching of live memory.

## Public Functions (semantic view)

### Core types (`lib.rs`)
- `Patch::new(id, desc, offset, original_bytes, patch_bytes)` → Patch record (offset + before/after bytes + applied flag).
- `Patch::size()` → byte length of replacement.
- `Patch::is_same_size()` → original.len == patch.len.
- `PatchSet::new/add/len/is_empty/total_bytes_modified` → collection helpers.

### `binary_patcher.rs`
- `apply_patches(patches, binary)` → returns new binary with all patches applied, plus a `PatchResult` report. **Verifiable**: byte-equality at each offset; len preserved iff is_same_size.
- `BinaryPatcher::new/with_options/with_validator/apply_one/apply_set` → orchestrated apply with validation and options.
- `apply_inserts(...)` / `apply_removals(...)` → length-changing edits (shifts tail).
- `checksum_after(patches, binary)` → u64 checksum of post-patch image. **Verifiable**: deterministic, recomputable.
- `parse_hex_bytes("DE AD BE EF" | "deadbeef")` → `Vec<u8>`. **Verifiable**: trivial round-trip vs Python `bytes.fromhex`.
- `pe_va_to_file_offset(pe_bytes, va)` → `PeSectionMap` (section name + file offset). **Verifiable**: cross-check vs pefile/LIEF.
- `patch_bytes_at_va(path, va, bytes, dry_run, backup)` → writes bytes at VA-resolved file offset; backup file optional. **Verifiable**: dry-run vs real run; file diff at offset.
- `patch_nop_range_at_va(path, va, length, ...)` → fills `length` bytes with 0x90.
- `patch_xor_region_at_va(path, va, length, key, ...)` → XORs region with repeating key.
- `patch_asm_at_va(path, va, asm, ...)` → assembles simple asm and writes.
- `assemble_simple(asm)` → bytes for a tiny built-in asm subset (likely nop/ret/int3/jmp etc.).

### `code_cave.rs`
- `CodeCaveScanner::new(min_size).with_fill_bytes(...).scan(binary)` → list of `CodeCave{offset,size,...}`.
- `CodeCaveScanner::detect_format(binary)` → `BinaryFormat` (PE/ELF/Mach-O).
- `CodeCaveScanner::find_first_fit(binary, needed)` → first cave ≥ needed.
- `find_code_caves(binary, min_size)` → `Vec<CodeCave>`. **Verifiable**: each reported region is a run of fill-byte (0x00/0x90/0xCC) of len ≥ min_size, inside an executable section.
- `find_code_caves_from_path(path, min_size)` → same, from path.

### `pe_security.rs`
- `pe_security_summary(data)` → `PeSecuritySummary` with flags (ASLR/DEP/CFG/SEH/HighEntropyVA, etc.). **Verifiable**: vs `dumpbin /HEADERS` or LIEF DllCharacteristics.
- `pe_security_summary_from_path(path)` → same.
- `compute_pe_checksum(image, checksum_offset)` → u32 PE CheckSum. **Verifiable**: matches Windows `CheckSumMappedFile` / pefile.
- `pe_security_set_from_path(path, toggles, dry_run, backup)` → flips PE flags, rewrites checksum.

### `binary_diff.rs`
- `BinaryDelta::encode()` / `decode(blob)` → serialize/deserialize delta. **Verifiable**: round-trip identity.
- `BinaryDelta::apply(old)` → new bytes. **Verifiable**: `apply(build_delta(old,new), old) == new`.
- `build_delta(old, new, opts)` → BinaryDelta with copy/insert ops.
- `diff(old, new)` → encoded delta bytes.
- `patch(old, delta)` → new bytes.

### `patch_validator.rs`
- `PatchValidator::new/strict/set_rule/validate_one/validate_set` → returns `ValidationReport{errors,warnings}`.
- `validate_patch(patch, binary)` → convenience. **Verifiable**: original_bytes match @offset, no overlaps, within bounds.

### `patch_rollback.rs`
- `RollbackEntry::from_patch / from_applied_op / can_rollback / is_already_rolled_back`.
- `RollbackSnapshot::new/with_label/total_bytes`.
- `PatchRollback::new/create_snapshot/create_snapshot_from_ops/rollback/apply_snapshot/snapshot_ids/get_snapshot/remove_snapshot/snapshot_count/clear`.
- `create_rollback(patches, binary)` → snapshot. **Verifiable**: `rollback(apply(p,b)) == b`.

### `hot_patch.rs`
- `HotPatcher::new(writer).apply(patch, address)` → `LivePatch`. Writer = `InMemoryWriter` or `RuntimeMemoryWriter`.
- `revert(id)` / `revert_all()` / `live_count()` / `live_patches()` / `get(id)` / `snapshot()`.
- **Verifiable** with `InMemoryWriter`: snapshot byte-equality before/after revert.

## Existing MCP Tools (wire_tools.rs)
- `patch_pe_security_summary` → `pe_security_summary_from_path`
- `patch_patch_find_code_caves` → `find_code_caves_from_path`
- `patch_bytes` → `patch_bytes_at_va`
- `patch_nop_range` → `patch_nop_range_at_va`
- `patch_xor_region` → `patch_xor_region_at_va`
- `patch_asm` → `patch_asm_at_va`
- `patch_pe_set_security` → `pe_security_set_from_path`

Not wired: `binary_diff` (diff/patch/build_delta), `patch_validator`, `patch_rollback`, `hot_patch`, `apply_patches`, `parse_hex_bytes`, `pe_va_to_file_offset` (standalone), `compute_pe_checksum`, `assemble_simple`.

## Testable Functions (high ground-truth)
1. `parse_hex_bytes` — Python `bytes.fromhex`.
2. `apply_patches` / `BinaryPatcher::apply_one` — byte-replace at offset, length-preserving check.
3. `diff` + `patch` round-trip — `patch(old, diff(old,new)) == new`.
4. `BinaryDelta::encode/decode` — round-trip.
5. `create_rollback` + `apply_patches` — rollback inverts apply.
6. `find_code_caves` — generated buffer with known runs of 0x00/0x90.
7. `compute_pe_checksum` — vs `pefile.PE.generate_checksum()`.
8. `pe_security_summary` — vs LIEF `optional_header.dll_characteristics`.
9. `pe_va_to_file_offset` — vs `pefile.get_offset_from_rva`.
10. `validate_patch` — synthetic mismatches, out-of-bounds, overlapping.
11. `HotPatcher` w/ `InMemoryWriter` — apply then revert == original buffer.
12. `assemble_simple("nop")` → `[0x90]`, `"ret"` → `[0xC3]`, `"int3"` → `[0xCC]` (subject to actual coverage).

## Validator Strategy
Build a Rust harness crate (or test bin) that links `rustre-patch` directly and runs the above categories against deterministic in-memory fixtures plus a small synthetic PE generated with `pefile`:
- pure-byte ops (1,2,3,4,5,6) → no external dep, just byte comparisons.
- PE ops (7,8,9) → cross-validate with a Python sidecar invoking `pefile`/`LIEF` on the same generated PE; compare JSON outputs.
- `assemble_simple` (12) → table of known mnemonic→opcode pairs.
- hot patching (11) → in-memory only, no OS calls.
Report per-function pass/fail + diff snippet on mismatch.
