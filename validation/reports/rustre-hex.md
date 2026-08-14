# rustre-hex — Analysis

## Purpose
Core hex editor data model and utilities: a mutable byte buffer (`HexBuffer`) with undo/redo, multi-cursor editing, bookmarks, typed data overlays (struct view), search (KMP/regex/hex-pattern), find-replace, byte statistics, histogram, Shannon entropy, byte diffing, bitwise transforms (XOR/AND/OR/NOT/ADD/NEG), block ops (fill/reverse/shift/rotate), and virtual-address mapping. Pure data layer — no GUI; designed to be driven by higher-level UI or MCP tools.

## Public Functions / Methods (semantic)

### Pure analysis (stateless, easily testable)
- `ByteStatistics::compute(data: bytes) -> ByteStatistics`
  Computes total count, min/max byte, mean, median, population std dev, Shannon entropy (0..8), unique byte count, mode and mode frequency. Ground truth: cross-check with numpy/scipy on the same bytes.
- `Histogram::compute(data: bytes) -> Histogram` + `.frequency(b)`, `.top_n(n)`, `.normalised()`
  256-bucket byte histogram. Ground truth: `collections.Counter` in Python.
- `HexDiff::compare_slices(left: bytes, right: bytes) -> Vec<DiffRegion>`
  Byte-by-byte diff, contiguous mismatching runs collapsed into regions with `{offset,len,left,right}`. Ground truth: trivial Python loop.
- `entropy(data, block_size) -> Vec<f64>` (free fn in lib root)
  Per-block Shannon entropy. Ground truth: scipy.stats.entropy or manual.

### HexBuffer construction
- `HexBuffer::new(Vec<u8>)`, `HexBuffer::empty()`, `HexBuffer::zeroed(len)` — constructors.
- `len()`, `is_empty()` — size queries.

### Read / Write / Edit (mutating, tracked by undo stack)
- `read(offset, len) -> &[u8]` — read up to len bytes (clamped).
- `write(offset, bytes) -> ()` — overwrite in place; records Replace edit.
- `insert(offset, bytes)` — splice insert; records Insert edit.
- `delete(offset, len)` — splice delete; records Delete edit.
- `read_padded(offset, len) -> Vec<u8>` — copy len bytes, zero-pad past end.
- `read_at_file_offset(FileOffset, len)`, `set_cursor_file_offset(FileOffset)` — typed-offset wrappers.
- `undo() -> bool`, `redo() -> bool`, `clear_history()` — history navigation. Ground truth: edit → undo → state == original.

### Block operations
- `fill(range, pattern)` — fill with repeating pattern.
- `reverse_range(range)` — in-place reverse.
- `shift_left/shift_right(range, amount, fill_byte)` — non-circular shift with fill.
- `rotate_left/rotate_right(range, amount)` — circular rotation.
  Ground truth: replicate in Python on the same bytes.

### Bitwise transforms
- `xor_range(range, key)` — repeating-key XOR. Ground truth: `bytes([b^k[i%len(k)] for ...])`.
- `and_range`, `or_range` — analogous AND/OR.
- `not_range(range)` — bitwise complement.
- `add_range(range, addend)` — wrapping byte add.
- `negate_range(range)` — two's complement byte negation.

### Search
- `search(pattern: &[u8]) -> Vec<usize>` — KMP byte search, all occurrences. Ground truth: Python `re.finditer(re.escape(pat))` or manual scan.
- `search_regex(pattern: &str) -> Vec<usize>` — byte-level regex NFA scan. Ground truth: Python `re` over bytes.
- `find_string(s, encoding) -> Vec<usize>` — encode string per `Encoding` (Utf8/Utf16Le/Utf16Be/Ascii/Latin1) then KMP. Ground truth: `s.encode(...)` then byte search.
- `find_hex_pattern("DE AD ? ? EF") -> Vec<usize>` — hex pattern with `?`/`??` wildcards. Ground truth: manual scan.
- `find_all(needle, &FindReplaceOptions{mode, wrap, limit}) -> Vec<FindResult>` — unified search across Exact/Regex/HexPattern modes with optional range limit.
- `replace_all(needle, replacement, opts) -> usize` — returns count of replacements (back-to-front to preserve offsets).

### Typed reads (struct overlay)
- `read_typed(offset, DataType) -> TypedValue` — reads U8/I8, U16/U32/U64/I16/I32/I64 (LE+BE), F32/F64 (LE+BE), Bytes(n), CStr (null-terminated UTF-8), Utf16(n code units, LE).
  Ground truth: Python `struct.unpack('<I', ...)` etc. — exact bit-level reference.

### Statistics + histogram on buffer
- `statistics() / statistics_range(range)` → ByteStatistics.
- `histogram() / histogram_range(range)` → Histogram.
- `entropy_blocks(block_size) -> Vec<f64>`.

### Address mapping
- `virtual_address(offset) -> u64` = base_address + offset.
- `offset_for_va(va) -> Option<usize>` = inverse, bounds-checked.

### Bookmarks
- `add_bookmark(offset, name, color)`, `remove_bookmark(offset) -> bool`, `nearest_bookmark(offset) -> Option<&Bookmark>`.

### Data annotations (typed overlays)
- `add_annotation(DataAnnotation)`, `remove_annotations_in(range)`, `annotations_overlapping(offset, len)`.

### MultiCursorState
- `new`, `count`, `cursors`, `cursor_mut(i)`, `add_cursor(offset)`, `remove_cursor(i)`, `move_all(delta, max)`, `collapse`, `sort`, `primary_offset`.

### HexDiff
- `compare(&HexBuffer, &HexBuffer) -> Vec<DiffRegion>`
- `compare_slices(&[u8], &[u8]) -> Vec<DiffRegion>`
- `apply_patch(&mut HexBuffer, &DiffRegion)` — applies right→left.

### Submodules (also pub)
- `hex_analysis`, `hex_bookmarks`, `hex_bookmark_manager`, `hex_diff`, `hex_disassembler`, `hex_editor_core`, `hex_search_engine`, `hex_undo`, `hex_undo_manager`, `hex_patch_manager`, `hex_selection`, `hex_goto_dialog` — additional managers / engines layered on top of HexBuffer.

## Existing MCP Tools
None. `Grep` over `rustre-mcp-tools/src/wire_tools.rs` for `rustre_hex` / `rustre-hex` returned no matches. The crate is currently **not** exposed via MCP — only used internally (or unused entry point). The only `hex_*` symbols in wire_tools are unrelated helpers (`hex_encode`, `hex_decode`, `parse_hex_bytes`) from other crates.

## Testable Functions (high-confidence ground truth)
1. `ByteStatistics::compute` — numeric, deterministic, replicable in Python (numpy + manual entropy).
2. `Histogram::compute` + `top_n` + `frequency` — `collections.Counter`.
3. `entropy(data, block_size)` / `entropy_blocks` — manual Shannon per block.
4. `HexBuffer::read_typed` for every `DataType` — Python `struct.unpack`.
5. `HexBuffer::search` (KMP), `search_regex`, `find_hex_pattern`, `find_string` (each Encoding) — Python `re`/manual.
6. `HexBuffer::xor_range / and_range / or_range / not_range / add_range / negate_range` — pure byte arithmetic.
7. `HexBuffer::fill / reverse_range / shift_left / shift_right / rotate_left / rotate_right` — pure transforms.
8. `HexDiff::compare_slices` — deterministic regions.
9. Undo/redo round-trip invariant: `state_after_undo(edit(s0)) == s0`.
10. `virtual_address` ↔ `offset_for_va` inverse property.

## Validator Strategy
Build a Python (or Rust integration-test) harness that:
1. Generates pseudo-random byte buffers (fixed seed) of various sizes (0, 1, small, 4 KiB, 1 MiB).
2. For each pure analysis function (stats, histogram, entropy, typed reads, bitwise/block transforms, search), computes the same result independently in Python (`struct`, `re`, `collections.Counter`, manual Shannon) and asserts equality (exact for ints/bytes, abs tol 1e-9 for floats).
3. Drives `HexBuffer` through a randomized edit sequence (insert/delete/write), records expected mirror state in Python `bytearray`, then validates `buffer.data == mirror` after every op, and that full undo restores `s0`.
4. For diff: generate two slightly perturbed buffers and check regions match a Python reference impl.
5. Since no MCP tools wire this crate, validation is library-level via `cargo test` or a dedicated `validation/` harness that links rustre-hex as a dependency and emits JSON for cross-check. Optionally, propose adding MCP tool wrappers (stats/histogram/entropy/typed-read/search) before user-facing validation.

Note: file paths referenced are absolute under `C:\Users\Fra\Desktop\RustRE\crates\rustre-hex\src\lib.rs` and `…\rustre-mcp-tools\src\wire_tools.rs`.
