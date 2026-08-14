# rustre-hex-pattern

Binary pattern matching library (IDA/HxD-style) for the RustRE workspace.

- **Crate**: `rustre-hex-pattern` v0.1.0 (edition 2024)
- **Path**: `crates/rustre-hex-pattern`
- **Public fn count (approx)**: 463 across 12 modules
- **Testable**: yes (extensive `#[cfg(test)]` module in `lib.rs`, in-memory SQLite supported)

## Dependencies

- `rustre-core`, `rustre-hex` (workspace) — KMP search, HexBuffer NFA regex
- `thiserror`, `serde`, `serde_json`, `serde-big-array`
- `rusqlite` (SQLite store), `mysql` (MySQL store)
- `rayon` (parallel scanning), `parking_lot` (locks)

## Modules

| Module | Role |
|---|---|
| `pattern_language` | High-level pattern DSL parser |
| `pattern_debugger` | Step-through match debugging |
| `pattern_evaluator` | Evaluation engine for compiled patterns |
| `pattern_exporter` | Multi-format export (JSON, IDA .pat) |
| `pattern_import` | Multi-format import |
| `pattern_stdlib` | Built-in/common signature library |
| `pattern_optimizer` | Pattern simplification + reorder |
| `multi_pattern_scanner` | Parallel/rayon scanning of many patterns |
| `pattern_diff` | Pattern comparison utilities |
| `pattern_search_engine` | Search backends |
| `wildcard_pattern_compiler` | Compile wildcard text -> CompiledPattern |

## Core API (lib.rs)

### Errors

`enum PatternError` (thiserror): `Parse{token,reason}`, `Database`, `NotFound`, `Empty`, `Regex`, `Export`, `Import`, `CaptureUndefined`.

### `PatternByte`

Enum: `Exact(u8) | Wildcard | Nibble{high:Option<u8>, low:Option<u8>}`.

- `matches(&self, byte: u8) -> bool`
- `is_wildcard(&self) -> bool` (const)
- `mask_byte(&self) -> u8` (const) — `0xFF` exact, `0x00` wildcard, partial for nibble
- `value_byte(&self) -> u8`

### `Pattern`

Fields: `bytes: Vec<PatternByte>`, `name: Option<String>`, `tags: Vec<String>`, `captures: Vec<NamedCapture>`, `comment: String`.

- `parse(s: &str) -> Result<Pattern, PatternError>` — IDA-style tokens: `??`, `?`, `AB`, `A?`, `?B`, single hex digit treated as high nibble.
- `matches(&self, data: &[u8], offset: usize) -> bool`
- `search(&self, data: &[u8]) -> Vec<usize>` — KMP if exact, otherwise anchor on first exact byte.
- `search_with_captures(&self, data: &[u8]) -> Vec<(usize, Vec<CaptureResult>)>`
- `with_capture(self, name, start, len) -> Self`
- `with_name(self, ..) / with_tag(..) / with_comment(..)`
- `to_bytes(&self) -> Option<Vec<u8>>` — `Some` only if no wildcards.
- `to_simd_form(&self) -> (Vec<u8>, Vec<u8>)` — `(values, masks)`
- `to_hex_string(&self) -> String` — `"DE AD ?? EF"`.
- `to_json / from_json` (serde JSON)
- `len / is_empty / exact_count / wildcard_count / specificity (f64 = exact/len)`

### `NamedCapture { name, start, len }` / `CaptureResult { name, offset, bytes }`

### `AlternationPattern { alternatives: Vec<Pattern>, name }`

Logical OR.

- `new(alts) (const)`, `parse("AA BB | CC DD")`, `with_name`
- `matches(data, off) -> bool`
- `search(data) -> Vec<usize>` (sorted, deduped)
- `len / is_empty` (const)

### `CompiledPattern`

Compiled form with `values`, `masks`, `first_exact` anchor.

- `compile(&Pattern) -> CompiledPattern`
- `matches(data, off) -> bool`
- `search(data) -> Vec<usize>` — KMP fast-path if all masks `0xFF`, anchored else, full-scan fallback.

### `MaskedPattern { bytes, mask, name }`

`(data[i] & mask[i]) == (bytes[i] & mask[i])`.

- `new(bytes, mask) -> Result<Self>` (length-checked)
- `from_pattern(&Pattern) -> Self`
- `matches / search / len / is_empty`

### `RegexPattern { pattern_str, name }`

Binary regex via `rustre_hex::HexBuffer::search_regex`.

- `new(pat)`, `with_name`
- `search(data) -> Result<Vec<usize>, PatternError>`

### `PatternGroup { name, patterns }` + `GroupMatch { pattern_index, pattern_name, offset }`

- `new(name)`, `add(Pattern)`
- `search_all(data) -> Vec<GroupMatch>` (sorted by offset)
- `any_matches(data, off) -> bool`
- `compile(&self) -> CompiledPatternGroup`
- `to_json / from_json`

### `CompiledPatternGroup { name, patterns }`

- `search_all(data) -> Vec<GroupMatch>`

### `SignaturePattern` (FLIRT-style)

Fields: `name, prologue: Pattern, crc16: u16, crc_len: u8, func_len: u32, module_name`.

- `new(name, prologue, crc16, crc_len, func_len)`, `with_module`
- `matches(data, off) -> bool` (prologue + CRC validation)
- `search(data) -> Vec<usize>`

### `crc16_ibm(data: &[u8]) -> u16`

CRC-16/IBM (poly 0x8005 reversed 0xA001, init 0, refin/refout true).

### `PatternDatabase` (SQLite, parking_lot::Mutex)

- `open(path) / open_in_memory() -> Result<Self>`
- `insert(&Pattern) -> Result<i64>`
- `search_by_name(name) -> Result<Vec<Pattern>>` (LIKE `%name%`, escaped)
- `search_by_tag(tag) -> Result<Vec<Pattern>>`
- `delete(id: i64) -> Result<()>`
- `count() -> Result<u64>`

Schema: `patterns(id PK, name, pattern(JSON of bytes), tags(CSV), comment)`.

### `MySqlPatternStore`

MySQL pool + in-memory `RwLock<HashMap>` cache.

- `connect(url) -> Result<Self>`
- `insert(&Pattern) -> Result<u64>` (invalidates cache)
- `search_by_name(name) -> Result<Vec<Pattern>>` (cached)

Schema: `patterns(id BIGINT AUTO_INC PK, name VARCHAR(255), pattern TEXT, tags TEXT, comment TEXT)` InnoDB utf8mb4.

### `PatternExporter`

- `export_json(&[Pattern]) -> Result<String>` (pretty)
- `import_json(&str) -> Result<Vec<Pattern>>`
- `export_ida_pat(&[Pattern]) -> String` — `"<hex> <name>"` per line
- `import_ida_pat(&str) -> Result<Vec<Pattern>>` — skips blank/`#` lines, infers name from trailing non-pattern token

## I/O Summary

| Input | Output |
|---|---|
| Pattern string (`"DE AD ?? ?F"`) | `Pattern` |
| Pipe-delimited (`"AA | BB"`) | `AlternationPattern` |
| `&[u8]` data + `Pattern` | `Vec<usize>` offsets (or with captures) |
| `Pattern` | JSON / IDA `.pat` text / SIMD `(values,masks)` |
| SQLite/MySQL file or URL | persistent pattern store |
| Binary regex string | `Vec<usize>` via NFA engine |

## Behavior Notes

- Empty pattern parse returns `PatternError::Empty`.
- Single hex digit treated as `Nibble { high: Some(d), low: None }` (matches `d0..dF`).
- `search` chooses the fastest backend: KMP for fully-exact, anchored linear scan for mixed wildcards, full enumeration when all wildcards.
- `CompiledPattern` masked compare uses `(b & mask) == (value & mask)`.
- SQL LIKE inputs are escaped with `\` to prevent wildcard injection (`%`, `_`, `\`).
- `PatternGroup::search_all` is single-threaded; `multi_pattern_scanner` provides rayon-parallel variant.
- All serializable types derive `Serialize`/`Deserialize` (JSON round-trip safe).
- `SignaturePattern::matches` requires both prologue match and CRC-16/IBM over the next `crc_len` bytes.

## Testability

- Unit-test module exists in `lib.rs` (PatternByte, Pattern parse/match/search, captures, alternation, compiled, etc.).
- `PatternDatabase::open_in_memory()` enables SQLite tests with no filesystem.
- `MySqlPatternStore` requires a live MySQL server (integration only).
