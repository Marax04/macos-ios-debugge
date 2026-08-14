# rustre-project — Analysis

## Purpose
Project file management and persisted session state for the RustRE platform. Provides directory-backed projects (`<root>/.rustre-project/`) containing a SQLite database, JSON metadata, and well-known subdirs (recordings, scripts, snapshots, views, ...). Manages binaries, functions, comments, xrefs, symbols, strings, bookmarks, triage results, patches, version snapshots, scripts, notes, layout, events; supports collaboration delta export/import; migrations; auto-save; multi-project management with optional tokio autosave task. Also exposes utility helpers: SHA-256 hex, Shannon entropy, binary classification (PE/ELF/Mach-O/WASM/DEX with arch detection).

## Public functions (key, by semantic role)

### Pure helpers (externally verifiable)
- **`sha256_hex(data: bytes) -> hex string`** — SHA-256 of input bytes as lowercase hex. Ground truth: Python `hashlib.sha256(data).hexdigest()`.
- **`shannon_entropy(data: bytes) -> f64`** — Shannon entropy in bits/byte over byte histogram. 0.0 for empty. Ground truth: Python `-sum((c/n)*log2(c/n) for c in Counter(data).values())`.
- **`classify_binary(bytes, &ProjectConfig) -> (format, arch)`** — Magic-based file format + architecture detection. Recognises `MZ`→PE (reads PE header machine field at e_lfanew for x86/x86_64/aarch64/arm), `\x7fELF`→ELF (EI_DATA endian + e_machine for x86/x86_64/arm/aarch64/riscv/mips), Mach-O magic (`feedface`/`cefaedfe`/`feedfacf`/`cffaedfe`/`cafebabe`→MachO-fat), `\0asm`→WASM/wasm32, `dex\n`→DEX/dalvik; otherwise `("unknown", config.default_arch || "unknown")`. Ground truth: `file(1)` / python-magic / lief / pefile.
- **`unix_to_iso8601`** (private but used in metadata): converts unix seconds → RFC3339 string.

### Migrations / schema
- **`get_migrations() -> Vec<Migration>`** — Returns 4 SQL migrations defining: binaries, functions, basic_blocks, edges, xrefs, symbols, types, variables, comments, bookmarks, strings, annotations, events, undo_log, scripts, notes, patches, version_history, layout_state, strings_fts (FTS5), triage_results. Verifiable by counting migrations (4) and ensuring versions 1..=4.
- **`run_pending_migrations(conn) -> u32`** / **`run_migrations(conn) -> ()`** — Applies un-applied migrations idempotently; records in `schema_migrations`. Verifiable: open empty SQLite, run, assert `schema_migrations` rows == 4.

### `Project` (directory-backed)
- **`Project::new(name, root_dir)`** — Creates `<root>/.rustre-project/` with subdirs `recordings,sandbox,attachments,workflows,scripts,reports,views,snapshots`, opens SQLite (WAL+FKs), runs migrations, writes `meta.json`. Errors if dir exists.
- **`Project::open(root_dir)`** — Opens existing project; errors `NotFound` if `.rustre-project` missing.
- **`save() / maybe_autosave() -> bool`** — Persist meta.json; autosave returns true if interval elapsed.
- **Binary mgmt:** `add_binary_from_path`, `add_binary` (alias), `list_binaries`, `find_binary_by_sha256`, `remove_binary` — dedup by sha256; classifies format/arch; stores canonical path and size.
- **Functions:** `add_function_record(binary_id,addr,name)`, `get_function_by_addr`, `list_functions(binary_id)` (ordered by addr), `rename_function`.
- **Comments:** `add_comment_record` (upsert), `get_comment`.
- **Xrefs:** `add_xref_record(binary_id,from,to,kind)`, `xrefs_to(addr)`, `xrefs_from(addr)`.
- **Events:** `add_event_record(kind, binary_id?, payload)`, `list_events(kind)`, `export_delta(since_ts)`, `import_delta(events) -> u64 imported`.
- **Bookmarks:** `add_bookmark(addr,label,color)`, `list_bookmarks`.
- **Symbols:** `add_symbol(addr,name,type,source)`, `search_symbols(prefix)` (LIKE prefix%).
- **Strings:** `add_string(addr,value,encoding)`, `search_strings_fts(query)` (FTS5 phrase match, double-quote escaped).
- **Triage:** `upsert_triage_result(scanner,verdict,score,details)`, `list_triage_results`.
- **Undo:** `append_undo_entry(...)`, `list_undo_log(session_id)`.
- **Patches:** `add_patch(addr,original,patched,desc)`, `list_patches`.
- **Version history:** `save_version_snapshot(binary_id,data,desc?) -> u64` (prunes to `MAX_VERSION_SNAPSHOTS=10`), `list_version_snapshots`.
- **Scripts:** `save_script(name,lang,body)`, `get_script(name)`, `list_scripts`.
- **Notes:** `save_note(title,body)`, `list_notes`.
- **Layout:** `save_layout(json)`, `load_layout`.
- **Statistics:** `binary_stats(binary_id) -> BinaryStats` (counts of functions, xrefs, symbols, comments, strings, bookmarks).
- **Export/Import:** `export_json(binary_id) -> json string` (metadata + functions), `import_binary_with_debug(path)` (adds binary + auto-detects `.pdb` sibling).
- **Accessors:** `name`, `metadata[_mut]`, `config[_mut]`, `project_dir`, `db_path`, `recordings_dir`, `sandbox_dir`, `attachments_dir`, `workflows_dir`, `scripts_dir`, `reports_dir`, `views_dir`, `snapshots_dir`.

### `BinaryProject` trait
Generic interface implemented by `Project`: `add_binary(path, sha256)`, `get_binary(id)`, `add_function`, `get_function`, `add_comment`, `add_xref`, `add_event(kind, actor, payload)` (wraps payload `{actor,data}`).

### `ProjectSession`
Runtime session attached to a project: `new(Arc<Mutex<Project>>)`, `open_view/close_view/is_view_open/open_view_count`, `activate_script/deactivate_script`.

### `ProjectManager`
Manages multiple open projects keyed by canonical path: `new`, `open(path)` (idempotent), `create(name,path)`, `close(id)`, `list`, `get`, `len`, `is_empty`, `save_all`, `recent_projects`, `spawn_autosave_task(interval_secs)` (tokio JoinHandle).

### Constants
`PROJECT_DIR_NAME=".rustre-project"`, `CURRENT_SCHEMA_VERSION=4`, `DEFAULT_AUTOSAVE_INTERVAL_SECS=300`, `MAX_VERSION_SNAPSHOTS=10`.

### Submodules (pub mod)
`analysis_cache, annotation_store, collaboration, export, plugin_manager, project_db_extended, project_migrator, project_serializer, project_templates, search, session, session_management, workspace, project_diff`. `session_management` re-exports: `ActiveSession, MultiSession, SessionExport, SessionHistory, SessionManagement, SessionRestore, SessionState`.

## Existing MCP tools (rustre-mcp-server)
Found in `crates/rustre-mcp-server/src/lib.rs`:
- `project.open` — open existing project at path
- `project.close` — close project
- `project.list_binaries` — list binaries in open project
- `project.info` — project metadata/info

No MCP tools currently expose: sha256_hex, shannon_entropy, classify_binary, function CRUD, comment/xref/symbol/string/bookmark/triage/patch/version-history/script/note/layout APIs, export_json, export_delta/import_delta, ProjectManager multi-project ops.

## Testable functions (externally verifiable ground truth)
1. **`sha256_hex(bytes)`** vs Python `hashlib.sha256`.
2. **`shannon_entropy(bytes)`** vs reference formula in Python.
3. **`classify_binary(bytes)`** — for known magic prefixes: `MZ...PE\0\0\x64\x86` → `("PE","x86_64")`; `\x7fELF` + e_machine 0x3e → `("ELF","x86_64")`; Mach-O magic → `("MachO",_)`; `\0asm` → `("WASM","wasm32")`; `dex\n` → `("DEX","dalvik")`. Cross-check via `file(1)`/lief.
4. **`get_migrations()` length == 4** and versions 1..=4 unique.
5. **`run_migrations(conn)` on fresh `:memory:` DB** → resulting schema contains all tables listed above and `schema_migrations` count == 4.
6. **`Project::new` then `Project::open`** roundtrips metadata (name, description, config fields) via meta.json.
7. **`Project::add_binary_from_path`** — sha256 of file matches `hashlib.sha256(file_bytes).hexdigest()`; dedup: adding same file twice keeps `list_binaries().len() == 1`.
8. **`save_version_snapshot` pruning** — adding > 10 snapshots keeps only most-recent 10.
9. **`unix_to_iso8601`** (indirect via `ProjectMetadata::new().created_at_iso`) — RFC3339 parseable, equals `datetime.utcfromtimestamp(created_at).isoformat()+"+00:00"`.

## Validator strategy
Two-tier validation:

**Tier A — pure functions (no I/O):** Build a small Rust harness (or use existing tests + a thin CLI) that calls `sha256_hex`, `shannon_entropy`, `classify_binary`, `get_migrations` on fixed input vectors and prints JSON. A Python validator (`hashlib`, manual entropy formula, `lief`/`pefile` for format, hard-coded migration count) compares outputs to ground truth.

**Tier B — Project CRUD via SQLite:** Drive `Project::new` in a tempdir, exercise `add_binary_from_path` (with a tiny crafted PE/ELF), `add_function_record`, `add_xref_record`, `add_comment_record`, `add_string`, `save_version_snapshot`(×12 to test pruning), `export_json`, `export_delta`/`import_delta` roundtrip, then validate by (1) re-opening the project and confirming state survives, (2) opening the underlying SQLite directly with `sqlite3` Python to confirm rows match expectations, (3) `meta.json` parseable as JSON with expected fields. SHA-256 cross-checked with Python hashlib on the same file bytes; classifier cross-checked with `lief` on the same crafted bytes.

Findings: massive functional surface (~70 pub fn on `Project`) vs only 4 MCP tools exposed (`project.open/close/list_binaries/info`) — large gap for MCP exposure of function/xref/comment/symbol/string/triage/patch/snapshot/script/note/event APIs.
