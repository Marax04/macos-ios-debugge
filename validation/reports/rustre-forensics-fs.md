# rustre-forensics-fs

Crate path: `crates/rustre-forensics-fs`
Edition: 2024 — Version 0.1.0

## Purpose

MemProcFS-style virtual filesystem layer over forensic memory images and on-disk
filesystem artifacts. Exposes processes, network connections, kernel modules and
disk-resident filesystem metadata (NTFS, FAT32, ext4, Prefetch, Registry, LNK,
timelines) as a navigable virtual tree of files; supports export to a real
directory and (on Unix) optional FUSE mounting.

## Dependencies (Cargo.toml)

- `rustre-forensics` — base forensics types (`MemoryImage`, `OsType`, `ForensicsError`)
- `rustre-forensics-mem` — process/module/network analyzers (`LinuxAnalyzer`, `WindowsAnalyzer`, `ProcessInfo`, `ModuleInfo`, `NetworkConnection`)
- `anyhow`, `thiserror`, `serde`, `serde_json`, `bitflags`
- Unix-only: `fuser = "0.14"`, `libc`

## Modules

| Module | Role |
|---|---|
| `artifacts` | Forensic artifact aggregation |
| `carver` | File carving from raw byte streams |
| `export` | Export helpers (real-disk materialisation) |
| `ext4_reader` | ext4 superblock / inode parsing |
| `fat32_reader`, `fat32_deep`, `fat_analyzer` | FAT/FAT32 surface + deep analysis |
| `filesystem_timeline`, `timeline`, `timeline_builder` | MAC time timelines |
| `inode` | Inode abstractions |
| `lnk_parser` | Windows `.lnk` shortcut parser |
| `model` | Shared model types |
| `ntfs_reader`, `ntfs_analyzer`, `ntfs_mft_full` | NTFS volume + MFT parsing |
| `prefetch_analyzer` | Windows Prefetch (`.pf`) parser |
| `registry_hive_parser` | Windows Registry hive parser |
| `lib` | `MemFs`, `MemoryFs`, FUSE bridge, walkers |

## Public API (lib.rs)

### Error

`enum MemFsError` (thiserror) — variants: `Forensics(ForensicsError)`, `NotFound(String)`, `Io(std::io::Error)`, `NotADirectory(String)`, `Serialization(String)`. Implements `From<serde_json::Error>`.

### Node types

`enum MemFsNode { Directory(Vec<(String, Self)>), File(Vec<u8>), LazyFile(Box<dyn Fn() -> Vec<u8> + Send + Sync>) }`
- `fn read_bytes(&self) -> Option<Vec<u8>>`
- `const fn is_dir(&self) -> bool`
- `fn is_file(&self) -> bool`
- `fn children(&self) -> Option<Vec<&str>>`
- `fn child(&self, name: &str) -> Option<&Self>`

`enum MemFsContent { File(Vec<u8>), Dir(Vec<MemFsNodeV2>) }`

`struct MemFsNodeV2 { name: String, content: MemFsContent, inode: u64, created: u64, modified: u64 }`
- `fn new_file(name: impl Into<String>, content: Vec<u8>, inode: u64) -> Self`
- `fn new_dir(name: impl Into<String>, inode: u64) -> Self`
- `fn add_child(&mut self, child: Self)` (panics on file node)
- `fn find_child(&self, name: &str) -> Option<&Self>`
- `const fn size(&self) -> u64`
- `const fn is_dir(&self) -> bool` / `fn is_file(&self) -> bool`
- `fn find_by_inode(&self, ino: u64) -> Option<&Self>` (recursive)
- `fn readdir_entries(&self) -> Vec<(u64, String, bool)>`

### MemoryFs (V2 tree, FUSE-suitable)

- `fn new() -> Self` (+ `Default`)
- `fn build_process_tree(processes: &[ProcessInfo], modules: &[ModuleInfo]) -> Self`
  Layout: `/processes/<pid>_<name>/{info.txt,modules/<mod>.txt,handles.csv}`
- `const fn root(&self) -> &MemFsNodeV2`
- `fn into_root(self) -> MemFsNodeV2`

### MemFs (V1 tree, memory-image driven)

- `fn build(image: &dyn MemoryImage) -> Result<Self, MemFsError>`
  Layout: `/processes/<pid>_<name>/{info.json,cmdline.txt,modules.csv,memory/<start>_<end>.bin}`,
  `/network/connections.csv`, `/kernel/modules.csv`. Dispatches Linux vs Windows analyzer by `image.os_type()`.
- `fn read_file(&self, path: &str) -> Option<Vec<u8>>`
- `fn list_dir(&self, path: &str) -> Option<Vec<String>>`
- `fn resolve(&self, path: &str) -> Option<&MemFsNode>`
- `fn export(&self, real_path: &Path) -> Result<(), MemFsError>` (recursive materialise; LazyFile resolved on write)
- `const fn root(&self) -> &MemFsNode`

### Walkers (DFS iterators yielding `(path, is_dir)`)

- `struct MemFsWalker<'a>` — `fn new(fs: &'a MemFs) -> Self` ; `Iterator<Item=(String,bool)>`
- `struct MemFsV2Walker<'a>` — `fn new(fs: &'a MemoryFs) -> Self` ; `Iterator<Item=(String,bool)>`

### Export to real directory

`fn to_export_dir(node: &MemFsNodeV2, base: &Path) -> std::io::Result<()>`
- Path-traversal guard via `sanitize_export_name` (replaces `/`, `\`, `\0`; collapses `.`/`..` to `_`).

### FUSE (Unix only)

- `struct FuseMemFs { ... }` — `fn new(root: MemFsNodeV2) -> Self`
- Implements `fuser::Filesystem`: `lookup`, `getattr`, `readdir`, `read` (read-only). Inodes mapped via internal `HashMap<u64, Vec<u64>>` chain index; root inode = 1.
- File perms `0o444`, dir perms `0o755`; uid/gid = 0; `blksize` 512.
- `fn mount_memory_fs(fs_root: MemFsNodeV2, mountpoint: &Path) -> anyhow::Result<fuser::BackgroundSession>` — mounts RO with FSName `rustre-memfs`; drop the session to unmount.

### Non-Unix stub

`fn mount_memory_fs(_fs_root: MemFsNodeV2, _mountpoint: &Path) -> anyhow::Result<()>` — always `Err("FUSE filesystem requires Linux or macOS")`.

## I/O behavior

- Input: `&dyn MemoryImage` (for `MemFs::build`) or pre-collected `&[ProcessInfo]`/`&[ModuleInfo]` (for `MemoryFs::build_process_tree`). Disk-artifact submodules consume raw byte buffers/files.
- Output (virtual): tree of `MemFsNode`/`MemFsNodeV2`; file payloads as `Vec<u8>` (JSON/CSV/text/raw binary). `MemFs` memory regions are materialised eagerly via `image.read(start, len)` and stored as `File(data)`.
- Output (real): `MemFs::export` and `to_export_dir` recursively write the tree to disk, sanitising names for path-traversal.
- Output (mount): Unix-only FUSE read-only mount yielding a `BackgroundSession` handle.

## Behavior notes

- `MemFs::build` synthesises `cmdline.txt` from process name; emits `info.json` via `serde_json::to_vec_pretty`, with a textual fallback on serialization error.
- `MemoryFs::build_process_tree` does not filter modules per-PID (attaches all `modules` to every process).
- `build_handles_csv` is a placeholder: emits up to 8 synthetic rows derived from `proc.handle_count`.
- `sanitize_filename` keeps `[A-Za-z0-9._-]`, replacing the rest with `_`. `sanitize_export_name` is stricter against traversal.
- `MemFsNode::LazyFile` is invoked on every `read_bytes` call (no caching).

## Function count

Total `pub fn` declarations across the crate's `src/` (including submodules): **536**
- `lib.rs` alone: 30 public methods/functions across `MemFsNode`, `MemFsNodeV2`, `MemoryFs`, `MemFs`, walkers, `to_export_dir`, `mount_memory_fs`.
- Submodules with the largest public surface: `model` (47), `ntfs_analyzer` (43), `fat32_deep` (43), `fat32_reader` (40), `ext4_reader` (36), `fat_analyzer` (34), `lnk_parser` (32), `ntfs_mft_full` (31).

## Testability

`#[cfg(test)] mod tests` in `lib.rs` provides ~40 unit tests covering: root layout, `info.json` shape, CSV headers, walker traversal, CSV escaping, filename sanitization, `MemFsNode`/`MemFsNodeV2` helpers, `MemoryFs::build_process_tree`, `to_export_dir`, `mount_memory_fs` non-Unix error path, timestamp helper. Tests rely on `rustre_forensics_mem::build_mock_image(OsType::Windows)` — no external fixtures required. The crate is therefore self-testable via `cargo test -p rustre-forensics-fs`. A `tests/` integration directory also exists.
