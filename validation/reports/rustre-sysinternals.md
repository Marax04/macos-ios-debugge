# rustre-sysinternals

Crate: `rustre-sysinternals` v0.1.0 (edition 2024) — Sysinternals-style platform-agnostic system introspection types and traits. Pure data; no OS calls performed by this crate.

## Cargo.toml

Workspace-inherited package metadata (license, description, repository, readme, keywords, categories, authors, lints).

Dependencies:
- `thiserror` — error derive
- `serde`, `serde_json` — serialization
- `parking_lot` — `RwLock` for the scanner cache
- `bitflags` — `DriverFlags`
- `async-trait` — async trait support

## Modules (pub mod)

- `event_log`
- `file_search`
- `process_monitor`
- `autoruns_analyzer`
- `file_monitor`
- `handle_viewer`
- `network_monitor`
- `process_explorer`
- `registry_monitor`
- `sigcheck_engine`
- `strings_extractor`
- `vmmap_analyzer`
- `procmon_log_parser`
- `procexp_dump_analyzer`

## Errors

- `enum SysinternalsError`: `AccessDenied`, `Unsupported`, `Io(String)`, `ProcessNotFound(u32)`, `InvalidData(String)`, `Timeout`, `NotFound(String)`.

## Bitflags / Enums

- `DriverFlags`: NONE / LOADED / UNLOADABLE / KERNEL_MODE / FS_FILTER (`Display`)
- `ThreadState`: Running, Waiting, Ready, Terminated, Unknown
- `ProcessStatus`: Running, Sleeping, Stopped, Zombie, Unknown
- `NetworkProtocol`: Tcp, Udp, Tcp6, Udp6, Raw
- `TcpState`: Listen, Established, TimeWait, CloseWait, Closed, SynSent, SynReceived, FinWait1, FinWait2, LastAck, Closing, Unknown
- `RegistryDataType`: RegSz, RegExpandSz, RegBinary, RegDword, RegQword, RegMultiSz
- `AutorunCategory`: 15 variants (LogonRegistry, RunOnce, Services, ScheduledTasks, StartupFolder, BrowserExtension, WmiSubscription, BootExecute, ImageFileExecution, AppCertDlls, LsaNotifications, Winlogon, ShellExecuteHooks, PrintMonitors, NetworkProviders)

## Data structs and pub fn

### `MemoryStats` (legacy) — fields: working_set, private_bytes, virtual_size, peak_working_set

### `MemoryInfo`
- `const fn new(vss, rss, peak_rss, shared, private, page_faults) -> Self`
- `fn rss_vss_ratio(&self) -> f64`

### `ModuleInfo`
- `fn new(base: u64, size: u64, name, path) -> Self`
- `const fn contains_addr(&self, addr: u64) -> bool`

### `ThreadInfo`
- `const fn new(tid, pid, start_address, priority, state) -> Self`

### `ProcessInfo`
- `fn new(pid, parent_pid, process_name) -> Self`
- `fn get_env(&self, key: &str) -> Option<&str>`
- `fn in_temp_dir(&self) -> bool`
- `fn is_system32(&self) -> bool`
- `fn to_csv_row(&self) -> String`
- `fn to_json(&self) -> Result<String, SysinternalsError>`

### `DriverInfo`
- `fn new(base, size, path, name, flags) -> Self`

### `HandleInfo`
- `fn new(handle, pid, type_name, object_address, access_mask) -> Self`

### `RegistryValue`
- `fn new(hive, key_path, value_name, data_type, data) -> Self`

### `NetworkEndpoint` (legacy)
- `fn new(pid, protocol, local_addr, local_port, remote_addr, remote_port, state) -> Self`

### `NetworkConnection`
- `fn new_tcp(pid, process_name, local_addr, local_port, remote_addr, remote_port, state) -> Self`
- `fn is_established(&self) -> bool`
- `fn is_listening(&self) -> bool`
- `fn to_csv_row(&self) -> String`

### `SystemSnapshot`
- `const fn empty() -> Self`

### Trait `SystemMonitor` (async_trait, Send + Sync)
- `fn list_processes() -> Result<Vec<ProcessInfo>, _>`
- `fn list_drivers() -> Result<Vec<DriverInfo>, _>`
- `fn list_handles(pid: Option<u32>) -> Result<Vec<HandleInfo>, _>`
- `fn network_connections() -> Result<Vec<NetworkEndpoint>, _>`
- `fn snapshot() -> Result<SystemSnapshot, _>`

### `InMemorySystemMonitor` (impl `SystemMonitor`)
- `fn new() -> Self`
- `fn add_process(&mut self, p)`
- `fn add_driver(&mut self, d)`
- `fn add_handle(&mut self, h)`
- `fn add_endpoint(&mut self, e)`

### `ProcessScanner`
- `fn new(refresh_interval: Duration) -> Self`
- `const fn scan() -> Result<Vec<ProcessInfo>, _>` (stub)
- `const fn get_process(_pid) -> Result<ProcessInfo, _>` (stub)
- `const fn find_by_name(_name) -> Result<Vec<ProcessInfo>, _>` (stub)
- `fn process_tree_from(processes) -> Result<ProcessTree, _>`
- `const fn process_tree() -> Result<ProcessTree, _>`
- `fn orphaned_processes(tree: &ProcessTree) -> Vec<u32>`
- `fn needs_refresh(&self) -> bool`
- `fn update_cache(&mut self, processes)`
- `fn cached(&self, pid) -> Option<ProcessInfo>`

### `ProcessTree` / `ProcessNode`
- `fn from_list(processes: &[ProcessInfo]) -> Result<Self, _>` (cycle-safe)
- `fn find(&self, pid) -> Option<&ProcessNode>`
- `fn depth_first_iter(&self) -> impl Iterator<Item = &ProcessNode>`
- `fn to_text(&self, indent: usize) -> String`
- `fn count(&self) -> usize`
- `fn max_depth(&self) -> usize`
- `ProcessNode::depth(&self) -> usize`

### `AutorunEntry`
- `fn new(category, location, name, image_path, launch_string) -> Self`
- `fn is_suspicious_path(&self) -> bool`
- `fn is_unsigned(&self) -> bool`
- `fn to_csv_row(&self) -> String`

### `AutorunDiff`
- `const fn is_clean(&self) -> bool`
- `const fn total_changes(&self) -> usize`

### `AutorunScanner`
- `const fn scan_all() -> Result<Vec<AutorunEntry>, _>` (stub)
- `const fn scan_category(_cat) -> Result<Vec<AutorunEntry>, _>` (stub)
- `fn filter_suspicious(&[AutorunEntry]) -> Vec<&AutorunEntry>`
- `fn filter_unsigned(&[AutorunEntry]) -> Vec<&AutorunEntry>`
- `fn diff(baseline, current) -> AutorunDiff`

### `CertInfo`
- `fn new(subject, issuer, serial, not_before, not_after, is_root) -> Self`
- `const fn valid_at(&self, unix_ts: u64) -> bool`

### `SignatureInfo`
- `fn unsigned(path) -> Self`
- `fn has_root_cert(&self) -> bool`

### `FileSignatureChecker`
- `fn check(path: &Path) -> Result<SignatureInfo, _>` (parses MZ/PE security dir)
- `fn hash_sha256(path) -> Result<String, _>` (builtin SHA-256)
- `fn hash_md5(path) -> Result<String, _>` (builtin MD5)
- `fn has_pe_signature(data: &[u8]) -> bool`

### `NetworkMonitor`
- `const fn snapshot() -> Result<Vec<NetworkConnection>, _>` (stub)
- `const fn connections_for_pid(_pid) -> Result<Vec<NetworkConnection>, _>` (stub)
- `const fn listening_ports() -> Result<Vec<NetworkConnection>, _>` (stub)
- `const fn connections_to_addr(_addr) -> Result<Vec<NetworkConnection>, _>` (stub)
- `fn filter_listening(&[NetworkConnection]) -> Vec<&NetworkConnection>`
- `fn filter_established(&[NetworkConnection]) -> Vec<&NetworkConnection>`
- `fn group_by_pid(&[NetworkConnection]) -> HashMap<u32, Vec<&NetworkConnection>>`
- `fn to_csv(&[NetworkConnection]) -> String`

### `ResourceUsage` — pure data struct (pid, cpu_percent, memory_bytes, ...)

## Notes

- Pure-data crate: many "scanner" entry points (`ProcessScanner::scan`, `AutorunScanner::scan_all`, `NetworkMonitor::snapshot`) are intentional stubs returning `Ok(Vec::new())` — actual OS access lives in higher layers.
- Includes self-contained SHA-256 and MD5 implementations (no extra deps).
- Two integration test files exist: `tests/blitz.rs`, `tests/blitz2.rs`.
- File is large (~3800 lines); only first 1630 lines fully inspected for this report; remaining modules (event_log, file_search, autoruns_analyzer, etc.) are documented via the module list above.

## Testability

Fully testable: the crate is pure data + builders + trait impls (`InMemorySystemMonitor`, `ProcessTree::from_list`, hash functions, PE signature parser, autorun diff). No OS calls required; integration tests already present.
