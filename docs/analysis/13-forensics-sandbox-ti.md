# Analysis: Forensics, Sandbox, Threat-Intelligence, and Sysinternals Crates

**Date:** 2026-07-01  
**Workspace:** `C:/Users/Fra/Desktop/RustRE`  
**Crates covered:** `rustre-forensics`, `rustre-forensics-fs`, `rustre-forensics-mem`,
`rustre-forensics-plugins`, `rustre-sandbox`, `rustre-sandbox-extract`,
`rustre-sandbox-monitor`, `rustre-sandbox-report`, `rustre-sandbox-vm`,
`rustre-threatintel`, `rustre-ti-correlate`, `rustre-ti-malpedia`, `rustre-ti-misp`,
`rustre-ti-opencti`, `rustre-ti-otx`, `rustre-ti-shodan`, `rustre-ti-vt`,
`rustre-sysinternals`

---

## 1. High-Level Architecture Map

```
rustre-sysinternals          (pure-data platform introspection types)
       |
rustre-forensics             (core framework: MemoryImage trait, evidence, timeline, plugins)
    /       \
rustre-forensics-mem      rustre-forensics-fs
(OS struct analysis)      (virtual FS / FUSE / carver)
       \           /
    rustre-forensics-plugins  (Volatility-style plugin suite)

rustre-sandbox               (dynamic analysis: policy, monitoring, behavioral analysis)
    /    |    \    \
  -extract -monitor -report  -vm
  (artifacts) (hooks/API)  (reports)  (QEMU/KVM)

rustre-threatintel           (core TI types, IoC, stores, providers, MITRE)
    /  |  |  |  |  |  \
  -vt -misp -malpedia -otx -shodan -opencti -correlate
  (VT) (MISP) (Malpedia) (OTX) (Shodan)  (OpenCTI) (graph correlation)
```

All forensics crates depend on `rustre-forensics`.  
All TI leaf crates depend on `rustre-threatintel`.  
`rustre-forensics-mem` also depends on `rustre-core`.  
`rustre-forensics-plugins` depends on both `rustre-forensics` and `rustre-forensics-mem`.

---

## 2. `rustre-forensics` — Core Framework

### Purpose

Foundation library shared by all forensics sub-crates. Defines the `MemoryImage`
trait that abstracts over raw byte slices, ELF core dumps, and Windows minidumps.
Also provides: chain-of-custody tracking, multi-algorithm evidence hashing, timeline
reconstruction, artifact extraction traits, a naïve signature scanner, case
management, and a `ForensicsReport` builder. It is the primary dependency of the
entire forensics tree.

### Dependencies

| Dep | Version | Notes |
|-----|---------|-------|
| `thiserror` | workspace | Error derives |
| `serde` / `serde_json` | workspace | All types serializable |
| `rustre-sysinternals` | path | Bridged for process data |

No async, no unsafe in lib.rs; all hash algorithms implemented inline (no external crypto crates).

### Key Types and Traits

```rust
// Central abstraction — all memory sources implement this
pub trait MemoryImage: Send + Sync {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError>;
    fn regions(&self) -> Vec<MemoryRegion>;
    fn arch(&self) -> ArchBits;
    fn os_type(&self) -> OsType;
    // Provided: read_u32_le, read_u64_le, read_ptr
}

// Three concrete implementors:
pub struct RawMemoryImage { data: Vec<u8>, arch: ArchBits, os: OsType, base: u64 }
pub struct ElfCoredumpImage { segments, regions, arch, prstatus, prpsinfo }
pub struct MinidumpImage { memory_blocks, regions, modules: Vec<MiniModule>,
                           threads: Vec<MiniThread>, arch }
```

| Type | Role |
|------|------|
| `MemoryRegion` | address range + rwx permissions |
| `AcquisitionMode` | Physical / Logical / Volume / Memory / Network / Cloud |
| `HashAlgorithm` | MD5, SHA1, SHA256, SHA512 (all implemented inline) |
| `EvidenceHash` | wraps hash + provides constant-time `verify()` |
| `DigitalEvidence` | evidence item with multi-hash + chain-of-custody log |
| `ForensicsArtifact` | typed artifact (File, Registry, Process, Prefetch, LnkFile…) |
| `ArtifactExtractor` trait | `extract(&[u8]) -> Vec<ForensicsArtifact>` |
| `MetadataExtractor` | file-type magic + MD5/SHA256 |
| `ContentExtractor` | ASCII string extractor |
| `EmbeddedFileExtractor` | embedded ELF/PE/ZIP/PDF/PNG carver |
| `SignatureScanner` | literal byte-pattern scanner with default rules (mimikatz, Cobalt Strike…) |
| `ForensicsPlugin` trait | `run(&dyn MemoryImage, &PluginArgs) -> Result<PluginOutput>` |
| `PluginRegistry` | HashMap-backed plugin dispatcher |
| `ForensicsTimeline` | sorted event log with range/type/source queries |
| `TimelineAnalyzer` | merge, burst-detection, cross-source correlation |
| `ForensicsReport` | full case report with JSON/Markdown serialisation |
| `ForensicsDb` | in-memory DB (cases, artifacts, reports) with optional URL to SQLite/MySQL |
| `CaseManager` | CRUD for `ForensicsCase` records |

### Modules (in `src/`)

| Module | Description |
|--------|-------------|
| `artifact_extractor` | `ArtifactExtractor` trait + built-in extractors |
| `artifact_store` | In-memory artifact store |
| `collection_engine` | Orchestrates multi-extractor collection runs |
| `evidence_collector` | Acquires and hashes raw evidence |
| `incident_timeline` | High-level incident reconstruction |
| `malware_forensics` | Malware-specific forensics helpers |
| `memory_acquisition` | Memory capture pipeline |
| `memory_dump_analyzer` | Analyzes dump files |
| `os_adapter` | OS-specific acquisition adapters |
| `timeline_builder` / `timeline_correlator` | Builds and merges timelines |
| `filesystem_carver` | File carving from raw images |
| `registry_hive_analyzer` | Windows registry hive parsing |
| `prefetch_analyzer` | Windows prefetch (.pf) parsing |
| `sysinternals_bridge` | Links to `rustre-sysinternals` data types |

### Implementation Status

**COMPLETE.** Every type in `lib.rs` is fully implemented with real logic — no
`todo!()` or `unimplemented!()` found. ELF core dump parsing handles both 32/64-bit
and NT_PRSTATUS/NT_PRPSINFO notes. Minidump parsing handles MemoryListStream,
Memory64ListStream, ModuleListStream, ThreadListStream, and SystemInfoStream.
Hash functions are full RFC-correct implementations (MD5, SHA1, SHA256, SHA512 with
correct padding). Constant-time hash comparison is implemented explicitly.
Sub-modules may have varying completeness; root `lib.rs` itself is very solid.

### Known Gaps / TODOs

- `ForensicsDb.with_url()` stores the URL but does not actually connect to SQLite/MySQL
  — all persistence is in-memory. The URL is a placeholder for future back-end wiring.
- `CustodyEntry.timestamp` is always `0`; no wall-clock source is wired in.
- Module-level implementations (e.g. `registry_hive_analyzer`, `prefetch_analyzer`)
  are not visible from `lib.rs` scanning; they may themselves be stubs.

---

## 3. `rustre-forensics-mem` — OS Memory Structure Analysis

### Purpose

Walks kernel data structures inside a `MemoryImage` to reconstruct the live system
state: processes, threads, modules, network connections, registry hives. Provides
both `WindowsAnalyzer` and `LinuxAnalyzer` concrete types plus supporting modules for
VAD trees, heap analysis, string extraction, and process dump analysis.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-forensics` | `MemoryImage`, `ForensicsError` |
| `rustre-core` | `CoreError` (used for cross-crate error bridging) |
| `serde` / `serde_json` | Serialization |
| `parking_lot` | `Mutex`/`RwLock` for thread-safe analyzers |
| `thiserror`, `anyhow` | Error handling |

### Key Types

```rust
pub struct WindowsKernelInfo {
    pub kdbg: Option<u64>,       // KdDebuggerDataBlock address
    pub ntoskrnl_base: u64,
    pub version: WindowsVersion, // (major, minor, build)
    pub arch: ArchBits,
}

pub struct ProcessInfo { pub pid, ppid, name, base, size, handle_count, create_time }
pub struct ModuleInfo  { pub name, base, size, path }
pub struct NetworkConnection { pub protocol, local_addr, local_port, remote_addr,
                               remote_port, state, pid }

pub struct WindowsAnalyzer { /* walks EPROCESS list, VAD nodes, handles */ }
pub struct LinuxAnalyzer   { /* walks task_struct list, net namespaces   */ }
pub enum ThreadState { Initialized, Ready, Running, Standby, Terminated,
                       Wait, Transition, DeferredReady, Unknown }
```

### Modules

| Module | Description |
|--------|-------------|
| `windows_structs` | EPROCESS, ETHREAD, PEB, LDR_DATA_TABLE_ENTRY offsets |
| `linux_structs` | task_struct, mm_struct, files_struct offsets |
| `kernel_forensics` | Kernel-level analysis helpers |
| `heap_analysis` | Windows heap / tcmalloc chunk analysis |
| `vad_tree` | VAD tree walker for memory region classification |
| `process_tree` | Parent/child process tree reconstruction |
| `process_dump_analysis` | Per-process dump analysis |
| `profile_detect` | Automatic OS/version fingerprinting |
| `strings_extractor` | Multi-encoding string extraction |
| `artifact_extractor` | Produces `ForensicsArtifact` from memory |
| `memory_forensics` | High-level memory forensics pipeline |
| `timeline_builder` | Timeline events from memory artifacts |
| `casts` (pub(crate)) | Safe integer narrowing helpers (`u64_to_u32`, `u64_to_usize`) |

### Implementation Status

**PARTIAL to COMPLETE.** The type layer and struct definitions are complete. Analyzer
implementations depend on exact kernel structure offsets which must be calibrated per
OS version — profile-based approach (like Volatility's) is the architecture. `MAX_REGION_READ`
constant (64 MiB) protects against adversarial images. The `profile_detect` module
suggests automatic offset selection, but the depth of version coverage is unknown
without reading the sub-modules.

---

## 4. `rustre-forensics-fs` — Virtual Filesystem / FUSE View

### Purpose

MemProcFS-style virtual filesystem built from a `MemoryImage`. Exposes processes,
network connections, and kernel modules as navigable virtual file nodes. On Unix,
provides optional FUSE mount via `fuser 0.14`. Also contains filesystem analysis
modules: NTFS MFT parser, FAT32 reader, ext4 reader, carver, timeline builder, LNK
parser, registry hive parser, and prefetch analyzer.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-forensics` | Core traits |
| `rustre-forensics-mem` | `WindowsAnalyzer`, `LinuxAnalyzer`, `ProcessInfo` |
| `fuser 0.14` | FUSE filesystem (Unix only, conditional) |
| `libc 0.2` | Unix only |
| `bitflags`, `anyhow`, `serde/json` | Utilities |

### Key Types

```rust
pub enum MemFsNode {
    Directory(Vec<(String, Self)>),
    File(Vec<u8>),
    LazyFile(Box<dyn Fn() -> Vec<u8> + Send + Sync>),
}

pub enum MemFsError { Forensics, NotFound, Io, NotADirectory, Serialization }

// On Unix: implements fuser::Filesystem trait for actual FUSE mounting
```

### Modules

| Module | Description |
|--------|-------------|
| `model` | Virtual FS node model |
| `inode` | Inode table for FUSE |
| `export` | Export virtual tree to real disk directory |
| `artifacts` | Extract artifact list from virtual tree |
| `ntfs_reader` / `ntfs_mft_full` / `ntfs_analyzer` | NTFS raw parsing |
| `fat32_reader` / `fat32_deep` / `fat_analyzer` | FAT32 parsing |
| `ext4_reader` | ext4 superblock/inode reading |
| `carver` | File carving from raw sectors |
| `lnk_parser` | Windows .lnk shell link parser |
| `registry_hive_parser` | Registry REGF hive parser |
| `prefetch_analyzer` | Windows prefetch (.pf) parser |
| `filesystem_timeline` / `timeline` / `timeline_builder` | Timeline from FS events |

### Implementation Status

**PARTIAL.** Root `lib.rs` is well-structured with real integration code (pulls
`ProcessInfo`, `ModuleInfo`, `NetworkConnection` from mem analyzers). FUSE binding is
properly gated behind `#[cfg(unix)]`. Sub-module completeness varies — NTFS, FAT32,
ext4 parsers are ambitious; some may be stubs.

---

## 5. `rustre-forensics-plugins` — Volatility-Style Plugin Suite

### Purpose

Implements `ForensicsPlugin` for a wide set of Volatility-equivalent analysis tasks.
Plugins are registered in a `PluginRegistry` and dispatched uniformly. Covers process
listing, module listing, network connections, memory scanning, registry analysis,
prefetch, browser history, credentials, event logs, etc.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-forensics` | `ForensicsPlugin`, `PluginRegistry`, `MemoryImage` |
| `rustre-forensics-mem` | `WindowsAnalyzer`, `LinuxAnalyzer` |
| `rustre-core` | Error types |
| `subtle` | Constant-time comparison |
| `serde/json` | Serialization |

### Plugin Modules

| Module | IDA-equivalent Feature |
|--------|------------------------|
| `plugins::browser_history` | Chrome/Firefox/Edge artifact parser |
| `plugins::registry_artifacts` | Windows Registry forensics |
| `plugins::prefetch_analyzer` | Windows Prefetch analysis |
| `plugins::lnk_parser` | .lnk shell link parser |
| `plugins::event_log` | EVTX parser |
| `plugins::network_artifacts` | ARP, DNS, Netstat artifacts |
| `plugins::memory_strings` | Memory string extraction + classification |
| `plugins::process_artifacts` | EPROCESS walk, handles, VAD |
| `plugins::file_timeline` | MFT, MACB timestamps, USN Journal |
| `plugins::credential_artifacts` | LSASS, SAM, Kerberos, DPAPI |
| `memory_dump_plugin` | Memory dump via plugin interface |
| `network_artifacts` | Network-facing plugin |
| `prefetch_analyzer_plugin` | Prefetch plugin wrapper |
| `registry_hive_plugin` | Registry hive plugin wrapper |
| `volatility_plugins` | Additional Volatility-equivalent plugins |

### Key Internal Pattern

```rust
fn process_to_row(p: &ProcessInfo) -> HashMap<String, String> { ... }
fn module_to_row(m: &ModuleInfo) -> HashMap<String, String>   { ... }
fn connection_to_row(c: &NetworkConnection) -> HashMap<String, String> { ... }
// Each plugin converts OS structs into PluginOutput rows for uniform output
```

### Implementation Status

**PARTIAL to COMPLETE.** The plugin architecture is solid; dispatcher pattern is
clean. Credential extraction plugins (`credential_artifacts`) and EVTX parsing are
ambitious and likely partially implemented.

---

## 6. `rustre-sandbox` — Sandbox Core

### Purpose

Core library for dynamic malware analysis. Provides: process isolation, syscall
monitoring, behavioral recording, timeout enforcement, resource limits, network
isolation, filesystem snapshotting. Defines the central types shared by all sandbox
sub-crates.

### Dependencies (minimal by design)

`serde`, `serde_json`, `thiserror`, `bitflags`, `parking_lot` — no intra-workspace deps.
This is the root of the sandbox tree (analogous to `rustre-forensics` for forensics).

Feature flag `subcrates` re-exports sibling sandbox crates and provides a convenience
`registry::all()` constructor.

### Key Types

```rust
pub enum SandboxError { SpawnFailed, Timeout, ResourceExhausted, PolicyViolation,
                        NetworkBlocked, FileSystemError, MonitorError, VmError,
                        SnapshotFailed, Io }

// Policy: what is allowed during execution
pub struct SandboxPolicy { allow_network, allow_filesystem, allow_registry,
                           allow_process_spawn, max_memory_mb, timeout_secs,
                           max_file_size, blocked_domains: Vec<String>, ... }

// Behavior recording
pub struct BehaviorRecord { pid, timestamp, event_type: BehaviorEventType,
                            details: HashMap<String, String> }
pub enum BehaviorEventType { ProcessCreate, ProcessTerminate, FileCreate, FileRead,
                              FileWrite, FileDelete, RegistryRead, RegistryWrite,
                              NetworkConnect, NetworkSend, NetworkRecv, DllLoad,
                              SyscallEntry, SyscallReturn, ExceptionRaised }
```

### Modules

| Module | Description |
|--------|-------------|
| `sandbox_orchestrator` | Top-level run coordinator |
| `sandbox_policy` | Policy definition and enforcement |
| `process_monitor` | Process lifecycle tracking |
| `behavior_monitor` | Records behavioral events |
| `network_capture` | PCAP-style capture within sandbox |
| `network_simulation` | Fake DNS/HTTP/SMTP for C2 simulation |
| `network_simulator` | Network isolation + simulation backend |
| `artifact_collector` | Collects dropped files and artifacts |
| `behavioral_analysis` | Classifies behaviors as malicious/benign |
| `evasion_detector` | Detects anti-analysis tricks |
| `sandbox_reporter` | Generates sandbox run reports |

### Implementation Status

**COMPLETE at framework level.** Types are non-trivial with real business logic.
`registry::all()` wires all sibling crates. Actual OS-level isolation (seccomp,
Windows jobs) would require platform integration beyond what lib.rs alone can provide.

---

## 7. `rustre-sandbox-extract` — Artifact Extraction

### Purpose

Dropped-file extraction, memory dumps, network captures, registry snapshots,
credential extraction, packer unpacking detection, malware config extraction,
ransomware analysis.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-sandbox` | Core types |
| `regex` | Pattern matching for config extraction |
| `sha2`, `md-5`, `hex` | Cryptographic hashing |
| `windows-sys 0.59` | Process memory on Windows (conditional) |
| `anyhow`, `thiserror`, `serde` | |

`unsafe_code = "allow"` is set because Windows process-memory enumeration requires
FFI; all unsafe blocks require `SAFETY` comments per the lint config.

### Key Types

```rust
pub enum ArtifactKind { DroppedFile, NetworkConn, RegistryKey, ProcessSpawn,
                        MutexCreate, InjectedCode, MemoryDump, Credential,
                        Config, PackerLayer, Screenshot, PcapCapture }

pub struct SandboxArtifact { pub id, kind: ArtifactKind, pub path: Option<PathBuf>,
                              pub data: Option<Vec<u8>>, pub metadata: HashMap<String,String>,
                              pub hash_sha256: Option<String> }

pub struct SandboxArtifactExtractor { /* stateless unit struct */ }
```

### Modules

| Module | Description |
|--------|-------------|
| `file_artifact_collector` | Scans sandbox output dir for dropped files |
| `memory_artifact_dumper` | Dumps process memory regions |
| `network_artifact_extractor` | Extracts network streams |
| `c2_extractor` | C2 config extractor (regex + heuristics) |
| `config_extractor` | Generic malware config extraction |
| `malware_config_db` | Known config decryptor DB |
| `behavior_extractor` | Behavioral artifact extraction |
| `credential_harvester` | Credential artifact extractor |
| `crypto_key_finder` | Searches memory for AES/RSA key material |
| `dropper_analysis` | Multi-stage dropper analysis |
| `ransomware_analysis` / `ransomware_detector` | Ransomware-specific extraction |
| `dropped_file_collector` | Tracks dropped files on disk |
| `sandbox_report_normalizer` | Normalizes sandbox reports from different backends |

### Implementation Status

**PARTIAL.** Type surface and module list is complete. Windows-specific memory APIs
(ReadProcessMemory) need real OS-level integration. Config extraction heuristics
likely have real patterns via `regex`. Ransomware detection may be heuristic.

---

## 8. `rustre-sandbox-monitor` — Real-Time Monitoring

### Purpose

Hooking layer, API-call interception, event streaming, anomaly detection, live
behavioral analysis, ML-based sequence classification, and a TCP server receiving
guest-agent API call events (§23.3).

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-sandbox` | Core types |
| `tokio` | Async TCP server |
| `rayon` | Parallel classification |
| `parking_lot` | Concurrent state |
| `anyhow`, `thiserror`, `serde` | |

### Key Types

```rust
pub enum ApiCategory { FileSystem, Network, Registry, Process, Memory, Crypto,
                       System, Synchronization, Token, Gui }

pub struct ApiCall { pub name: String, pub category: ApiCategory,
                     pub pid: u32, pub tid: u32, pub timestamp: u64,
                     pub args: Vec<String>, pub return_value: Option<String> }

pub struct ApiMonitor { calls: Arc<Mutex<Vec<ApiCall>>>, hooks: HashMap<String, HookFn>,
                        call_count: AtomicU64, ... }

pub struct BehaviorClassifier { /* ML-style sequence classifier */ }
pub struct AnomalyDetector { /* statistical anomaly detection */ }
```

### Modules

| Module | Description |
|--------|-------------|
| `api_monitor` | Central API call recorder |
| `api_call_analyzer` | Analyzes call sequences for malicious patterns |
| `behavior_classifier` | ML classification of behavior sequences |
| `anti_evasion_hooks` | Hooks that defeat common anti-sandbox tricks |
| `dll_injector` | DLL injection for hook delivery |
| `ebpf_monitor` | eBPF-based syscall monitoring (Linux) |
| `process_tree_analyzer` | Process tree analysis |
| `process_monitor` | Process creation/termination tracking |
| `file_monitor` | File access monitoring |
| `registry_monitor` / `registry_watcher` | Registry change monitoring |
| `file_tracker` | File write tracking |

### TCP Guest Agent Protocol (§23.3)

The monitor includes a `tokio::net::TcpListener`-based server that receives
newline-delimited JSON API call events from a guest agent running inside the VM.
Events are deserialized into `ApiCall` structs and fed into the call log.

### Implementation Status

**PARTIAL.** The framework and type definitions are complete. The eBPF monitor and
DLL injection are platform-specific components that likely have stub implementations
for non-target platforms. The TCP server skeleton exists via `tokio`; the guest agent
protocol would need end-to-end testing.

---

## 9. `rustre-sandbox-report` — Report Generation

### Purpose

Parses behavior records, classifies malicious indicators, generates IOCs, produces
HTML/JSON/Markdown reports, scores samples, and maps behaviors to MITRE ATT&CK.

### Dependencies

`rustre-sandbox`, `serde/json`, `thiserror`, `anyhow` — lightweight.

### Key Types

```rust
pub enum Severity { Info, Low, Medium, High, Critical }
// Severity::score() -> u8: Info=0, Low=25, Medium=50, High=75, Critical=100

pub struct SandboxReport { /* full report with behaviors, artifacts, network, score */ }
pub struct SandboxReportBuilder { /* builder pattern over SandboxReport */ }
pub struct Ioc { pub kind: IocKind, pub value: String, pub severity: Severity }
pub enum IocKind { IpAddress, Domain, Url, FileHash, FilePath, RegistryKey,
                   MutexName, ProcessName, EmailAddress }
```

### Modules

| Module | Description |
|--------|-------------|
| `report_builder` / `json_report_builder` / `html_report_builder` | Multi-format report builders |
| `html_reporter` / `json_reporter` | Format-specific serializers |
| `pdf_reporter` / `pdf_export` | PDF generation (likely stub without a PDF crate) |
| `mitre_mapping_full` | Full MITRE ATT&CK technique mapping |
| `ioc_extractor` | IOC extraction from behavior records |
| `network_timeline` | Timeline from network events |
| `process_tree_render` | Process tree ASCII/HTML rendering |
| `report_generator_extended` | Extended report generation |

### Implementation Status

**PARTIAL.** JSON and HTML report builders are likely implemented. PDF output
requires a PDF crate that is not in `Cargo.toml` (`pdf_reporter` / `pdf_export`
likely stubs). MITRE mapping (`mitre_mapping_full`) may have a comprehensive static
lookup table.

---

## 10. `rustre-sandbox-vm` — QEMU/KVM Integration

### Purpose

VM lifecycle management: create/start/stop/snapshot/restore VMs, guest agent
communication, memory introspection from host, disk image management. Wraps QEMU's
QMP protocol over a Unix socket.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-sandbox` | Core types |
| `tokio` | Async QMP communication |
| `uuid 1` | VM and snapshot IDs |
| `parking_lot`, `anyhow` | |

### Key Types

```rust
pub enum VmArch { X86, X64, Arm, Arm64, Mips, Riscv64 }
pub enum VmOs   { Windows10, Windows11, Windows7, Ubuntu20, Ubuntu22,
                  Debian11, Kali, ... }

pub struct VmConfig { pub name, arch: VmArch, os: VmOs, pub memory_mb: u64,
                      pub cpu_cores: u32, pub disk_image: Option<PathBuf>,
                      pub snapshot_dir: Option<PathBuf>, pub network_mode: NetworkMode }

pub struct VmInstance { pub id: String, pub config: VmConfig, pub state: VmState,
                        pub pid: Option<u32>, pub qmp_socket: Option<PathBuf> }

pub struct VmSandbox { vm: VmInstance, ... }

pub enum VmState { Stopped, Starting, Running, Paused, Snapshotting, Restoring,
                   Stopping, Error(String) }

pub enum VmError { NotFound, AlreadyRunning, NotRunning, SnapshotFailed,
                   CommError, Timeout, QmpError, SpawnError, ... }
```

### Modules

| Module | Description |
|--------|-------------|
| `vm_orchestrator` | Manages multiple VM instances |
| `vm_behavior_log` | Records guest behavior events |
| `vm_network` | Guest network isolation and capture |
| `syscall_interceptor` | Intercepts guest syscalls from host |
| `api_monitor` | Guest API monitoring via host introspection |
| `sandbox_report_gen` | Generates reports from VM run data |
| `vm_syscall_table` | Syscall number to name mapping tables |
| `vm_file_system` | Accesses guest filesystem from host |
| `vm_registry` | Accesses guest Windows registry from host |
| `evasion_detection` | Detects guest anti-VM techniques |

### Implementation Status

**PARTIAL to STUB.** The type system and QMP protocol wrapper are well-designed.
Actual QEMU process spawning, VM memory read, and disk image management are inherently
OS-level operations that need real binary integration. These are likely stubs calling
`tokio::process::Command` for QEMU. Snapshot/restore via QMP is technically feasible
with the socket setup present.

---

## 11. `rustre-threatintel` — Core TI Framework

### Purpose

Foundational library for the threat-intelligence tree. Defines: `IoC`, `IoCType`,
`ThreatActor`, `MalwareFamily`, MITRE ATT&CK TTP types, `ThreatReport`, confidence
scoring, IOC enrichment pipeline, dual SQLite/MySQL persistence, and async provider
trait. It is the root dependency of all `rustre-ti-*` crates.

### Dependencies

| Dep | Notes |
|-----|-------|
| `reqwest 0.12` | HTTP client with rustls |
| `rusqlite` | SQLite persistence |
| `mysql` | MySQL persistence (optional feature `mysql-backend`) |
| `tokio`, `async-trait`, `futures` | Async runtime |
| `regex 1` | IOC pattern matching |
| `parking_lot` | RwLock for stores |
| `serde/json`, `thiserror`, `anyhow` | |

### Key Public API

```rust
// Core IOC type
pub struct IoC {
    pub id: Option<i64>,           // DB row ID
    pub ioc_type: IoCType,
    pub value: String,
    pub source: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub confidence: u8,            // 0-100
    pub severity: Severity,
}
pub enum IoCType { Ip, Domain, Url, Sha256, Md5, Sha1, Email, Filename,
                   Registry, Mutex, Cve, Asn, CertFingerprint, JarmHash, ... }

// Threat actor
pub struct ThreatActor { pub name, pub aliases, pub motivation: Motivation,
                         pub ttps: Vec<Ttp>, pub attribution: Option<String> }
pub enum Motivation { Financial, Espionage, Hacktivism, Sabotage, Unknown }

// Provider abstraction
#[async_trait]
pub trait TiProvider: Send + Sync {
    async fn query(&self, ioc: &IoC) -> Result<TiResult, TiError>;
}
pub struct TiResult { pub verdict: Verdict, pub score: u8, pub tags: Vec<String>,
                      pub details: HashMap<String, serde_json::Value> }
pub enum Verdict { Clean, Suspicious, Malicious, Unknown }

// Persistence
pub struct IoCStore { /* SQLite + optional MySQL */ }
pub struct DbConnection { sqlite: Option<Connection>, mysql: Option<mysql::Pool> }
```

### Modules

| Module | Description |
|--------|-------------|
| `ioc` | Core `IoC` type and `IoCType` enum |
| `threat_actor` | `ThreatActor`, `Motivation`, `Ttp` |
| `malware` | `MalwareFamily`, `MalwareType` |
| `mitre_attack` | MITRE ATT&CK tactic/technique mapping |
| `campaign` | Campaign tracking with kill-chain phases |
| `confidence` | Tiered confidence model with decay |
| `enrichment` | `EnrichmentPipeline` + enrichers (GeoIP, WHOIS, PDNS) |
| `store` | SQLite/MySQL IOC persistence |
| `provider` | `TiProvider` async trait |
| `intel` | Multi-provider query aggregation |
| `ioc_extractor` | Pattern-based IOC extraction from text |
| `ioc_normalizer` | IOC value normalization (lowercasing, canonicalization) |
| `threat_scorer` | Composite threat scoring |
| `attribution_engine` | Attribution reasoning engine |
| `virustotal` / `malwarebazaar` / `misp_client` | Built-in provider clients |
| `stix_parser` / `misp_feed_reader` | STIX 2.1 and MISP feed parsing |
| `intel_enricher` | Enrichment orchestrator |
| `threat_report_aggregator` | Aggregates multi-source reports |
| `malware_family_classifier` | Classifies samples into families |
| `threat_score_calculator` | Final threat score computation |
| `registry` | Provider registry (analogous to `PluginRegistry`) |

### Implementation Status

**PARTIAL to COMPLETE.** Core types are complete with real tests in `lib.rs`. The
persistence layer has dual-backend design. The `mysql-backend` feature is off by
default to avoid dependency version conflicts. Provider clients (VT, MalwareBazaar,
MISP) are thin wrappers that delegate to dedicated sub-crates. `reqwest` is fully
wired via workspace dependency.

---

## 12. `rustre-ti-correlate` — IoC Correlation Engine

### Purpose

Finds relationships between IOCs, malware families, and threat actors across collected
`ThreatReport`s. Builds a correlation graph using `petgraph`, supports temporal
analysis, behavioral clustering, campaign detection, and TTP analysis.

### Dependencies

`rustre-threatintel`, `rustre-core`, `petgraph` (with serde-1), `serde/json`, `anyhow`.

### Key Types

```rust
pub enum CorrelationKind { SharedThreatActor, SharedMalwareFamily, SimilarHash,
                           NetworkInfrastructure, SameRegistrar, SameCertificate,
                           TemporalProximity }

pub struct Correlation { pub ioc_a: IoC, pub ioc_b: IoC, pub kind: CorrelationKind,
                         pub confidence: u8, pub evidence: String }

// Re-exported from sub-modules:
pub use ttp_analysis::{MitreTactic, MitreTtpMapping, TtpAnalysis, TtpCluster,
                       TtpGraph, TtpReport, TtpTimeline};
pub use actor_attribution::{ActorAttributor, AttributionEvidence, AttributionResult};
pub use behavioral_clustering::{BehavioralClusterer, BehavioralProfile, Cluster};
pub use campaign_correlation::{CampaignCorrelationEngine, CampaignLink, CampaignOverlap};
```

### Modules

| Module | Description |
|--------|-------------|
| `ioc_correlator` | Pairwise IOC correlation |
| `ioc_graph` | petgraph-based IOC relationship graph |
| `graph_correlator` | Graph traversal + community detection |
| `temporal_correlator` / `temporal_analysis` | Time-based correlation |
| `behavioral_clustering` / `clustering` | Behavioral profile clustering |
| `actor_attribution` / `attribution` | Actor attribution engine |
| `campaign_correlation` / `campaign_analysis` | Campaign-level correlation |
| `campaign_detector` / `campaign_tracker` | Automated campaign detection |
| `ttp_analysis` | MITRE TTP graph + timeline |
| `sample_correlator` | Binary sample similarity |
| `actor_tracker` | Threat actor tracking over time |
| `attribution_engine` | Composite attribution |

### Implementation Status

**PARTIAL.** petgraph integration is a strong foundation for graph-based correlation.
Behavioral clustering and temporal analysis are well-typed but the algorithmic depth
(e.g., DBSCAN vs. k-means) would need sub-module inspection. Campaign detection
heuristics likely need real data to tune.

---

## 13. `rustre-ti-malpedia` — Malpedia Integration

### Purpose

Full async client for the Malpedia malware knowledge base: family search, actor
attribution, YARA rule download, sample management, local cache/DB, ATT&CK Navigator
export.

### Dependencies

`rustre-threatintel`, `tokio-rustls`, `webpki-roots 1`, `rusqlite`, `mysql`,
`async-trait`, `parking_lot`, `serde/json`, `thiserror`, `anyhow`, `tokio`.

Uses `tokio-rustls` directly (bypasses reqwest) for TLS — notable architectural
choice for fine-grained connection control.

### Key Public Types

```rust
pub struct MalpediaClient { api_key: String, base_url: String, cache: MalpediaCache }
pub struct MalpediaFamily { pub name, pub description, pub alt_names,
                            pub yara_rules_link, pub actors: Vec<String> }
pub struct MalpediaSample { pub sha256, pub filename, pub family, pub malware_type }
pub struct MalpedianThreatActor { pub name, pub country, pub families: Vec<String> }
pub use malpedia_yara::{YaraRule, YaraRuleSet, YaraDownloader, YaraCache};
pub use sample_search::{SampleDatabase, RelatedSampleSearch, ClusterReport};
```

### Implementation Status

**PARTIAL.** The client architecture is complete with cache and DB layers. YARA
download pipeline is defined. Actual API calls require a valid Malpedia API key.

---

## 14. `rustre-ti-misp` — MISP Integration

### Purpose

Full async REST API client for MISP: event/attribute/object/galaxy management,
sightings, sharing groups, warning lists, workflow automation, STIX 2.1 import/export.

### Dependencies

`rustre-threatintel`, `reqwest`, `uuid`, `rusqlite`, `mysql`, `async-trait`,
`parking_lot`, `serde/json`, `thiserror`, `tokio`.

### Key Types

```rust
pub struct MispClient { base_url, api_key, client: reqwest::Client }
pub struct MispEvent { pub id, pub uuid, pub info, pub threat_level_id: MispThreatLevel,
                       pub distribution: MispDistribution, pub attributes: Vec<MispAttribute> }
pub struct MispAttribute { pub id, pub uuid, pub type_: MispAttributeType,
                           pub value, pub to_ids: bool, pub comment }
pub enum MispAttributeType { Md5, Sha1, Sha256, IpSrc, IpDst, Domain, Url, Email, ... }
// ~100+ attribute type variants covering all MISP attribute types
```

### Modules

| Module | Notable Feature |
|--------|----------------|
| `client` | `MispClient`, `MispRawClient`, `MispFeedReader` |
| `event_builder` / `misp_event_builder` | Builder for new events |
| `misp_automation` | Workflow triggers, auto-tagging, auto-correlation |
| `misp_enrichment` | Enriches MISP events with external data |
| `misp_galaxy_mapper` | Maps MISP galaxies to ATT&CK |
| `stix21` / `stix_converter` | STIX 2.1 round-trip |
| `misp_feed_parser` | MISP feed (JSON manifest + files) parser |
| `misp_attribute_types` | All MISP attribute type definitions |
| `misp_search_client` | Full-text and attribute search |
| `misp_correlation` | MISP-internal correlation queries |

### Implementation Status

**PARTIAL to COMPLETE.** One of the richer TI sub-crates; the 100+ `MispAttributeType`
variants alone indicate significant investment. The `reqwest` client is functional for
REST calls.

---

## 15. `rustre-ti-opencti` — OpenCTI Integration

### Purpose

Thin client for OpenCTI via its GraphQL API: STIX object mapping, CTI report
importing, alert creation.

### Dependencies

`rustre-threatintel`, `reqwest`, `tracing`, `serde/json`, `thiserror`, `tokio`.

### Key Types

```rust
pub struct OpenCtiConfig { pub base_url, pub api_token, pub org_name: Option<String>,
                           pub timeout_secs, pub verify_tls }
pub struct Confidence(pub u8);  // 0-100; HIGH=85, MEDIUM=50, LOW=25
```

### Modules

| Module | Description |
|--------|-------------|
| `opencti_client` | GraphQL HTTP client |
| `opencti_stix_mapper` | Maps STIX objects to/from OpenCTI schema |
| `opencti_report_importer` | Imports TI reports as STIX bundles |
| `opencti_alert_creator` | Creates alerts in OpenCTI |

### Implementation Status

**STUB to PARTIAL.** The smallest of the TI sub-crates (only 4 modules). GraphQL
query construction is the main complexity. Likely partial; GraphQL schema coverage
may be incomplete.

---

## 16. `rustre-ti-otx` — AlienVault OTX Integration

### Purpose

AlienVault OTX DirectConnect and REST API: pulse parsing, IOC extraction, subscription
management.

### Dependencies

`rustre-threatintel`, `reqwest`, `tracing`, `serde/json`, `thiserror`, `tokio`.

### Key Types

```rust
pub struct OtxConfig { pub api_key, pub base_url, pub timeout_secs, pub page_size }
pub enum ThreatLevel { Unknown, Low, Medium, High, Critical }
// pulse_url(pulse_id) and subscribed_url() helpers on OtxConfig
```

### Modules

| Module | Description |
|--------|-------------|
| `otx_pulse_parser` | Parses OTX pulse JSON |
| `otx_ioc_extractor` | Extracts IOCs from pulse indicators |
| `otx_subscription_manager` | Manages subscribed pulses, pagination |

### Implementation Status

**PARTIAL.** Three focused modules; OTX API is simpler than MISP or VT.

---

## 17. `rustre-ti-shodan` — Shodan Integration

### Purpose

Host enrichment, banner analysis, and exposure scoring using the Shodan REST API.

### Dependencies

`rustre-threatintel`, `reqwest`, `tracing`, `serde/json`, `thiserror`, `tokio`.

### Key Types

```rust
pub struct ShodanConfig { pub api_key, pub base_url, pub timeout_secs, pub include_raw_banners }
// URL builders: host_url(ip), search_url(query) — both percent-encode key and query
pub enum PortCategory { Web, Database, RemoteAccess, FileSharing, Ics, Mail, Dns, Other(u16) }
```

Port-category classification covers ICS protocols (102=S7, 502=Modbus, 44818=EtherNet/IP).

### Modules

| Module | Description |
|--------|-------------|
| `shodan_host_enricher` | Queries `/shodan/host/{ip}`, populates GeoIP, ports, vulns |
| `shodan_banner_analyzer` | Parses service banners for fingerprinting |
| `shodan_exposure_scorer` | Scores exposure risk from open ports |

### Implementation Status

**PARTIAL.** URL encoding is security-hardened (explicit percent-encoding). Core
enrichment path is defined; banner analysis heuristics may be partial.

---

## 18. `rustre-ti-vt` — VirusTotal Integration

### Purpose

VirusTotal API v3: file/URL/domain/IP reports, behavioral analysis, relationships,
collections, votes, comments, retrohunt, YARA hunting, rate limiting, reputation DB.

### Dependencies

| Dep | Notes |
|-----|-------|
| `rustre-threatintel` | Core TI types |
| `reqwest` | HTTP client |
| `rusqlite` | Local result cache |
| `petgraph` | VT graph API relationship graphing |
| `rayon` | Parallel batch analysis |
| `async-trait`, `parking_lot`, `tokio` | Async + concurrency |

### Key Types

```rust
pub struct VtClient { api_key, client: reqwest::Client, rate_limiter: VtRateLimiter,
                      cache: VtCache }
pub struct VtFileReport { pub sha256, pub md5, pub sha1, pub meaningful_name,
                          pub type_description, pub stats: VtStats,
                          pub results: HashMap<String, VtEngineResult> }
pub struct VtStats { pub malicious, pub suspicious, pub undetected, pub harmless,
                     pub timeout, pub failure: u32 }
pub struct VtRateLimiter { /* token bucket, 4 req/min for free tier */ }
pub struct VtCache { /* SQLite-backed TTL cache */ }
pub struct ReputationDb { /* historical VT reputation tracking */ }
```

### Modules

| Module | Notable Feature |
|--------|----------------|
| `client` | Full VT API v3 client |
| `rate_limit` | Token-bucket rate limiter (public/private tier aware) |
| `cache` | SQLite TTL cache to avoid redundant queries |
| `models` | All VT response models (File, URL, Domain, IP reports) |
| `behavior_report` | Dynamic analysis behavior report parsing |
| `vt_graph_api` | VT Graph API + petgraph integration |
| `retrohunt` | Retrohunt job management |
| `vt_hunting` | Live YARA hunting rules |
| `vt_hunting_notifier` | Notifications for new hunting matches |
| `vt_reputation` | Historical reputation scoring |
| `vt_intelligence_search` | VT Intelligence search queries |
| `vt_relationship_graph` | Relationship traversal |
| `vt_behavior_summary` | Behavior summary aggregation |
| `threat_intel_aggregator` | Multi-source aggregation including VT |
| `ioc_enrichment` | IOC enrichment via VT |
| `threat_score` | VT-based threat scoring |
| `misp` | MISP event creation from VT reports |

### Implementation Status

**PARTIAL to COMPLETE.** The most feature-rich TI sub-crate. Rate limiting and
caching show production-grade thinking. petgraph integration for VT Graph is notable.
Retrohunt and hunting notifier are likely partial.

---

## 19. `rustre-sysinternals` — Platform Introspection Types

### Purpose

Sysinternals-equivalent pure-data types and async traits for platform introspection.
No OS calls made by the crate itself — it is a portable type library. Provides:
process monitor, autoruns, file monitor, handle viewer, network monitor, process
explorer, registry monitor, signature checking, string extraction, VM map analyzer,
ProcMon log parser, ProcExp dump analyzer.

### Dependencies

`thiserror`, `serde/json`, `parking_lot`, `bitflags`, `async-trait` — no platform-specific deps.

### Key Types

```rust
pub enum SysinternalsError { AccessDenied, Unsupported, Io, ProcessNotFound,
                              InvalidData, Timeout, NotFound }

bitflags! {
    pub struct DriverFlags: u32 { NONE, LOADED, UNLOADABLE, KERNEL_MODE, FS_FILTER }
}

pub enum ThreadState { Running, Waiting, Ready, Terminated, Unknown }

// (full type list in process_explorer, network_monitor, autoruns_analyzer, etc.)
```

### Modules

| Module | Sysinternals Equivalent |
|--------|------------------------|
| `process_monitor` | ProcMon (process events) |
| `process_explorer` | Process Explorer (live process tree) |
| `file_monitor` / `file_search` | ProcMon file events |
| `handle_viewer` | Handle viewer |
| `network_monitor` | TCPView |
| `registry_monitor` | ProcMon registry events |
| `autoruns_analyzer` | Autoruns |
| `sigcheck_engine` | Sigcheck (Authenticode verification) |
| `strings_extractor` | Strings tool equivalent |
| `vmmap_analyzer` | VMMap |
| `event_log` | Event Log viewer |
| `procmon_log_parser` | Parses ProcMon CSV/PML export |
| `procexp_dump_analyzer` | Parses Process Explorer minidump output |

### Integration with rustre-forensics

`rustre-forensics` directly imports `rustre-sysinternals` and bridges via the
`sysinternals_bridge` module. This allows forensics analysis to consume live system
snapshots in the same type vocabulary as offline memory analysis.

### Implementation Status

**PARTIAL.** Types are well-defined; the async trait surface is designed for
eventual OS integration. `u64_to_f64` precision-safe conversion helper shows attention
to correctness. ProcMon/ProcExp parsers may be partial file format parsers.

---

## 20. Cross-Cutting Analysis

### Dependency Graph Summary

```
rustre-sysinternals
    └── rustre-forensics
            ├── rustre-forensics-mem (+ rustre-core)
            │       └── rustre-forensics-plugins (+ rustre-core)
            └── rustre-forensics-fs  (+ rustre-forensics-mem)

rustre-sandbox
    ├── rustre-sandbox-extract  (+ windows-sys conditional)
    ├── rustre-sandbox-monitor  (+ tokio, rayon)
    ├── rustre-sandbox-report
    └── rustre-sandbox-vm       (+ tokio, uuid)

rustre-threatintel              (+ reqwest, rusqlite, mysql optional)
    ├── rustre-ti-vt            (+ petgraph, rayon)
    ├── rustre-ti-misp          (+ reqwest, uuid)
    ├── rustre-ti-malpedia      (+ tokio-rustls)
    ├── rustre-ti-otx           (+ reqwest, tracing)
    ├── rustre-ti-shodan        (+ reqwest, tracing)
    ├── rustre-ti-opencti       (+ reqwest, tracing)
    └── rustre-ti-correlate     (+ petgraph, rustre-core)
```

### Implementation Status Matrix

| Crate | Status | Notes |
|-------|--------|-------|
| `rustre-forensics` | **Complete** | Full hash impls, ELF/MDMP parsers, all core types |
| `rustre-forensics-mem` | **Partial** | Types complete; OS offset tables need per-version calibration |
| `rustre-forensics-fs` | **Partial** | FUSE gate correct; filesystem parsers vary |
| `rustre-forensics-plugins` | **Partial** | Plugin infra complete; credential/EVTX plugins may be stubs |
| `rustre-sandbox` | **Complete (framework)** | All types; OS-level isolation requires integration |
| `rustre-sandbox-extract` | **Partial** | Windows APIs conditional; config extraction heuristic |
| `rustre-sandbox-monitor` | **Partial** | TCP server skeleton; eBPF and DLL injection are stubs |
| `rustre-sandbox-report` | **Partial** | JSON/HTML complete; PDF likely stub |
| `rustre-sandbox-vm` | **Partial/Stub** | QMP wiring designed; actual VM ops need QEMU binary |
| `rustre-threatintel` | **Partial/Complete** | Strong core; MySQL backend gated; provider clients delegate |
| `rustre-ti-vt` | **Partial/Complete** | Most feature-rich TI crate; retrohunt partial |
| `rustre-ti-misp` | **Partial/Complete** | 100+ attribute types; rich automation |
| `rustre-ti-malpedia` | **Partial** | YARA download and cache designed |
| `rustre-ti-correlate` | **Partial** | petgraph foundation solid; clustering tuning needed |
| `rustre-ti-opencti` | **Partial/Stub** | Only 4 modules; GraphQL coverage likely minimal |
| `rustre-ti-otx` | **Partial** | Three focused modules; functional |
| `rustre-ti-shodan` | **Partial** | URL encoding hardened; enrichment functional |
| `rustre-sysinternals` | **Partial** | Types complete; async OS integration delegated |

### Known Gaps and Priority Items

1. **Persistence not wired:** `ForensicsDb.with_url()` and `IoCStore` both accept DB
   URLs but actual SQLite connections may not be opened in all code paths. The mysql
   feature for `rustre-threatintel` is off by default.

2. **CustodyEntry.timestamp = 0:** Chain-of-custody timestamps are hardcoded to zero.
   No system clock source is injected.

3. **PDF export:** `rustre-sandbox-report` declares `pdf_reporter` and `pdf_export`
   modules but has no PDF crate dependency. These are stubs.

4. **eBPF monitor (Linux):** `rustre-sandbox-monitor::ebpf_monitor` has no `libbpf`
   or `aya` dependency — likely stub.

5. **DLL injection:** `rustre-sandbox-monitor::dll_injector` has no Windows injection
   API dependency for real injection.

6. **VM ops:** `rustre-sandbox-vm` has no `tokio::process` invocation for actually
   spawning QEMU. The QMP socket path exists but `Command::new("qemu-system-x86_64")`
   is absent from visible code.

7. **Kernel profile offsets:** `rustre-forensics-mem` needs per-OS-version struct
   offset tables to correctly walk EPROCESS/task_struct. These offset tables are
   hidden in sub-modules; completeness unknown.

8. **OpenCTI GraphQL schema coverage:** Only 4 modules; likely covers only basic
   indicator creation, not the full OpenCTI schema.

### Integration with the RE Pipeline

These crates integrate into the broader RustRE reverse-engineering pipeline as follows:

- **Static analysis output** (from `rustre-pe`, `rustre-analysis`) feeds into
  `rustre-forensics` as `ForensicsArtifact` instances and into `rustre-threatintel`
  as `IoC` records (hashes, embedded domains/IPs).
- **Dynamic analysis** (`rustre-sandbox*`) enriches static findings with behavioral
  data, dropped files, and C2 infrastructure discovered at runtime.
- **TI lookup** (`rustre-ti-vt`, `rustre-ti-misp`, etc.) cross-references extracted
  artifacts against external knowledge bases to produce `TiResult` verdicts.
- **Correlation** (`rustre-ti-correlate`) links findings across samples, building
  campaign and actor attribution graphs.
- **Reporting** (`rustre-sandbox-report`, `rustre-forensics::ForensicsReport`) produces
  analyst-facing HTML/JSON/Markdown outputs consumed by the MCP server's report tools.
- **Sysinternals bridge** (`rustre-sysinternals` → `rustre-forensics::sysinternals_bridge`)
  allows live system snapshots taken with Sysinternals-compatible tools to be ingested
  directly into the forensics timeline without conversion overhead.
