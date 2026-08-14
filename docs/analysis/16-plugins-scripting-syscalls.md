# Analysis: Plugin Infrastructure, Scripting Engines, and Syscall Subsystems

**Crates covered (13):** rustre-plugin-api, rustre-plugin-host, rustre-plugin-loader,
rustre-plugin-native, rustre-plugin-python, rustre-plugin-lua, rustre-script,
rustre-script-python, rustre-script-lua, rustre-script-rhai,
rustre-syscalls, rustre-syscalls-linux, rustre-syscalls-windows

---

## 1. rustre-plugin-api

### Purpose
Central ABI/trait-definition crate. Every other plugin crate depends on types declared here.
Defines the binary interface that native `.dll`/`.so` plugins must satisfy and the trait
hierarchy that host-side plugin objects implement.

### Key API Surface

```rust
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &Version;
    fn capabilities(&self) -> Vec<PluginCapability>;
    fn manifest(&self) -> PluginManifest;
    fn init(&self, ctx: &mut PluginContext) -> PluginResult<()>;
    fn unload(&self, ctx: &mut PluginContext);
    fn as_any(&self) -> &dyn Any;
}

// ABI entry point every native plugin must export
pub type PluginRegisterFn = unsafe extern "C" fn(*mut PluginRegistry);
pub const PLUGIN_MAGIC: [u8; 8] = *b"RUSTREP\0";
```

#### PluginCapability variants (22 total)

| Variant | RE relevance |
|---|---|
| Loader | binary format parsers |
| Architecture | ISA-specific logic |
| AnalysisPass | code analysis plugins |
| Decompiler | decompiler backends |
| DebugBackend | debugger adapters |
| UiPanel | GUI panels |
| ScriptExtension | scripting language support |
| MlilTransform / HlilTransform | IL lifting passes |
| TypeProvider | type system extensions |
| CallingConvention | ABI definitions |
| PlatformProvider | OS-level platform info |
| SignatureProvider | function signature libraries |
| ThemeProvider / SymbolProvider | cosmetic / naming |
| DataRenderer / HighlightProvider | display |
| Workflow | automation pipelines |
| SidebarProvider / NotificationHandler | UI peripherals |
| FileModifier / ProjectHook | project lifecycle |

#### Permission model

Four nested sub-structs compose `PluginPermissions`:
- `MemoryPermissions` — read/write/execute access flags
- `IoPermissions` — filesystem and network gates
- `RuntimePermissions` — subprocess, FFI, thread creation
- `AnalysisPermissions` — binary view access level

#### Declared submodules (18)

`abi`, `capabilities_extended`, `host_compat`, `plugin_context_api`,
`plugin_view_api`, `plugin_script_api`, `plugin_data_api`, `hot_reload`,
`platform_provider`, `plugin_events_full`, `plugin_marketplace`, `plugin_sdk`,
`sandbox`, `type_provider`, `plugin_manifest`, `plugin_permission_model`,
`plugin_ipc_protocol`, plus the root module.

### Internal Architecture

`PluginRegistry` is the runtime container for `Box<dyn Plugin>` objects.
`PluginRegistry::load_from_file` is a **deliberate stub**:

```rust
pub fn load_from_file(&mut self, _path: &Path) -> PluginResult<()> {
    Err(PluginError::LoadError(
        "requires 'dynamic-plugins' feature".to_string()
    ))
}
```

Dynamic loading is gated behind a cargo feature that is not enabled in the workspace.
The IPC layer (`plugin_ipc_protocol`) defines `InProcessIpcDispatcher` backed by
`HashMap<String, Box<dyn handler>>` for zero-cost in-process plugin calls.

### Dependencies

| Crate | Role |
|---|---|
| rustre-core | Version, binary-view types |
| thiserror | Error derive |
| serde / serde_json | Manifest serialisation |
| parking_lot | RwLock on registry |

### Implementation Status: **PARTIAL**

Framework is complete. Dynamic loading, marketplace, and several extended capability
modules are stubs or empty. The 18 declared submodules have not all been verified as
implemented; bodies for most were not readable within file-size limits.

### Gaps / TODOs
- `dynamic-plugins` cargo feature never enabled — no native plugin can be loaded at runtime.
- `plugin_marketplace` module exists but is unread; likely a stub.
- `hot_reload` module declared but body unknown.

---

## 2. rustre-plugin-host

### Purpose
Runtime orchestrator for all registered plugins. Manages lifecycle (init → running →
unload), persistence (SQLite), sandboxing, event bus, IPC dispatchers, health
monitoring, and dependency ordering.

### Key Types

```rust
pub struct PluginHost {
    registry:        HostPluginRegistry,
    plugins_by_name: RwLock<HashMap<String, Arc<dyn Plugin>>>,
    hook_registry:   HookRegistry,
    entries:         Vec<PluginEntry>,
    event_log:       VecDeque<PluginEvent>,
    db:              Mutex<Option<Connection>>,       // rusqlite
    settings_store:  HashMap<String, serde_json::Value>,
    sandbox_configs: HashMap<String, PluginSandbox>,
    health_map:      HashMap<String, PluginHealth>,
    ipc_dispatchers: HashMap<String, InProcessIpcDispatcher>,
    manifests:       HashMap<String, PluginManifest>,
}
```

SQLite schema (two tables):

```sql
CREATE TABLE IF NOT EXISTS plugin_entries (
    name TEXT PRIMARY KEY, version TEXT, source TEXT, state TEXT, loaded_at INTEGER
);
CREATE TABLE IF NOT EXISTS plugin_settings (
    plugin TEXT, key TEXT, value TEXT, PRIMARY KEY (plugin, key)
);
```

### Load-Source Dispatch

```rust
match source {
    PluginSource::DynLib { .. } =>
        Err("not yet implemented"),          // STUB
    PluginSource::BuiltIn { .. } =>
        Err("not found"),                    // STUB
    PluginSource::Inline(p) =>
        Ok(Arc::clone(p)),                  // WORKS
}
```

Only inline (code-registered) plugins actually load. File-system and built-in
resolution are unimplemented stubs.

### FilePluginRegistry

`FilePluginRegistry::scan_directory()` walks a directory for `*.toml` files and
deserialises each as a `PluginManifest33` (versioned manifest schema). This gives
a declarative, file-based plugin registry but without the ability to actually load
the compiled plugin object.

### Sandbox

```rust
pub struct PluginSandbox {
    allowed_paths:   Vec<String>,   // support ** glob
    allowed_hosts:   Vec<String>,
    max_memory_mb:   u64,
    allow_subprocess: bool,
    allow_ffi:       bool,
}

pub fn check_fs_read(&self, path: &Path) -> bool;
```

`check_fs_read` validates a requested path against the allow-list using glob
`**` wildcard matching.

### PermissionRequest enum

`FsRead{paths}`, `FsWrite{paths}`, `Network{hosts}`, `Subprocess{commands}`,
`FullMemoryAccess`, `UnsafeFfi`

### ExtensionPoint enum (notable variants)

`McpTool{tool_name}`, `LlmBackend` — shows the crate is aware of the MCP server
layer and LLM integration as first-class extension points.

### DependencyGraph

Full topological sort with cycle detection over `HashMap<String, Vec<String>>`
dependency edges; used to determine plugin init order.

### PluginHealth

```rust
pub struct PluginHealth {
    pub error_count:  u32,
    pub last_heartbeat: Instant,
    pub status:       HealthStatus,
}
```

### Declared submodules (17+)

`dynamic_loader`, `hot_reload_engine`, `plugin_event_bus`, `plugin_ipc`,
`plugin_lifecycle`, `plugin_permissions`, `plugin_sandbox`, `plugin_sandbox_full`,
`wasm_plugin_runtime`, `plugin_capability_model`, `plugin_registry_v2`,
`plugin_event_bus_v2`, `plugin_permission_system`, `plugin_sandbox_v2`,
`plugin_ipc_v2`, `native_plugin_loader`

### Dependencies

| Crate | Role |
|---|---|
| rustre-plugin-api | all plugin traits/types |
| rusqlite | settings + entry persistence |
| toml | manifest file parsing |
| windows-sys / libc | OS-level plugin probing |
| parking_lot | interior mutability |

### Implementation Status: **PARTIAL**

Lifecycle management, SQLite persistence, health tracking, dependency ordering,
sandbox path-checking, and IPC dispatcher plumbing are all substantially
implemented. Native loading, hot-reload, WASM runtime, and built-in registration
remain stubs.

### Gaps / TODOs
- `wasm_plugin_runtime`: module exists but body is unknown — WASM plugin support
  is planned but not confirmed operational.
- No `DynLib` loading path — `libloading` is not used here (only in plugin-native).
- v2 module variants (`plugin_registry_v2`, etc.) suggest ongoing refactoring with
  possible dead code.

---

## 3. rustre-plugin-loader

### Purpose
Thin adapter layer between file-system discovery and the plugin-api registry.
All implementation lives in three submodules; the crate itself only re-exports.

```rust
pub use file_loader::FilePluginLoader;
pub use manifest_loader::ManifestLoader;
pub use loader_registry::LoaderRegistry;
```

### Dependencies
Depends only on `rustre-plugin-api`. `unsafe_code = "deny"`.

### Implementation Status: **UNKNOWN (re-export only)**
Submodule bodies were not read. The crate compiles, suggesting non-trivial
implementations exist, but completeness cannot be confirmed without reading
`file_loader.rs`, `manifest_loader.rs`, and `loader_registry.rs`.

---

## 4. rustre-plugin-native

### Purpose
Native (shared-library) plugin loading via `libloading`. Provides the bridge between
the Rust ABI (`PluginRegisterFn`, `PLUGIN_MAGIC`) and OS dynamic linker.

```rust
pub use native_abi_bridge::NativeAbiBridge;
pub use native_plugin_loader::NativePluginLoader;
pub use native_symbol_resolver::NativeSymbolResolver;
```

### Dependencies

| Crate | Role |
|---|---|
| libloading | dlopen / LoadLibrary |
| thiserror | error types |
| parking_lot | shared library handle cache |

`unsafe_code = "allow"` — necessary for FFI.

### Implementation Status: **PARTIAL (assumed)**
`libloading` is present and the three types are re-exported. The actual `dlopen`
call, magic-byte validation, and `PluginRegisterFn` invocation are presumably in
the submodule bodies (not read). However, `rustre-plugin-host` never calls into
this crate for `DynLib` sources — the integration path is broken end-to-end.

### Gaps / TODOs
- Plugin-host's `DynLib` arm returns an error instead of delegating to
  `NativePluginLoader`. The two crates are not wired together.

---

## 5. rustre-plugin-python

### Purpose
Python-language plugin adapter. Exposes `rustre-plugin-api` types to Python code
via pyo3 bindings so that `.py` files can implement plugin logic.

```rust
pub use python_error_handler::PythonErrorHandler;
pub use python_re_module::PythonReModule;
pub use python_type_bridge::PythonTypeBridge;
```

### Dependencies

| Crate | Role |
|---|---|
| pyo3 (workspace) | CPython FFI |

`unsafe_code = "deny"` despite pyo3 relying on unsafe internally.

### Implementation Status: **UNKNOWN**
All implementation is in the three submodule bodies, which were not read.
The presence of `PythonReModule` suggests a `rustre` Python module mirroring
what `rustre-script-python` provides, but whether plugin registration
(implementing the `Plugin` trait from Python) is supported is unclear.

---

## 6. rustre-plugin-lua

### Purpose
Lua-language plugin adapter, parallel to rustre-plugin-python.

```rust
pub use lua_api_provider::LuaApiProvider;
pub use lua_plugin_loader::LuaPluginLoader;
pub use lua_state_manager::LuaStateManager;
```

### Dependencies

| Crate | Role |
|---|---|
| mlua (send feature) | Lua 5.4 runtime |
| thiserror | errors |
| parking_lot | state locking |

`unsafe_code = "deny"` (mlua handles unsafe internally).

### Implementation Status: **UNKNOWN**
Submodule bodies not read. `LuaStateManager` implies per-plugin Lua VM instances
with state isolation. `mlua` is used here (unlike rustre-script-lua which uses a
pure-Rust interpreter), suggesting real Lua 5.4 semantics.

---

## 7. rustre-script

### Purpose
Unified scripting abstraction layer. Aggregates all three scripting backends
(Python, Lua, Rhai) under a single `ScriptEngine` trait and provides the shared
infrastructure: `ScriptValue` type, `ScriptContext`, `ScriptPipeline`, `ScriptModule`,
sandbox policy, and all RE built-in function registrations.

### ScriptEngine trait

```rust
#[async_trait]
pub trait ScriptEngine: Send + Sync {
    fn name(&self) -> &str;
    fn file_extensions(&self) -> &[&str];

    async fn execute(&self, code: &str, ctx: &mut ScriptContext)
        -> Result<ScriptValue, ScriptError>;
    async fn execute_file(&self, path: &Path, ctx: &mut ScriptContext)
        -> Result<ScriptValue, ScriptError>;

    fn call_function(&self, name: &str, args: &[ScriptValue],
        ctx: &mut ScriptContext) -> Result<ScriptValue, ScriptError>;
    fn register_function(&mut self, name: &str, f: Box<dyn ScriptFn>)
        -> Result<(), ScriptError>;
    fn set_global(&mut self, name: &str, value: ScriptValue)
        -> Result<(), ScriptError>;
    fn get_global(&self, name: &str) -> Option<ScriptValue>;
    // + sandbox, introspection, hot-reload hooks
}
```

### ScriptValue

```rust
pub enum ScriptValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<ScriptValue>),
    Map(HashMap<String, ScriptValue>),
    Address(u64),        // virtual address for RE use
    Callable(String),    // function name reference
}
```

`Address` is a RE-domain extension beyond typical scripting value types.

### ScriptPipeline

```rust
pub struct ScriptPipeline {
    steps: Vec<PipelineStep>,  // engine + code pairs
}

impl ScriptPipeline {
    pub async fn execute_all(&mut self, ctx: &mut ScriptContext)
        -> Result<Vec<ScriptValue>, ScriptError>;
}
```

`execute_all` chains steps sequentially, injecting each step's result as `_prev`
into the next step's global scope. This enables multi-engine pipelines (e.g.
Rhai analysis → Python post-processing → Lua output formatting).

### RE Built-ins

`re_module()` returns a `ScriptModule` named `"re"` registering:
- `disassemble(addr, count)` — disassemble N instructions at address
- `read_bytes(addr, len)` — raw memory read
- `find_pattern(hex_pattern)` — byte pattern search
- `get_function_name(addr)` — symbol resolution
- `xrefs_to(addr)` / `xrefs_from(addr)` — cross-reference queries
- `get_strings()` — enumerate binary strings
- `entropy(addr, len)` — block entropy
- `get_imports()` / `get_exports()` — import/export tables

`register_builtins(ctx)` injects all of the above plus additional helpers
into any script context.

### SandboxPolicy

```rust
pub struct SandboxPolicy {
    pub allow_fs_read:  bool,
    pub allow_fs_write: bool,
    pub allow_network:  bool,
    pub allow_subprocess: bool,
    pub max_execution_steps: Option<u64>,
    pub allowed_paths:  Vec<PathBuf>,
}
```

### Dependencies

| Crate | Role |
|---|---|
| rustre-script-python | Python engine |
| rustre-script-lua | Lua engine |
| rustre-script-rhai | Rhai engine |
| async-trait | async in traits |
| tokio | async runtime |
| anyhow / thiserror | errors |
| serde / serde_json | value serialisation |
| parking_lot | engine registry lock |

### Implementation Status: **SUBSTANTIAL**

The abstraction layer, built-in registration, ScriptValue, ScriptPipeline, and
sandbox policy are all well-implemented. The 14 declared submodules are not all
verified, but the core integration surface is solid.

### RE Pipeline Fit
This crate is the scripting entry point for the MCP server and for any future
plugin that needs to run user-supplied code against a binary.

---

## 8. rustre-script-python

### Purpose
Python scripting backend providing two distinct engines: `PythonScriptEngine`
(full CPython via pyo3) and `PythonEngine` (pure-Rust Python subset interpreter).

### PythonScriptEngine (pyo3 path)

```rust
#[pyclass(name = "BinaryView")]
pub struct BinaryView {
    name: String,
}
// stub: functions() and strings() return empty vecs
```

`create_rustre_module(py)` registers a `rustre` module in `sys.modules` with:
- `rustre.log(msg)` — log to host
- `rustre.version()` → string
- `rustre.current_binary()` → `BinaryView` stub

### PythonEngine (pure-Rust interpreter)

A hand-written recursive-descent parser and tree-walking evaluator.

#### AST coverage

| Category | Variants |
|---|---|
| PyStmt | 13 (Assign, If, While, For, Def, Return, Import, Print, Pass, Break, Continue, Expr, Try) |
| PyExpr | 12 (Literal, Var, BinOp, UnOp, Call, Index, Attr, List, Dict, Tuple, Lambda, Comprehension) |
| PyBinOp | 17 (arithmetic, comparison, logical, bitwise, string concat, power) |
| PyUnOp | 2 (Neg, Not) |

```rust
pub struct PythonEngine {
    max_steps: u64,   // 100_000
    globals: HashMap<String, PyValue>,
    functions: HashMap<String, PyFunctionDef>,
}
```

`PyValue`: None, Bool, Int(i64), Float(f64), Str, List, Dict, Tuple, Bytes, Function.

### Dependencies

| Crate | Role |
|---|---|
| pyo3 0.23 + auto-initialize | CPython FFI |
| bitflags | permission flags |

`unsafe_code = "allow"` (pyo3 requires it).

### Implementation Status: **PARTIAL**

CPython path works but `BinaryView` is a stub with no real data. Pure-Rust engine
covers the common Python subset but lacks generators, decorators, class definitions,
exception chaining, and standard library modules.

### Gaps / TODOs
- `BinaryView.functions()` and `.strings()` return empty — no connection to
  the actual binary analysis layer.
- No `import` resolution in the pure-Rust engine beyond built-in names.
- 14 submodules declared — only the root was read.

---

## 9. rustre-script-lua

### Purpose
Lua scripting backend. Implements a complete pure-Rust Lua 5.x subset interpreter
**without** using mlua for execution (mlua appears in Cargo.toml but is unused
at runtime for eval). Provides binary analysis built-ins accessible from Lua.

### Architecture

```
LuaSourceParser (recursive descent)
       ↓ produces
LuaStmt / LuaExpr AST
       ↓ evaluated by
LuaEngine (tree-walk interpreter)
       ↓ calls
LuaContext stdlib (rustre.*, re.*, dbg.*)
       ↓ delegates to
STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> (global binary store)
```

#### AST coverage

| Category | Variants |
|---|---|
| LuaStmt | 10 (Local, Assign, If, While, For, Function, Return, Break, Do, Call) |
| LuaExpr | 10 (Nil, Bool, Number, String, Var, BinOp, UnOp, Call, Index, Function) |
| BinOp | 15 (arithmetic, comparison, logical, concat, length) |
| UnOp | 3 (Neg, Not, Len) |

#### Interpreter limits

```rust
pub struct LuaEngine {
    max_steps:  u64,   // 100_000
    call_depth: u32,   // max 200
}
```

Full scope save/restore on function calls; closures capture by reference to
outer scope map.

### Binary Store API (from Lua)

```lua
rustre.load_binary("path/to/file")   -- load into named slot
rustre.get_info("id")                -- format/arch/entry_point/size
re.disasm("id", 0x1000, 10)         -- x86 decode, N instructions
re.find_strings("id")               -- ASCII min_len=4
```

`store_load_binary(path)` enforces a sandbox gate:
```rust
let canonical = fs::canonicalize(path)?;
if !canonical.starts_with(cwd) { return Err(...); }
```

`lua_detect_format_string` magic-byte dispatch:

| Magic | Format |
|---|---|
| `MZ` | PE |
| `\x7fELF` | ELF |
| `\0asm` | WASM |
| `dex\n` | DEX |

#### Stdlib surface (registered as Function sentinels)

- `rustre.*` (20+ functions): log, version, load_binary, get_info, hex, unhex, …
- `re.*` (10 functions): disasm, find_strings, find_pattern, entropy, …
- `dbg.*` (15 functions): set_breakpoint, read_mem, write_mem, step, …

### `casts` module

All numeric conversions are explicit named `const fn`s:
`u64_to_i64`, `i64_to_u64`, `f64_to_i64`, `i64_to_f64`, `usize_to_u64`, etc.
No implicit Lua-style coercion; the engine is strict about types.

### Dependencies

| Crate | Role |
|---|---|
| mlua (lua54+vendored) | bundled for possible future use; not used in eval |
| thiserror / anyhow | errors |

### Implementation Status: **SUBSTANTIAL**

Interpreter is functional for common Lua idioms. Binary analysis builtins work
end-to-end (load → disasm → strings). `dbg.*` functions are registered as
sentinels but their implementations in submodules were not verified.

### Gaps / TODOs
- `mlua` dependency is unused at eval time — either migrate to mlua for full Lua 5.4
  compatibility, or remove the dependency.
- `dbg.*` functions beyond registration are unverified.
- No metatables, no coroutines, no `pcall`/`xpcall` (error propagation is Rust panics).
- 16 submodules declared; only root was read.

---

## 10. rustre-script-rhai

### Purpose
Rhai scripting backend. The most complete scripting engine: uses the real
`rhai 1.20` crate with sync and internals features. Provides RE-specific modules
for binary analysis, event bus, and SHA-256 hashing.

### Architecture

```rust
pub struct RhaiScriptEngine {
    engine:      rhai::Engine,
    binary_store: BinaryStore,   // Arc<Mutex<HashMap<String, Vec<u8>>>>
    state:       Arc<Mutex<RustreState>>,
}
```

`RhaiScriptEngine::with_re_api()` and `::with_rustre_module()` are the two standard
constructors, differing in which module set they register.

### re Module

```rust
// registered free functions on engine:
load_binary(path: &str) -> bool
get_info(id: &str) -> Map
find_pattern(id: &str, pattern: &str) -> Array
// pattern: space-separated hex with "??" wildcards
sha256_file(path: &str) -> String
entropy(id: &str, offset: i64, len: i64) -> f64
entropy_classify(e: f64) -> String
```

`entropy_classify` thresholds:

| Range | Label |
|---|---|
| < 1.0 | "very low" |
| < 3.5 | "low" |
| < 6.0 | "medium" |
| < 7.2 | "high" |
| ≥ 7.2 | "very high" |

`find_pattern_impl` supports `??` as single-byte wildcards in a space-separated
hex string (e.g. `"48 8B ?? 00 ?? FF"`).

### rustre Module (static Rhai module)

Sub-modules registered: `actions`, `events`, `utils`.

```rust
// rustre.log(msg)
// rustre.version() -> str
// rustre.actions.push(action_name)
// rustre.events.subscribe(name, fn_ptr)
// rustre.events.emit(name, data)
// rustre.utils.hex(bytes) -> str
```

### Event Systems

Two parallel event implementations:

1. **EventBus** — `Vec<(String, AST)>`: dispatch re-evaluates stored AST with
   `event_data` scope variable injected.

2. **EventHookSystem** — `FnPtr`-based: `register_script(fn_name, AST)` + `emit()`.

### num_cast Module

All numeric conversions exposed as named Rhai functions:
`lossy_u64_to_f64`, `trunc_f64_to_i64`, `sat_usize_to_i64`, etc.
Explicit casts avoid silent truncation bugs in analysis scripts.

### RustreState

```rust
pub struct RustreState {
    pub log_messages:    Vec<String>,
    pub actions:         Vec<String>,
    pub event_listeners: HashMap<String, Vec<String>>,
}
```

### Dependencies

| Crate | Role |
|---|---|
| rhai 1.20 (sync + internals) | script engine |
| sha2 | SHA-256 for binary hashing |
| parking_lot | BinaryStore locking |

### Implementation Status: **MOST COMPLETE of all engines**

Real engine (not hand-written interpreter). `find_pattern` with wildcards, `entropy`,
`entropy_classify`, SHA-256, event bus, and per-engine binary store isolation are
all implemented and functional. The 15 declared submodules were not fully read but
the root module alone provides substantial RE capability.

### Gaps / TODOs
- Two parallel event systems (EventBus + EventHookSystem) — unclear which is
  the canonical one; the other is likely dead code.
- No `disassemble` built-in at Rhai level (available in rustre-script's re_module
  but requires engine-side wiring).
- 15 submodules declared; only root read.

---

## 11. rustre-syscalls

### Purpose
Core syscall type library. Provides the shared type system (OS families,
architectures, argument types, risk levels, categories), static syscall tables
embedded as `&[(u64, &str)]`, context-aware argument decoding, and an in-memory
`SyscallDatabase` with multiple query modes.

### Type Hierarchy

```rust
pub enum OsFamily    { Linux, Windows, MacOs, FreeBsd, OpenBsd }
pub enum SyscallArch { X86_64, X86, Arm64, Arm, Mips, Riscv64 }
pub enum RiskLevel   { Benign, Low, Medium, High, Critical }
pub enum SyscallCategory {
    FileSystem, Process, Memory, Network, Ipc, Signal,
    Device, Time, Security, User, System, Unknown
}
```

### SyscallType — argument type encoding (25+ variants)

| Variant | Meaning |
|---|---|
| `Int`, `UInt`, `Long`, `ULong` | standard integer args |
| `Ptr`, `Buffer{size_arg}` | raw pointer and sized buffer |
| `Fd` | file descriptor (decoded as stdin/stdout/stderr) |
| `FdArray` | array of fds |
| `Socklen`, `IpAddr`, `SaFamily` | socket types |
| `Mode` | permission bits (displayed as octal) |
| `ClockId` | clock identifier (named CLOCK_REALTIME etc.) |
| `Signal` | signal number (named SIGKILL, SIGSEGV etc.) |
| `Errno` | errno value (named ENOENT, EACCES etc.) |
| `Pid`, `Uid`, `Gid` | process/user/group IDs |
| `Size`, `Offset` | size_t / off_t |
| `Flags` | bitmask |

### decode_arg_value

Context-aware decoding with named constants:

```rust
pub fn decode_arg_value(ty: &SyscallType, raw: u64) -> DecodedArg {
    // fd 0/1/2 → "stdin"/"stdout"/"stderr"
    // signal 9 → "SIGKILL", 11 → "SIGSEGV", etc.
    // errno 2 → "ENOENT", 13 → "EACCES", etc.
    // clock 0 → "CLOCK_REALTIME", 1 → "CLOCK_MONOTONIC", etc.
    // mode displayed as octal "0644"
    // IP address formatted as dotted-quad
    // NULL pointer shown as "NULL"
}
```

### Static Syscall Tables

Three tables embedded as `&[(u64, &str)]`:
- `LINUX_X86_64_ENTRIES`: NR 0–329 (read, write, open, … through all common calls)
- `LINUX_ARM64_ENTRIES`: AArch64 NR set
- `WINDOWS_X64_ENTRIES`: NT syscall stubs:
  `NtReadFile=0, NtWriteFile=1, … NtCreateThreadEx=0xE, NtAllocateVirtualMemory=0xF, …`

### SyscallDatabase

```rust
pub struct SyscallDatabase {
    entries:     HashMap<(OsFamily, SyscallArch, u64), Syscall>,
    name_index:  HashMap<String, Vec<(OsFamily, SyscallArch, u64)>>,
}

impl SyscallDatabase {
    pub fn insert(&mut self, syscall: Syscall);
    pub fn merge(&mut self, other: SyscallDatabase);
    pub fn lookup(&self, os: OsFamily, arch: SyscallArch, nr: u64)
        -> Option<&Syscall>;
    pub fn lookup_by_name(&self, name: &str)
        -> Vec<&Syscall>;
    pub fn all_for(&self, os: OsFamily, arch: SyscallArch)
        -> impl Iterator<Item = &Syscall>;
    pub fn all_for_category(&self, cat: SyscallCategory)
        -> impl Iterator<Item = &Syscall>;
    pub fn high_risk(&self) -> impl Iterator<Item = &Syscall>;
}
```

### SyscallCall — live call record

```rust
pub struct SyscallCall {
    pub syscall:   Syscall,
    pub args:      Vec<u64>,   // raw register values
    pub ret:       i64,
    pub timestamp: u64,        // nanoseconds
    pub pid:       u32,
    pub tid:       u32,
    pub tags:      Vec<String>,
}
```

`Syscall::prototype()` returns a C-like prototype string for display.

### Declared submodules (15)

`syscall_emulator`, `syscall_tracer`, `syscall_decoder`, `syscall_dispatcher`,
`syscall_filter`, `syscall_hook_detector`, `syscall_statistics`,
`syscall_policy_checker`, `compat_layer`, `linux_syscall_table`,
`syscall_table_linux`, `syscall_table_win`, `windows_syscalls`, `syscall_table`,
plus several others declared in nested modules.

### Dependencies

| Crate | Role |
|---|---|
| anyhow / thiserror | errors |
| serde / serde_json | Syscall serialisation |
| rusqlite | optional syscall call log persistence |
| mysql | optional remote syscall DB |
| parking_lot | database locking |

`unsafe_code = "warn"` (not deny — some unsafe may be present).

### Implementation Status: **SUBSTANTIAL**

Rich type system, comprehensive static tables, context-aware decoding, and a
queryable in-memory database are all fully implemented. The 15 submodules
(emulator, tracer, filter, hook detector, policy checker, etc.) were not read
in detail but their existence suggests significant additional functionality.

---

## 12. rustre-syscalls-linux

### Purpose
Linux-specific syscall resolution with full parameter details, ptrace-based
tracing, seccomp profile generation, and statistical analysis.

### Public Types

```rust
pub struct SyscallParam {
    pub name: String,   // e.g. "fd", "buf"
    pub ty:   String,   // C type e.g. "int", "const char __user *"
}

pub struct LinuxSyscall {
    pub number: u32,
    pub name:   String,    // without sys_ prefix
    pub params: Vec<SyscallParam>,
    pub ret_ty: String,
}

pub enum LinuxSyscallError {
    UnsupportedArch(SyscallArch),
    NotFound { arch: SyscallArch, number: u32 },
}
```

### Modules

| Module | Likely purpose |
|---|---|
| `linux_syscall_table_x86_64` | full x86-64 table with param types |
| `ptrace_tracer` | ptrace(2)-based syscall interception |
| `ptrace_syscall_tracer` | higher-level tracer using ptrace primitives |
| `syscall_intercept` | LD_PRELOAD or seccomp-based interception |
| `seccomp_profile_generator` | generate BPF seccomp profiles |
| `syscall_statistics` | aggregation and frequency analysis |

### Dependencies

| Crate | Role |
|---|---|
| rustre-syscalls | core types |
| thiserror / serde / serde_json | standard |
| rusqlite | call log persistence |

### Implementation Status: **UNKNOWN (file too large to read in full)**

The lib.rs (311KB) contains substantial code given its size. Public types
(`LinuxSyscall`, `SyscallParam`) are defined and well-structured. Six
submodules cover the full Linux dynamic analysis pipeline from table lookup
through live ptrace tracing to seccomp profile generation.

### Gaps / TODOs
- ptrace tracing is Linux-only and will not compile on Windows without
  cfg-gating.
- Integration with rustre-plugin-host or MCP server was not verified.

---

## 13. rustre-syscalls-windows

### Purpose
Windows NT syscall layer with per-version SSN (System Service Number) tables,
hook detection, NT object manager support, ETW event parsing, API monitoring,
and registry monitoring.

### Public Types

```rust
pub enum WinArch    { X86, X64, Arm64 }
pub enum WinVersion { WindowsXP, WindowsVista, Windows7, Windows8,
                      Windows81, Windows10, Windows11 }

pub enum WinSyscallError {
    UnsupportedArch(WinArch),
    NotFound { arch: WinArch, ssn: u32 },
    UnsupportedVersion(WinVersion),
    HookDetected {
        name: String,
        expected: Vec<u8>,
        found: Vec<u8>,
    },
}
```

`HookDetected` carries the expected vs. actual bytes of a syscall stub — this
is the userland hook detection pattern (check if bytes at Nt* entry point
match the standard `mov eax, SSN; syscall; ret` stub).

### Modules

| Module | Likely purpose |
|---|---|
| `nt_syscalls` | NT syscall number definitions |
| `nt_syscall_table` | per-version SSN tables (XP through Win11) |
| `nt_object_manager` | NT object type/handle enumeration |
| `api_monitor` | Win32 API call monitoring |
| `api_monitor_hooks` | inline hook installation for monitoring |
| `win32_api_monitor` | higher-level Win32 API wrapper |
| `etw_event_parser` | ETW (Event Tracing for Windows) parsing |
| `windows_events` | Windows event log integration |
| `registry_monitor` | registry access monitoring |

### Dependencies

| Crate | Role |
|---|---|
| rustre-syscalls | core types |
| anyhow / thiserror / serde | standard |
| parking_lot | shared state |

No `windows-sys` dependency in Cargo.toml — likely uses raw pointer casts
or is designed to be cross-compiled with types defined internally.

### Implementation Status: **UNKNOWN (file too large to read in full)**

At 361KB, the lib.rs is the largest in the workspace. The presence of
`HookDetected` with byte-level comparison and a `WinVersion` enum covering
7 OS versions implies real per-version SSN table data and hook detection logic.
ETW parsing and registry monitoring modules suggest a substantial runtime
monitoring stack.

### Gaps / TODOs
- No `windows-sys` dependency — actual WinAPI calls may be behind feature
  flags or absent (static-table only).
- ETW parsing without winapi bindings would require raw pointer work.
- Integration path to MCP server not verified.

---

## Cross-Crate Dependency Map

```
rustre-core
    └── rustre-plugin-api
            ├── rustre-plugin-host
            │       └── (DynLib) ── rustre-plugin-native [NOT WIRED]
            ├── rustre-plugin-loader
            ├── rustre-plugin-python
            └── rustre-plugin-lua

rustre-script
    ├── rustre-script-python  (pyo3 + pure-Rust interpreter)
    ├── rustre-script-lua     (pure-Rust Lua interpreter)
    └── rustre-script-rhai    (real rhai 1.20 engine)

rustre-syscalls (core types)
    ├── rustre-syscalls-linux   (ptrace, seccomp, tables)
    └── rustre-syscalls-windows (NT SSN tables, ETW, hooks)
```

---

## Implementation Status Summary

| Crate | Status | Key blocker |
|---|---|---|
| rustre-plugin-api | Partial | dynamic-plugins feature never enabled |
| rustre-plugin-host | Partial | DynLib/BuiltIn load paths are stubs |
| rustre-plugin-loader | Unknown | submodule bodies not read |
| rustre-plugin-native | Partial | not wired to plugin-host |
| rustre-plugin-python | Unknown | submodule bodies not read |
| rustre-plugin-lua | Unknown | submodule bodies not read |
| rustre-script | Substantial | – |
| rustre-script-python | Partial | BinaryView stub, no real data |
| rustre-script-lua | Substantial | mlua unused, dbg.* unverified |
| rustre-script-rhai | Most complete | dual event systems (dead code) |
| rustre-syscalls | Substantial | submodule depth unverified |
| rustre-syscalls-linux | Unknown | file too large (311KB) to read fully |
| rustre-syscalls-windows | Unknown | file too large (361KB) to read fully |

---

## RE Pipeline Integration

```
Binary input
    ↓
rustre-syscalls-linux / -windows     ← live syscall tracing (ptrace / ETW)
    ↓
rustre-syscalls                      ← decode & classify syscall args, risk
    ↓
rustre-script (ScriptPipeline)
    ├── RhaiScriptEngine             ← pattern search, entropy, SHA-256
    ├── LuaEngine                    ← format detect, disasm, string extract
    └── PythonScriptEngine           ← CPython analysis scripts
    ↓
rustre-plugin-host                   ← orchestrate analysis plugins
    ├── PluginSandbox                ← permission enforcement
    ├── DependencyGraph              ← ordered plugin init
    └── SQLite                       ← persist results
    ↓
MCP server (rustre-mcp)             ← expose all above as MCP tools
```

### Critical Integration Gaps

1. **Native plugin loading is broken end-to-end.** `rustre-plugin-host` returns
   an error for `DynLib` sources; `rustre-plugin-native` is never called.
   No `.dll`/`.so` plugin can be loaded without enabling the `dynamic-plugins`
   cargo feature and wiring `NativePluginLoader` into `PluginHost::load_plugin`.

2. **BinaryView stub disconnects Python scripting from analysis.** The pyo3
   `BinaryView` object has no real backing — scripts cannot read binary data,
   function lists, or strings through the Python engine.

3. **Lua mlua dependency is vestigial.** The Lua engine uses a hand-written
   interpreter; the bundled mlua crate adds compile time and binary size with
   no runtime benefit.

4. **Dual event systems in Rhai.** `EventBus` and `EventHookSystem` both exist
   in `rustre-script-rhai`; one is likely dead code and should be removed or
   the two merged.

5. **rustre-syscalls-linux ptrace modules will not compile on Windows** without
   `#[cfg(target_os = "linux")]` guards. The crate has no such guards visible
   in the Cargo.toml features.
