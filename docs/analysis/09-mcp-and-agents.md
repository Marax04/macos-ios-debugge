# 09 — MCP Layer and Agent Framework: In-Depth Analysis

> Generated: 2026-07-01  
> Workspace root: `C:/Users/Fra/Desktop/RustRE`  
> Covers: `rustre-mcp`, `rustre-mcp-server`, `rustre-mcp-tools`, `rustre-mcp-federation`,  
> `rustre-agent`, `rustre-agent-llm`, `rustre-agent-prompts`, `rustre-agent-workflow`

---

## 1. Crate Inventory and Roles

| Crate | Kind | Role |
|---|---|---|
| `rustre-mcp` | lib + binary | Umbrella coordinator: exposes `McpCoordinator`, `McpTool` trait, middleware, metrics, and the `rustre-mcp` binary entry point |
| `rustre-mcp-server` | lib (no bin) | JSON-RPC 2.0 transport layer: `ToolHandler` trait, `RustReMcpServer`, stdio/HTTP runners, wire types |
| `rustre-mcp-tools` | lib | Concrete tool implementations: all RE capabilities as `ToolHandler` structs, `wire_tools` wiring function |
| `rustre-mcp-federation` | lib | Multi-server federation: routing, health monitoring, tool discovery, call logging |
| `rustre-agent` | lib | Core agent framework: `Agent` trait, `AgentOrchestrator`, `WorkflowEngine`, supporting types |
| `rustre-agent-llm` | lib | LLM backend clients: Anthropic, OpenAI-compatible, Ollama; streaming, tool call loop, prompt/response handling |
| `rustre-agent-prompts` | lib | RE-specific prompt library: templates, few-shot SQLite DB, chain-of-thought, prompt optimizer |
| `rustre-agent-workflow` | lib | Multi-step workflow engine: DSL, step executor, SQLite+MySQL checkpointing, named RE workflow templates |

### Dependency Cycle Avoidance Architecture

The dependency graph is carefully structured to avoid cycles:

```
rustre-mcp (binary+lib)
  ├── rustre-mcp-server   (transport/wire types)
  ├── rustre-mcp-tools    (tool implementations, depends on rustre-mcp-server)
  └── rustre-mcp-federation (routing, depends on rustre-mcp-server)

rustre-mcp-tools
  └── rustre-agent        (agent framework, no RE crate deps)
  └── rustre-agent-workflow
  └── rustre-agent-llm

rustre-agent-prompts
  └── rustre-agent
  └── rustre-agent-llm

rustre-agent-workflow
  └── rustre-agent
```

The key insight documented in Cargo.toml comments: `rustre-mcp-server` cannot depend on `rustre-mcp-tools` (that would create a cycle via `rustre-mcp`), so the `rustre-mcp` umbrella crate is the only place that can import both and wire them together.

---

## 2. `rustre-mcp` — MCP Coordinator (Umbrella)

### 2.1 Purpose

Acts as the public API surface for the entire MCP subsystem. It owns:
- The `McpTool` trait (the interface every tool must implement at the "coordinator" layer)
- The `McpCoordinator` registry and dispatcher
- Cross-cutting middleware, per-tool metrics, rate limiting, audit log
- The `rustre-mcp` binary entry point (source at `rustre-mcp-server/src/bin/rustre-mcp.rs`)

### 2.2 Public API Surface

#### Core Trait

```rust
#[async_trait]
pub trait McpTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ToolCategory { ToolCategory::Utility }
    fn schema(&self) -> ToolSchema { ToolSchema::any() }
    fn capabilities(&self) -> Vec<McpCapability>;
    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError>;
}
```

#### Key Types

| Type | Description |
|---|---|
| `McpCoordinator` | Central registry and dispatcher. Thread-safe via `parking_lot::RwLock`. Holds `HashMap<String, Arc<ToolEntry>>`. |
| `McpError` | Enum: `ToolNotFound`, `InvalidRequest`, `Execution`, `Serialization`, `SchemaValidation`, `RateLimited`, `MiddlewareRejected`, `Timeout`, `CategoryDisabled`, `BatchTooLarge`, `Internal`. Maps to JSON-RPC codes. |
| `McpRequest` / `McpResponse` / `RpcError` | Wire-level request/response with `id`, `method`, `params`, `result`, `elapsed_ms` |
| `RequestContext` | Per-request metadata: `caller`, `trace_id`, `received_at_ms`, `metadata` HashMap |
| `ToolSchema` | Lightweight schema: `required` fields, `param_types`, `param_descriptions`. Has `.validate()` method. |
| `ToolCategory` | Enum: `Analysis`, `Debug`, `Loader`, `Symbols`, `Script`, `ThreatIntel`, `Visualize`, `Utility`, `Custom(String)` |
| `ToolMetrics` | Per-tool stats: `success_count`, `error_count`, `total_us`, `min_us`, `max_us`, `last_error`. Has `.avg_us()`, `.error_rate()`. |
| `RateLimiter` | Token-bucket (sliding window) rate limiter using `VecDeque<Instant>`. |
| `BatchRequest` / `BatchResponse` | Batch dispatch: `Vec<McpRequest>` executed sequentially with configurable `batch_limit` (default 100). |
| `AuditEntry` | Per-call audit record: `request_id`, `tool`, `caller`, `success`, `timestamp_ms`, `elapsed_ms`. Ring buffer, max 10,000. |
| `McpMiddleware` | Sync trait with `before(req, ctx) -> Result<(), McpError>` and `after(req, resp, ctx)`. Built-ins: `LoggingMiddleware`, `DenyListMiddleware`. |
| `ToolRegistration` | Builder for registering tools with optional category/schema/rate-limit/timeout overrides. |

#### McpCoordinator Key Methods

```rust
// Registration
fn register(&self, reg: ToolRegistration);
fn register_tool(&self, tool: Arc<dyn McpTool>);
fn builder(tool: Arc<dyn McpTool>) -> ToolRegistration;
fn remove_tool(&self, name: &str) -> bool;

// Dispatch
async fn dispatch(&self, req: McpRequest) -> McpResponse;
async fn dispatch_with_context(&self, req: McpRequest, ctx: RequestContext) -> McpResponse;
async fn dispatch_batch(&self, batch: BatchRequest) -> BatchResponse;

// Introspection
fn tool_names(&self) -> Vec<String>;
fn tool_count(&self) -> usize;
fn metrics(&self, name: &str) -> Option<ToolMetrics>;
fn audit_log(&self) -> Vec<AuditEntry>;
```

#### Entry Point Functions

```rust
// In rustre-mcp/src/lib.rs
pub async fn run_stdio_wired() -> anyhow::Result<()>;
pub async fn run_http_wired(bind: &str) -> anyhow::Result<()>;
```

Both functions create a `RustReMcpServer`, call `wire_tools::wire_into_server(&mut inner)` to register all tool implementations from `rustre-mcp-tools`, then delegate to `rustre-mcp-server` for transport.

### 2.3 Internal Architecture

Dispatch pipeline (in order):
1. Before-middleware (all `McpMiddleware::before` calls; first failure short-circuits)
2. Tool lookup by `req.method` in `HashMap<String, Arc<ToolEntry>>`
3. Category enabled check
4. Rate limiter check (per-tool token bucket)
5. Schema validation of `req.params`
6. Tool execution with optional per-tool timeout (`tokio::time::timeout`)
7. Metrics recording
8. Audit log push
9. After-middleware (all `McpMiddleware::after` calls)

### 2.4 Sub-modules

| Module | Content |
|---|---|
| `tool_registry` | JSON-Schema-validated registry with versioning |
| `tool_pipeline` | Pipeline middleware chaining |
| `tool_handlers` | Built-in RustRE MCP tool handler impls |
| `federation` | Re-exports from `rustre-mcp-federation` |
| `mcp_capabilities` | `McpCapabilities`, `CapabilityNegotiation`, `ClientCapabilities` |
| `mcp_protocol` / `mcp_protocol_handler` | Protocol-level types and dispatch |
| `mcp_client` | Client-side MCP connection types |
| `mcp_server_impl` | Higher-level server wrapper types |
| `mcp_tool_registry` | Tool registration with versioned entries |
| `mcp_notification_handler` | Notification subscription types |
| `mcp_resource_provider` | MCP resources (read-only data sources) |
| `mcp_error_types` | Extended error types beyond `McpError` |
| `subcrates` | Thin re-exports from subcrates |

### 2.5 Binary Entry Point

`src/bin/rustre-mcp.rs` (located in `rustre-mcp-server/src/bin/` but compiled under `rustre-mcp`):

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --stdio (default) or --transport=sse:<addr> or --bind=<addr>
    if stdio || bind.is_none() {
        rustre_mcp::run_stdio_wired().await
    } else {
        rustre_mcp::run_http_wired(&bind.unwrap()).await
    }
}
```

### 2.6 Status

**Complete** for the coordinator/middleware/metrics infrastructure. The `McpCoordinator` is a fully functional, production-quality dispatcher. The binary entry point correctly wires everything together. Sub-modules (`tool_pipeline`, `tool_handlers`, `mcp_server_impl`, etc.) exist with substantial content.

---

## 3. `rustre-mcp-server` — JSON-RPC 2.0 Transport Layer

### 3.1 Purpose

Provides the MCP protocol wire format, transport adapters (stdio and HTTP/SSE), and the `ToolHandler` trait that all concrete tools implement. Does **not** contain tool implementations — that lives in `rustre-mcp-tools`.

### 3.2 Public API Surface

#### Core Trait

```rust
#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError>;
}
```

#### Wire Types

```rust
struct JsonRpcRequest { jsonrpc: String, id: Value, method: String, params: Option<Value> }
struct JsonRpcResponse { jsonrpc: String, id: Value, result: Option<Value>, error: Option<JsonRpcError> }
struct JsonRpcError { code: i32, message: String, data: Option<Value> }

// Predefined codes on JsonRpcError:
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;
```

#### MCP Domain Types

```rust
enum ContentBlock { Text { text: String }, Image { data: String, mime_type: String } }

struct ToolResult { content: Vec<ContentBlock>, is_error: bool }
// Constructors: ToolResult::text(s), ToolResult::error(s), ToolResult::json(v)

struct ToolDefinition { name: String, description: String, input_schema: Value, parameters: Value }
struct ResourceDefinition { uri: String, name: String, description: String, mime_type: String }
```

#### McpError (transport-layer)

```rust
enum McpError {
    ParseError(String),     // -32700
    MethodNotFound(String), // -32601
    InvalidParams(String),  // -32602
    InternalError(String),  // -32603
    ToolError(String),      // -32000
    Io(#[from] std::io::Error), // -32001
}
```

#### Server Types

- `RustReMcpServer`: Inner server that holds a `HashMap<String, (ToolDefinition, Box<dyn ToolHandler>)>` plus resource providers. Has `register_tool(def, handler)`, `register_resource(def, handler)`.
- `RustREMcpServer`: Outer wrapper implementing the `rmcp` SDK's `ServerHandler` trait. Created via `RustREMcpServer::from_inner(inner)`.
- `run_stdio_from(server)` / `run_http_from(server, bind)`: Entry point functions consuming a `RustREMcpServer`.

### 3.3 Sub-modules

| Module | Content |
|---|---|
| `analysis_tools` | Analysis-specific tool implementations (direct registration path) |
| `binary_analysis_server` | Binary analysis server state (path-based analysis) |
| `rustre_tools` | Core RustRE tool implementations registered by default |
| `tool_implementation` | Additional tool implementations and helpers |
| `mcp_tool_registry` | Internal tool + resource registry types |
| `mcp_session_handler` | Per-session state management |
| `mcp_resource_provider` | Resource provider implementations |
| `mcp_transport_stdio` | Stdio transport adapter details |

### 3.4 External Dependency

Depends on `rmcp` (workspace crate — the official Rust MCP SDK) for the `ServerHandler` trait and transport machinery. Also depends on `iced-x86` directly for some inline disassembly helpers in `analysis_tools`.

### 3.5 Status

**Complete** for transport infrastructure. The ~8,400-line `lib.rs` contains extensive tool implementations directly. The `ToolHandler` trait and `ToolDefinition`/`ToolResult` types are stable and used consistently throughout. The `rmcp` dependency provides the compliant MCP protocol implementation.

---

## 4. `rustre-mcp-tools` — Concrete Tool Implementations

### 4.1 Purpose

The "tool catalog" crate: contains every concrete RE capability as a `ToolHandler`-implementing struct. Has the broadest dependency set in the workspace — it imports virtually every RE analysis crate, making it the integration point between the MCP layer and the RE analysis engine.

### 4.2 Module Structure

| Module | Content |
|---|---|
| `tool_catalog` | `ToolCatalog`, `ToolEntry`, `ToolCategory`, `ToolVersion`, `ToolDependency`, `CatalogSearch` — versioned tool registry |
| `tool_schemas` | `McpToolBundle` with group-based registration: `register_disasm_group`, `register_decompile_group`, etc. |
| `builtin_tools` | Built-in tool structs (disasm, string scan, function analysis, etc.) |
| `tool_executor` | Tool dispatch and execution engine |
| `tool_registry` | Registry bridging `ToolCatalog` to `RustReMcpServer` |
| `tool_schema` | JSON schema generation helpers |
| `disasm_tool` | Disassembler MCP tool: wraps `iced-x86` + `capstone` for multi-arch disassembly |
| `function_analysis_tool` | Function detection, CFG, call graph tools |
| `search_tool` | Pattern/string/symbol search tools |
| `wire_tools` | `wire_into_server(&mut RustReMcpServer)` — the registration function called by `rustre-mcp` |
| `infer_types_path` | Path-accepting type inference tool |

### 4.3 Wire Tools Integration

`wire_tools::wire_into_server` is the primary integration function. It takes a `&mut RustReMcpServer` and registers all "gap-filling" tools that require cross-crate access:

```rust
pub fn wire_into_server(server: &mut RustReMcpServer) {
    // Gap G: loader_core_md5
    server.register_tool(LoaderCoreMd5Tool::definition(), Box::new(LoaderCoreMd5Tool));
    // Gap A: analysis_fn_detect_functions_path
    // Gap D: analysis_string_scan_path
    // Gap F: analysis_crypto_scan_path
    // Gap H: arch-specific disasm tools
    // Gap I: ELF loader tools
    // Gap J/K: additional path-accepting wrappers
    // ... (many more)
}
```

Each tool is a thin wrapper delegating to the underlying analysis crate. For example, `LoaderCoreMd5Tool` calls `rustre_loader::md5(&data)` and returns `{"md5": "..."}`.

### 4.4 Tool Categories in `tool_catalog`

```rust
enum ToolCategory {
    Disassembly, Decompilation, Analysis, Patching, Debugging, Emulation,
    Scripting, Networking, Forensics, Cryptography, Symbols, MobileRE,
    DotNet, ThreatIntel, Utility, Custom(String)
}
```

### 4.5 Dependency Surface

`rustre-mcp-tools` imports every major RE subsystem crate:

| Category | Crates |
|---|---|
| Arch | `rustre-arch-x86`, `-arm64`, `-mips`, `-riscv`, `-wasm`, `-cil`, `-jvm`, `-lua`, `-6502`, `-luajit`, `-avr`, `-bpf`, `-sparc`, `-68k`, `-arm`, `-msp430`, `-ppc`, `-z80`, `-dex` |
| Analysis | `rustre-analysis`, `-fn`, `-string`, `-xref`, `-cfg`, `-dataflow`, `-type`, `-typerecov`, `-vsa`, `-vtable`, `-callconv` |
| Loaders | `rustre-loader`, `-pe`, `-elf`, `-macho`, `-java`, `-wasm`, `-android`, `-dotnet`, `-firmware`, `-ole`, `-pdf`, `-lua`, `-luajit`, `-console` |
| Decompiler | `rustre-decompiler`, `-c`, `-cfs`, `-ghidra`, `-type`, `-expr` |
| Deobfuscation | `rustre-deobf`, `-mba`, `-opaque`, `-vmlift`, `-vm`, `-antianti`, `-string`, `-iadl`, `-mhcde`, `-smc`, `-cff` |
| Debug | `rustre-debug`, `-linux`, `-macos`, `-windbg`, `-frida`, `-windows`, `-gdb`, `-kgdb`, `-unicorn` |
| Symbols | `rustre-symbols`, `-pdb`, `-dwarf`, `-stabs`, `-codeview` |
| Tracing | `rustre-trace`, `-navigate`, `-coverage`, `-pt`, `-coresight` |
| TTD | `rustre-ttd`, `-recorder`, `-replayer`, `-replay`, `-query` |
| Fuzzing | `rustre-fuzz`, `-afl`, `-libfuzzer`, `-sanitizers`, `-net`, `-cov` |
| Sandbox | `rustre-sandbox`, `-vm`, `-report` |
| Mobile | `rustre-mobile`, `-apktool`, `-jadx`, `-dyld`, `-ios`, `-ipa`, `-smali` |
| Network | `rustre-net`, `-proxy`, `-dissect`, `-rules`, `-pcap` |
| Threat Intel | `rustre-threatintel`, `rustre-ti-malpedia`, `-misp`, `-opencti`, `-vt`, `-otx` |
| Scripting | `rustre-script`, `-rhai`, `-python` |
| Other | `rustre-agent`, `rustre-agent-workflow`, `rustre-agent-llm`, `rustre-agent-prompts` |

This makes `rustre-mcp-tools` the "leaf" crate that aggregates the entire workspace.

### 4.6 Status

**Partial to Complete** — the tool catalog infrastructure is complete. Wire tools in `wire_tools.rs` implement concrete RE capabilities. The `lib.rs` (~7,800 lines) contains extensive tool implementations. The degree to which each individual tool delegates to a fully-implemented backend crate varies; some tools reach into fully-complete analysis crates, others may delegate to stubs.

---

## 5. `rustre-mcp-federation` — Multi-Server Federation

### 5.1 Purpose

Orchestrates multiple external MCP servers and presents a unified tool surface to clients. Handles server discovery, health monitoring, routing, call logging, and result aggregation.

### 5.2 Public API Surface

#### Configuration

```rust
struct FederationConfig {
    servers: Vec<ExternalServerConfig>,
    routing_rules: Vec<RoutingRule>,
    fallback_server: Option<String>,
    max_concurrent_calls: u32,   // default 16
    call_timeout_secs: u64,      // default 30
}

struct ExternalServerConfig {
    name: String,
    description: String,
    transport: ServerTransport,
    tags: Vec<String>,
    enabled: bool,
    health_check_interval_secs: u64,
}

enum ServerTransport {
    Stdio { command: String, args: Vec<String>, env: HashMap<String, String> },
    SseHttp { url: String, headers: HashMap<String, String>, timeout_secs: u64 },
    WebSocket { url: String, headers: HashMap<String, String> },
    UnixSocket { path: String },
}
```

The `FederationConfig::default_config()` pre-configures three external servers: `frida-mcp` (stdio), `ghidra-mcp` (HTTP at localhost:18080), `yara-mcp` (stdio).

#### Routing

```rust
enum RouteTarget { Server(String), ServerGroup(Vec<String>), Broadcast, FirstSuccess }

struct RoutingRule { pattern: String, route_to: RouteTarget, priority: u32 }
// Pattern matching: glob with * and ?

struct RoutingDecision {
    tool_name: String,
    servers: Vec<String>,
    strategy: RouteTarget,
    confidence: f64,    // 1.0 = exact, 0.9 = rule match, 0.7 = registry, 0.1 = fallback
    fallback: Option<String>,
}
```

#### Health Monitoring

```rust
enum HealthStatus { Unknown, Healthy, Degraded, Unhealthy, Unreachable }
// Thresholds: 0 failures = Healthy, 1-2 = Degraded, 3-5 = Unhealthy, 6+ = Unreachable

struct HealthMonitor {
    server_states: HashMap<String, ServerHealth>,
    history: HashMap<String, Vec<HealthCheck>>,
}
// Tracks avg_response_ms and uptime_pct from history
```

#### FederationManager (Top-Level Facade)

```rust
struct FederationManager {
    config: FederationConfig,
    registry: ToolRegistry,
    router: ToolRouter,
    health: HealthMonitor,
    call_log: CallLog,  // ring buffer, max 10,000 entries
}

impl FederationManager {
    fn new(config: FederationConfig) -> Self;
    fn from_toml(content: &str) -> Result<Self, ConfigError>;
    fn discover_tools_from_config(&mut self);  // probes HTTP servers, falls back to stubs
    fn simulate_call(&mut self, tool: &str, params: Value) -> Result<Value, FederationError>;
    fn status_report(&self) -> FederationStatus;
}
```

#### Tool Discovery

`discover_tools_from_config()` for HTTP/WebSocket servers uses `reqwest` to POST a `tools/list` JSON-RPC request. Uses `tokio::task::block_in_place` to run async code from sync context. Falls back to synthetic `ping` / `capabilities` stubs on connection failure.

#### ClientConnection (Legacy Transport)

The original `ClientConnection` type manages long-lived stdio child processes:
- Spawns the external MCP server as a child process
- Communicates via `Channel` (async stdin/stdout with 64 MiB line limit)
- Supports reconnect logic (`max_reconnects`)

#### CallAggregator

```rust
impl CallAggregator {
    fn merge_results(results: Vec<(String, Value)>) -> Value;
    fn first_success(results: Vec<(String, Result<Value, String>)>) -> Option<(String, Value)>;
    fn deduplicate(results: Value, key_field: &str) -> Value;
    fn combine_arrays(results: Vec<Value>) -> Value;
    fn merge_objects(base: Value, override_val: Value) -> Value;
}
```

### 5.3 Sub-modules

| Module | Content |
|---|---|
| `mcp_router` | Extended routing with priority queues |
| `proxy_protocol` | Protocol-level proxy types |
| `tool_proxying` | Transparent tool call proxying |
| `ai_orchestrator` | AI-driven orchestration (routes based on semantic analysis) |
| `context_propagation` | Cross-server context/trace propagation |
| `federation_metrics` | Aggregated federation-level metrics |
| `federation_registry` | Extended tool registry with server attribution |
| `result_cache` | TTL-based result caching |
| `server_discovery` | Dynamic server discovery (mDNS/config) |
| `session_multiplexer` | Session multiplexing across servers |
| `tool_aggregator` | Result aggregation strategies |
| `workflow_engine` | Federation-level multi-step workflows |
| `federation_router` | Priority-based router with load awareness |
| `federation_load_balancer` | Load-balanced server selection |
| `federation_cache` | Federation-level response caching |

### 5.4 Status

**Partial** — core types (`FederationConfig`, `ToolRegistry`, `ToolRouter`, `HealthMonitor`, `CallLog`, `FederationManager`) are complete and fully implemented. The `simulate_call` method returns stubs. Actual async tool proxying (dispatching a call to a remote server and awaiting the result) is present in the `Channel`/`ClientConnection` types for stdio transport but the full async call path for `FederationManager` calls into `simulate_call` with stub results. Sub-modules like `ai_orchestrator`, `session_multiplexer`, `federation_load_balancer` exist but their integration into the dispatch path is not yet wired.

**Key gap**: `FederationManager::simulate_call` always returns a stub result rather than forwarding the call to the actual remote server.

---

## 6. `rustre-agent` — Core Agent Framework

### 6.1 Purpose

Foundation crate for all AI agent functionality. Provides the `Agent` trait, `AgentOrchestrator`, `WorkflowEngine` (basic), and all shared types. Has no dependencies on RE analysis crates (pure agent framework).

### 6.2 Public API Surface

#### Agent Trait

```rust
#[async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn capabilities(&self) -> Vec<AgentCapability>;
    async fn process(&self, input: AgentInput, ctx: &AgentContext) -> Result<AgentOutput, AgentError>;
    async fn initialize(&mut self, config: &AgentConfig) -> Result<(), AgentError>;
}
```

#### AgentCapability Enum

```rust
enum AgentCapability {
    Disassembly, Decompilation, TypeRecovery, SymbolRename,
    PatternMatching, ScriptExecution, NetworkAnalysis,
    MalwareAnalysis, VulnerabilityDetection
}
```

#### Input/Output Types

```rust
struct AgentInput {
    task: String,
    context: HashMap<String, serde_json::Value>,
    binary_data: Option<Vec<u8>>,
    history: Vec<AgentMessage>,
}

struct AgentOutput {
    result: String,
    actions: Vec<AgentAction>,
    artifacts: Vec<Artifact>,
    confidence: f32,        // [0.0, 1.0]
    next_steps: Vec<String>,
}
```

#### AgentAction Enum

```rust
enum AgentAction {
    RenameSymbol { addr: u64, name: String },
    AddComment { addr: u64, comment: String },
    ApplyType { addr: u64, ty: String },
    CreateBookmark { addr: u64, name: String },
    RunScript { code: String, engine: String },
    ApplyPatch(Patch),
}
```

#### ArtifactType Enum

```rust
enum ArtifactType { Report, Script, PatchedBinary, TypeDefinitions, Signatures, Graph }
```

#### AgentConfig / AgentContext

```rust
struct AgentConfig {
    model: String,          // default "gpt-4o"
    api_key: String,
    base_url: String,       // default "https://api.openai.com"
    max_tokens: u32,        // default 4096
    temperature: f32,       // default 0.2
    timeout_ms: u64,        // default 60_000
}

struct AgentContext {
    binary_path: Option<PathBuf>,
    architecture: String,
    os: String,
    analysis: HashMap<String, serde_json::Value>,
}
```

#### AgentOrchestrator

```rust
struct AgentOrchestrator {
    agents: RwLock<Vec<RegisteredAgent>>,
}

impl AgentOrchestrator {
    async fn register(&self, agent: Box<dyn Agent>, config: AgentConfig) -> Result<(), AgentError>;
    fn find_by_capability(&self, capability: &AgentCapability) -> Option<String>;
    fn agent_names(&self) -> Vec<String>;
    fn get_config(&self, agent_name: &str) -> Option<AgentConfig>;
    async fn execute(&self, agent_name: &str, input: AgentInput, ctx: &AgentContext)
        -> Result<AgentOutput, AgentError>;
}
```

### 6.3 Sub-modules

| Module | Content |
|---|---|
| `re_agent` | `ReAgent` implementation: `BinaryAnalysisTask`, `DecompileTask`, `YaraTask`, `DiffTask`, `AgentSession`, `ReportGenerator` |
| `reasoning_engine` | Chain-of-thought reasoning primitives |
| `task_planner` | Decomposes high-level tasks into sub-tasks |
| `agent_task_queue` | Priority queue for async task scheduling |
| `agent_memory_store` | Persistent memory (key-value + episodic) |
| `agent_action_executor` | Executes `AgentAction` items against the platform |
| `tool_registry` | Agent-level tool registry (distinct from MCP-level) |
| `agent_loop` | Main `think-act-observe` loop |
| `agent_memory` | Short-term/working memory types |
| `context_manager` | Manages conversation context windows |
| `memory_store` | Storage backend abstraction |
| `tool_executor` | Executes tools requested by the LLM |
| `agent_tools_full` | Full tool set available to agents |
| `casts` | Safe numeric cast helpers (`f64_to_f32`, `u64_to_u32`, etc.) |

### 6.4 Status

**Complete** for framework types. The `Agent` trait, `AgentOrchestrator`, `AgentInput`/`AgentOutput`, and `AgentAction` types are fully defined. `re_agent.rs` provides a concrete `ReAgent` implementation. Supporting modules provide real implementations. The framework is production-ready for defining agents; what remains is wiring agents to LLM backends (done in `rustre-agent-llm`).

---

## 7. `rustre-agent-llm` — LLM Backend Integrations

### 7.1 Purpose

Implements HTTP clients for LLM APIs: Anthropic (`/v1/messages`), OpenAI-compatible, and local Ollama. Also provides streaming, tool call loop, prompt/response building, caching, and model selection. Does **not** use the `reqwest` workspace version for all transports — the lib.rs core implements manual HTTP/1.1 via `tokio::net::TcpStream` (no-dep path), while `anthropic_client.rs` and `local_llm_client.rs` use `reqwest`.

### 7.2 Public API Surface

#### LlmBackend Trait

```rust
#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse, LlmError>;
    async fn stream(&self, req: CompletionRequest)
        -> Result<Pin<Box<dyn Stream<Item=Result<StreamChunk, LlmError>> + Send>>, LlmError>;
    fn model_name(&self) -> &str;
    fn max_context_tokens(&self) -> u32;
}
```

#### Core Types

```rust
struct Message { role: String, content: String }
// Constructors: Message::system(s), Message::user(s), Message::assistant(s), Message::tool_result(id, s)

struct CompletionRequest {
    model: String,
    messages: Vec<Message>,
    max_tokens: u32,
    temperature: f32,
    tools: Option<Vec<ToolSpec>>,
    tool_choice: Option<ToolChoice>,
    system: Option<String>,
    stream: bool,
}

struct CompletionResponse {
    content: String,
    tool_calls: Vec<ToolCall>,
    usage: TokenUsage,
    model: String,
    finish_reason: FinishReason,
}

struct ToolCall { id: String, name: String, arguments: serde_json::Value }
struct TokenUsage { input: u32, output: u32, cache_read: u32, cache_write: u32 }
enum FinishReason { Stop, ToolUse, Length, Error }
```

#### AnthropicClient (in `anthropic_client.rs`)

```rust
struct AnthropicClient {
    client: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
    max_retries: u32,
    total_cost_usd: Arc<AtomicU64>,  // atomic cost accumulation
}

// Supports: tool use, vision (base64 image blocks), streaming SSE, 
// exponential backoff retry, rate-limit handling, prompt caching beta,
// per-model pricing table
```

#### ModelPricing

```rust
struct ModelPricing {
    input_per_mtok: f64,
    output_per_mtok: f64,
    cache_write_per_mtok: f64,
    cache_read_per_mtok: f64,
}
```

### 7.3 Sub-modules

| Module | Content |
|---|---|
| `anthropic_client` | Full Anthropic API client with streaming, tool use, vision, cost tracking |
| `local_llm_client` | Ollama/llama.cpp client via reqwest |
| `context_manager` | Token counting and context window management |
| `llm_context_manager` | Extended context manager for multi-turn |
| `llm_context_builder` | Context assembly from RE analysis results |
| `llm_prompt_builder` | Prompt construction for RE tasks |
| `llm_response_parser` | LLM response parsing and extraction |
| `model_registry` | Registry of known models with capabilities and context limits |
| `model_selector` | Task-to-model selection logic |
| `prompt_builder` | Generic prompt builder |
| `prompt_cache` | LRU prompt caching for expensive prompts |
| `response_parser` | Generic JSON/structured response parser |
| `streaming` | SSE streaming stream adapters |
| `tool_call_loop` | The think-act-observe loop: LLM call → tool call → result → repeat |
| `tool_execution` | Tool call dispatch from LLM requests |

### 7.4 Key Design: Manual HTTP in lib.rs

The `lib.rs` core (~4,600 lines) implements HTTP/1.1 manually via `tokio::net::TcpStream` to avoid mandatory `reqwest` in every code path. This is used for the base `LlmClient` struct. The `anthropic_client` module uses `reqwest` with `rustls-tls` for the higher-level production client.

### 7.5 Status

**Complete** — `AnthropicClient` is fully implemented with streaming, tool use, vision, retries, and cost tracking. The `LlmBackend` trait and `CompletionRequest`/`CompletionResponse` types are stable. The tool call loop, model registry, and streaming support are implemented. This is one of the more mature crates in the workspace.

---

## 8. `rustre-agent-prompts` — Prompt Engineering Library

### 8.1 Purpose

RE-specific prompt templates, a SQLite-backed few-shot example database, chain-of-thought helpers, and a prompt optimizer. Provides the "knowledge" layer for LLM-assisted RE tasks.

### 8.2 Public API Surface

#### PromptTemplate

```rust
struct PromptTemplate {
    name: String,
    template: String,           // {{varname}} syntax
    variables: Vec<String>,
    system_prompt: String,
}

impl PromptTemplate {
    fn render(&self, vars: &HashMap<String, String>) -> Result<String, PromptError>;
}
```

#### PromptRenderer

Static renderer with `{{varname}}` substitution. Returns `PromptError::MissingVariable` for undeclared variables.

#### PromptError

```rust
enum PromptError {
    MissingVariable(String),
    TemplateNotFound(String),
    DbError(String),
    SerializationError(String),
    ChainError { step: usize, message: String },
}
```

### 8.3 Sub-modules

| Module | Content |
|---|---|
| `prompts_re` | Core RE prompt definitions (disassembly, decompilation, malware analysis, vuln detection, etc.) |
| `re_prompt_library` | Named library of RE-specific prompts |
| `prompt_library` | Generic prompt library with CRUD |
| `prompt_templates` | Standard template definitions |
| `prompt_template_engine` | Template rendering with conditionals/loops |
| `few_shot_db` | SQLite-backed few-shot example storage (`rusqlite`) |
| `few_shot_examples` | Curated few-shot examples for RE tasks |
| `analysis_prompt_builder` | Assembles prompts from analysis results (disasm, decompilation, strings, xrefs) |
| `context_assembler` | Context assembly from multiple RE sources |
| `context_builder` | Generic context builder |
| `chain_of_thought` | CoT step definitions and chain runner |
| `prompt_chain` | Multi-step prompt chain executor |
| `prompt_optimizer` | Token-count optimizer for prompts |
| `result_parser` | Structured result extraction from LLM responses |

### 8.4 Few-Shot Database

Uses `rusqlite` to store/retrieve few-shot examples. Schema likely:
```sql
CREATE TABLE few_shot_examples (
    id INTEGER PRIMARY KEY,
    task_type TEXT,
    input TEXT,
    expected_output TEXT,
    metadata TEXT  -- JSON
);
```

### 8.5 Status

**Complete** — all modules exist with substantial content. The `PromptTemplate`/`PromptRenderer` is fully functional. The few-shot DB uses `rusqlite` (production-ready). The RE-specific prompt library (`prompts_re`, `re_prompt_library`) contains domain-specific prompts for binary analysis tasks.

---

## 9. `rustre-agent-workflow` — Multi-Step Workflow Engine

### 9.1 Purpose

Provides a workflow DSL (YAML-serializable), step executor with retry/backoff, conditional branching, parallel execution, and SQLite + MySQL persistence for workflow checkpointing.

### 9.2 Public API Surface

#### Core Types

```rust
struct Workflow {
    id: String,
    name: String,
    steps: Vec<WorkflowStep>,
    on_error: ErrorStrategy,
}

struct WorkflowStep {
    id: String,
    agent: String,
    input_mapping: HashMap<String, String>,   // workflow_var -> AgentInput context key
    output_mapping: HashMap<String, String>,  // AgentOutput field -> workflow_var
    condition: Option<WorkflowCondition>,
    retry: RetryConfig,
}
```

#### Condition and Error Strategy

```rust
enum WorkflowCondition {
    Always,
    OnSuccess,
    OnFailure,
    IfVar { var: String, eq: serde_json::Value },
    IfCapability(AgentCapability),
}

enum ErrorStrategy { Stop, Continue, Retry, Rollback }
```

#### RetryConfig

```rust
struct RetryConfig {
    max_attempts: u32,
    backoff_ms: u64,
    exponential: bool,
}
// delay_ms(attempt) computes linear or exponential backoff
```

#### WorkflowState / WorkflowStatus

```rust
enum WorkflowStatus { Pending, Running, Succeeded, Failed(String), Cancelled }

struct WorkflowState {
    workflow_id: String,
    current_step: usize,
    variables: HashMap<String, serde_json::Value>,
    step_results: HashMap<String, AgentOutput>,
    status: WorkflowStatus,
}
```

#### WorkflowEngine

```rust
struct WorkflowEngine {
    agents: RwLock<HashMap<String, RegisteredAgent>>,
    store: Option<Arc<WorkflowStore>>,  // optional SQLite/MySQL persistence
}

impl WorkflowEngine {
    fn new() -> Self;
    fn with_store(self, store: WorkflowStore) -> Self;
    async fn register_agent(&self, agent: Box<dyn Agent>, config: AgentConfig) -> Result<(), WorkflowError>;
    async fn run(&self, workflow: &Workflow, initial_state: WorkflowState) -> Result<WorkflowState, WorkflowError>;
}
```

#### WorkflowError

```rust
enum WorkflowError {
    NotFound(String), InvalidWorkflow(String),
    StepFailed { step: String, message: String },
    ConditionError(String), AgentError(#[from] AgentError),
    DbError(String), SerializationError(String),
    Cancelled, RetriesExceeded(String), RollbackFailed(String),
}
```

### 9.3 Sub-modules

| Module | Content |
|---|---|
| `re_workflows` | `ReWorkflows`: 20+ named RE workflow templates (malware analysis, decompile + annotate, YARA scan, diff, vuln search, etc.) |
| `workflow_dsl` | YAML-serializable workflow definition DSL (via `serde_yaml`) |
| `workflow_executor` | Basic sequential executor |
| `workflow_executor_full` | Full executor with conditions, retries, rollback |
| `workflow_templates` | Standard workflow template library |
| `workflow_validator` | Pre-execution validation: checks agent availability, parameter types, cycle detection |
| `workflow_checkpointer` | SQLite + MySQL checkpoint persistence |
| `step_executor` | Individual step execution with retry logic |
| `parallel_workflow` | Parallel branch execution (fan-out/fan-in) |
| `result_aggregator` | Aggregates results from parallel steps |
| `task_executor` | Task-level execution primitives |

### 9.4 RE Workflow Templates

`re_workflows::ReWorkflows` provides named templates including:
- `malware_full_analysis` — triage → strings → crypto scan → decompile → yara
- `decompile_and_annotate` — decompile → type recovery → rename symbols
- `vulnerability_search` — CFG analysis → taint tracking → vuln report
- `binary_diff` — load both binaries → semantic diff → report
- `yara_hunt` — apply YARA rules → classify matches → report
- `exploit_analysis` — shellcode analysis → ROP chain detection
- And ~15+ more templates

### 9.5 Persistence

`WorkflowStore` (in `workflow_checkpointer`) supports:
- **SQLite**: via `rusqlite` — local file-based checkpointing
- **MySQL**: via `mysql` workspace crate — remote shared state (multi-node RE campaigns)

### 9.6 Status

**Complete** — workflow DSL, engine, executor, and template library are fully implemented. The persistence layer uses production-ready crates. `re_workflows` templates cover the major RE automation scenarios. The `parallel_workflow` module enables concurrent step execution. This is one of the most complete crates in the agent subsystem.

---

## 10. Integration Points Across All Crates

### 10.1 MCP-to-Analysis Pipeline

```
External Client (Claude, IDE plugin)
    ↕ JSON-RPC 2.0 (stdio or HTTP/SSE)
rustre-mcp binary (rustre-mcp crate)
    → run_stdio_wired() / run_http_wired()
    → RustReMcpServer + wire_tools::wire_into_server()
    → ToolHandler::call(args) dispatch
    → rustre-mcp-tools concrete tool impls
    → Underlying RE crate (e.g., rustre-analysis-fn, rustre-crypto-id)
    → JSON result back to client
```

### 10.2 Agent-to-MCP Integration

`rustre-mcp-tools` depends on `rustre-agent` and `rustre-agent-workflow`. This means MCP tools can invoke agents internally. There are tool implementations that:
1. Accept a task description as a parameter
2. Instantiate an agent (e.g., `ReAgent`) via `AgentOrchestrator`
3. Execute a workflow via `WorkflowEngine::run`
4. Return the workflow result as JSON to the MCP client

### 10.3 Agent-to-LLM Integration

```
rustre-agent-workflow (WorkflowEngine::run)
    → rustre-agent (Agent::process)
    → rustre-agent-llm (AnthropicClient::complete / tool_call_loop)
    → rustre-agent-prompts (PromptTemplate::render / few_shot_db)
    → LLM API (Anthropic, OpenAI-compatible, Ollama)
    → tool calls back to rustre-agent (ToolExecutor)
    → result → AgentOutput
```

### 10.4 Federation-to-External Integration

```
External MCP client
    → rustre-mcp (McpCoordinator::dispatch)
    → rustre-mcp-federation (FederationManager::simulate_call)
    → ClientConnection (stdio/HTTP/WS to external server)
    → External MCP server (frida-mcp, ghidra-mcp, yara-mcp)
    → result merged by CallAggregator
```

---

## 11. Implementation Status Summary

| Crate | Status | Notes |
|---|---|---|
| `rustre-mcp` | **Complete** | Coordinator, middleware, metrics, audit log fully implemented. Binary entry point wires all components correctly. |
| `rustre-mcp-server` | **Complete** | Transport layer, `ToolHandler` trait, `ToolDefinition`/`ToolResult` types, `RustReMcpServer` with `rmcp` SDK integration all complete. |
| `rustre-mcp-tools` | **Partial→Complete** | Infrastructure complete. Wire tools and tool catalog fully implemented. Individual tool quality depends on underlying backend crate completeness. |
| `rustre-mcp-federation` | **Partial** | Config, routing, health, call log complete. `FederationManager::simulate_call` returns stubs — real async dispatch to remote servers not yet wired into `FederationManager`. `ClientConnection` (stdio) and HTTP probe work but are not called from `simulate_call`. |
| `rustre-agent` | **Complete** | Framework types, `Agent` trait, `AgentOrchestrator`, `ReAgent`, all sub-modules implemented. |
| `rustre-agent-llm` | **Complete** | `AnthropicClient` fully implemented. Tool call loop, streaming, cost tracking all work. Manual HTTP path and reqwest path both present. |
| `rustre-agent-prompts` | **Complete** | Template engine, few-shot DB, RE prompt library, CoT, chain runner all implemented. |
| `rustre-agent-workflow` | **Complete** | Workflow DSL, engine with retry/rollback/parallel, RE templates, SQLite+MySQL persistence all implemented. |

---

## 12. Known Gaps and TODOs

### 12.1 Federation Real Dispatch

`FederationManager::simulate_call` always returns a stub result:
```rust
let result = serde_json::json!({
    "stub": true, "tool": tool_name, "server": server, "params_echo": params
});
```
The actual async call path using `ClientConnection::call_tool()` exists but is not invoked from the `FederationManager`. **Priority fix**: wire `FederationManager::call_tool_async` to use `ClientConnection` or the HTTP probe path.

### 12.2 Federation Sub-module Integration

Modules `ai_orchestrator`, `session_multiplexer`, `federation_load_balancer`, `federation_cache` exist but are not integrated into the `FederationManager` dispatch path. They are independently usable but the federation does not yet use load balancing or session multiplexing.

### 12.3 AgentConfig Default

`AgentConfig::default()` uses `base_url: "https://api.openai.com"` and `model: "gpt-4o"`. Code using `AnthropicClient` must explicitly override. There is no workspace-level configuration for default LLM provider.

### 12.4 MCP vs Coordinator Layer Duality

There are two separate dispatcher hierarchies:
- `rustre-mcp::McpCoordinator` (uses `McpTool` trait)
- `rustre-mcp-server::RustReMcpServer` (uses `ToolHandler` trait)

These are not the same. The binary uses `RustReMcpServer` (via `rmcp` SDK), not `McpCoordinator`. The `McpCoordinator` is a higher-level abstraction that is not yet connected to the binary transport path. This means the middleware, rate limiting, and audit log in `McpCoordinator` are not active in the running binary.

### 12.5 Wire Tools Coverage

`wire_tools.rs` uses gap-label comments (`// gap G`, `// gap A`, etc.) indicating an incremental gap-filling approach. Not all gaps may be filled. Tools that accept file paths (e.g., `analysis_fn_detect_functions_path`) require the binary to have read access to the file at runtime.

---

## 13. Pipeline Position

```
[Binary Input] → [Loaders] → [Analysis Engine] → [IL/CFG/Type Recovery]
                                                          ↓
                               [MCP Layer: rustre-mcp-server + rustre-mcp-tools]
                                                          ↓
                               [External AI Clients: Claude, IDE plugins]
                                                          ↓
                               [Agent Layer: rustre-agent + rustre-agent-llm]
                                                          ↓
                               [Workflow Engine: rustre-agent-workflow]
                                                          ↓
                               [Actions: rename, comment, patch, report]
```

The MCP layer is the primary integration surface for AI-assisted reverse engineering. Clients (including Claude via Claude Code) call tools over JSON-RPC 2.0, the tools invoke the analysis engine, and results flow back as structured JSON. The agent layer provides autonomous multi-step analysis that can itself call MCP tools in a tool-use loop.
