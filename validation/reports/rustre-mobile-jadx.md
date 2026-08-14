# rustre-mobile-jadx

JADX Java decompiler wrapper, Dalvik bytecode lifter, Java AST + emitter.

## Cargo.toml
- name: `rustre-mobile-jadx` v0.1.0, edition 2024
- deps: bitflags, petgraph, serde, serde_json, thiserror, anyhow, tokio, tempfile 3, zip 2

## Modules (`lib.rs`)
`java_decompiler`, `dalvik_lift`, `deobfuscation_pass`, `dex_to_java`, `jadx_decompiler_analysis`, `java_ast`, `java_emitter`, `kotlin_support`, `lambda_recovery`, `jadx_output_parser`, `jadx_resource_decoder`, `jadx_call_graph_builder`.

## Public API

### Errors
- `enum JadxError { NotFound, Decompile, Parse, Io }`

### Config types
- `struct JadxConfig { jadx_path, input, output_dir, threads, deobfuscate }`
  - `new(jadx, input, out)`, `with_threads(t)`, `with_deobfuscate()`
- `struct CliJadxConfig { jadx_path: PathBuf, output_dir: Option<PathBuf>, deobfuscate, show_inconsistent_code, no_res }` + `Default` (PATH lookup)

### Java model
- `struct JavaMethod { name, signature, return_type, params, body, is_static, is_native }`
  - `is_constructor() -> bool`
- `struct JavaClass { class_name, package, source, methods, super_class }`
  - `static_methods()`, `native_methods()`
- `struct DecompiledProject { classes, total, failed }`
  - `find_class(name)`, `in_package(pkg)`, `success_rate() -> f64`, `mock()`

### Runners
- `trait JadxRunner { fn decompile(&self, cfg: &JadxConfig) -> Result<DecompiledProject, JadxError>; }`
- `struct MockJadxRunner` — returns `DecompiledProject::mock()`
- `struct CliJadxRunner`
  - `new(config)`, `find_jadx_in_path() -> Option<PathBuf>`
  - `async decompile(apk: &Path, out: &Path) -> Result<DecompiledProject, JadxError>` — spawns `jadx --output-dir <out> [--deobf] [--show-bad-code] [--no-res] <apk>`, walks tree, parses `.java`.
  - `async decompile_class(apk, class_name) -> Result<String, JadxError>` — full decompile to tempdir, return one class source.
- `struct CliJadxRunner2 { jadx_path, timeout_secs }`
  - `new() -> anyhow::Result<Self>` (auto-locate), `with_path(p)`, `with_timeout(secs)`
  - `async decompile_apk(apk, out) -> anyhow::Result<()>` (uses `--no-res`, timeout)
  - `read_decompiled_class(out, fqcn) -> anyhow::Result<String>` (maps dots → path under `sources/`)
  - `async decompile_class(apk, fqcn) -> anyhow::Result<String>` (tempdir-backed)

### Top-level functions
- `async fn decompile_apk(apk: &Path, out: &Path) -> Result<DecompiledProject, JadxError>` — tries CLI JADX, else native fallback (stub class).
- `fn find_jadx() -> Option<PathBuf>` — `JADX_PATH` env → PATH probe (`jadx`/`jadx.bat`/`jadx-gui`) → common install dirs (Linux/macOS/Windows).

### Dalvik / native fallback
- `struct DalvikMethod { name, class_name, return_type, params, instructions: Vec<String> }`
- `struct NativeDexDecompiler`
  - `decompile_method(&DalvikMethod) -> Result<String, JadxError>` — emits pseudo-Java for const/move/return/invoke/iget/iput/sget/sput/new-instance/new-array/array ops/arith/cast/control-flow/throw/monitor/nop; unknowns become `// [native decompiler] unhandled opcode`.
- `enum DalvikOpcode` (20 variants: ReturnVoid 0x0e, Return 0x0f, Const4 0x12, ConstString 0x1a, Iget 0x54, Iput 0x59, InvokeVirtual 0x6e, InvokeDirect 0x70, InvokeStatic 0x71, MoveResult 0x0a, AddInt 0x90, SubInt 0x91, MulInt 0x92, IfEq..IfLe 0x32-0x37, Goto 0x28, NewInstance 0x22)
  - `from_byte(b) -> Option<Self>`, `mnemonic(self) -> &'static str`
- `struct NativeDexLifter` — `lift_instruction(...)` register-machine lifter for the 20 opcodes.

## I/O
- **Inputs**: APK/DEX path (`&Path`), output dir (`&Path`), class FQN (`&str`), `DalvikMethod`, raw opcode bytes, env `JADX_PATH`.
- **Outputs**: `DecompiledProject` (classes + counts), Java source `String` per class, pseudo-Java `String` from native lifter, `PathBuf` of jadx binary.
- **Side effects**: spawns `jadx` subprocess (tokio), writes to output dir (or tempdir), reads recursively (`MAX_WALK_DEPTH = 64`).

## Testable
Mock runner (`MockJadxRunner` / `DecompiledProject::mock`) and `NativeDexDecompiler` are pure; CLI runners require a real `jadx` binary + APK.
