# rustre-mobile-apktool

Apktool wrapper types and Android APK analysis primitives.

## Cargo.toml
- name: `rustre-mobile-apktool` v0.1.0, edition 2024
- deps: `serde`, `serde_json`, `thiserror`, `anyhow` (all workspace)

## Modules
`apk_analyzer`, `apk_rebuilder`, `apk_signing`, `apk_signature_verifier`, `apk_threat_model`,
`arsc_parser`, `arsc_value_decoder`, `res_table_parser`, `res_decompiler`, `res_rebuilder`,
`resource_decoder`, `manifest`, `android_manifest_parser` (alias `manifest_parser`),
`dex_parser`, `dex_analyzer`, `dalvik_disasm`, `cert_analyzer`.

## Public API (lib.rs root)

### Error
`enum ApktoolError { NotFound(String), Decode(String), Build(String), Io(String) }` — `thiserror::Error`.

### ApktoolConfig
Fields: `apktool_path: String`, `output_dir: String`, `no_src: bool`, `no_res: bool`, `force: bool`.
- `new(path: impl Into<String>, out: impl Into<String>) -> Self`
- `with_no_src(self) -> Self` (const)
- `with_no_res(self) -> Self` (const)
- `with_force(self) -> Self` (const)
- Serialize/Deserialize.

### DecodeResult
Fields: `output_dir`, `smali_dirs: Vec<String>`, `res_dir: Option<String>`, `success: bool`, `log: String`.
- `smali_count(&self) -> usize` (const).

### BuildResult
Fields: `apk_path: String`, `success: bool`, `log: String`.

### ApkDecodeResult
Fields: `output_dir`, `smali_dirs`, `res_dir`, `manifest_path: Option<String>`, `warnings: Vec<String>`.
- `smali_count() -> usize` (const)
- `is_clean() -> bool` (const, true if no warnings).

### ApkBuildResult
Fields: `apk_path: String`, `unsigned: bool`, `size_bytes: u64`.

### Trait `ApktoolRunner: Send + Sync`
- `decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError>`
- `build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError>`

### MockApktoolRunner
Fields: `decode_ok: bool`, `build_ok: bool`, `smali_dirs: Vec<String>`.
- `success() -> Self`, `failure() -> Self` (const).
- Implements `ApktoolRunner` deterministically.

### CliApktoolRunner
Spawns external `apktool` subprocess.
- Fields: `apktool_path: PathBuf`.
- `new() -> Result<Self, ApktoolError>` — auto-locate via `APKTOOL_PATH` env, `apktool` on PATH, or `apktool.bat` (Windows).
- `with_path(path: impl Into<PathBuf>) -> Self`
- `find_apktool() -> Option<PathBuf>`
- `decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError>` — runs `apktool d <apk> -o <out>` with flags `--no-src`/`--no-res`/`-f`; captures stdout+stderr; treats non-zero exit or lines starting with `I: E:`/`E: `/`brut.` as failure; scans output dir for directories starting with `smali`.
- `build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError>` — runs `apktool b <dir> -o <out>/dist/<basename>.apk`.
- Implements `ApktoolRunner`.

### ApktoolRunnerImpl
Structural (non-subprocess) implementation wrapping `ApktoolConfig`.
- Fields: `config: ApktoolConfig`.
- `new(config) -> Self` (const)
- `decode(&self, apk_path: &str) -> Result<ApkDecodeResult, ApktoolError>` — validates `.apk` extension; synthesizes output paths.
- `build(&self, dir: &str) -> Result<ApkBuildResult, ApktoolError>` — errors on empty dir.
- `install_framework(&self, apk_path: &str) -> Result<(), ApktoolError>` — validates `.apk` extension.

## I/O behavior
- **Inputs**: APK file paths (string), source dir paths, optional `APKTOOL_PATH` env.
- **Outputs**: structured result types (smali dir list, res dir, manifest path, rebuilt APK path, log).
- **Side effects** (`CliApktoolRunner` only): spawns external `apktool` process; reads output directory via `fs::read_dir`. `ApktoolRunnerImpl` and `MockApktoolRunner` perform no FS/process I/O.

## Testability
Crate is fully unit-testable without external tools via `MockApktoolRunner` and `ApktoolRunnerImpl`. `CliApktoolRunner` requires `apktool` installed on PATH for integration tests. lib.rs contains 35+ in-crate tests.
