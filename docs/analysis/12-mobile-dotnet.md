# Analysis: Mobile and .NET Subsystems

Crates covered: `rustre-mobile`, `rustre-mobile-android`, `rustre-mobile-ios`,
`rustre-mobile-apktool`, `rustre-mobile-jadx`, `rustre-mobile-smali`,
`rustre-mobile-dyld`, `rustre-mobile-ipa`, `rustre-dotnet`,
`rustre-dotnet-decompile`, `rustre-dotnet-edit`, `rustre-dotnet-metadata`.

---

## 1. Architecture Overview

The twelve crates split into two independent pillars — **Mobile** and **.NET** —
each following the same layered pattern used elsewhere in the workspace:

```
rustre-mobile          (facade / hub)
├── rustre-mobile-android    Android APK model, DEX, permissions, obfuscation
├── rustre-mobile-apktool    apktool CLI wrapper (decode/rebuild APK)
├── rustre-mobile-jadx       JADX CLI wrapper + native Dalvik decompiler fallback
├── rustre-mobile-smali      Full Dalvik opcode table, Smali IR, lexer/parser/printer
├── rustre-mobile-dyld       dyld shared cache parser (iOS system dylib blob)
├── rustre-mobile-ios        iOS bundle, plist, ObjC/Swift metadata, code-signature
└── rustre-mobile-ipa        IPA archive extractor, entitlements, provisioning
```

```
rustre-dotnet-metadata  (foundation — ECMA-335 PE parser, metadata tables)
rustre-dotnet           (high-level .NET model, CIL IR, CLR analysis)
├── rustre-dotnet-decompile  CIL → C# decompiler (LINQ/async recovery)
└── rustre-dotnet-edit       Assembly mutation (patcher, editor, signer, merger)
```

Neither pillar depends on the other. The mobile pillar does **not** depend on
any PE/ELF crate — Mach-O is handled via `goblin` inside `rustre-mobile-ios`
and `rustre-mobile-dyld`. The .NET pillar is fully self-contained.

---

## 2. Mobile Crates

### 2.1 `rustre-mobile` — Hub / Facade

**Purpose.** Re-exports the primary types from every sub-crate and exposes a
`registry::all()` function listing wired backends.

**Public surface.**

```rust
// Type re-exports
pub use rustre_mobile_android::AndroidManifest;
pub use rustre_mobile_apktool::ApktoolConfig;
pub use rustre_mobile_dyld::DyldHeader;
pub use rustre_mobile_ios::BundleInfo;
pub use rustre_mobile_ipa::IpaPackage;
pub use rustre_mobile_jadx::DecompiledProject;
pub use rustre_mobile_smali::SmaliClass;

// Namespace aliases
pub use rustre_mobile_android as android;
pub use rustre_mobile_apktool as apktool;
// … etc.

pub mod registry {
    pub fn all() -> Vec<&'static str>;   // lists 7 backend crate names
}
```

**Status.** Complete — purely structural. No logic resides here.

---

### 2.2 `rustre-mobile-android` — Android APK Model

**Purpose.** Core Android static-analysis types: manifest parsing, permission
classification, DEX class model, strings, native libs, certificates,
obfuscation reports, threat scoring.

**External dependencies.** `serde`, `serde_json`, `thiserror`, `zip`, `bitflags`.

**Key types (defined in `lib.rs`, ~3 700 lines).**

| Type | Role |
|------|------|
| `AndroidManifest` | Fully parsed `AndroidManifest.xml` including permissions, components, SDK levels |
| `Apk` | Complete APK model (entries, manifest, DEX classes, strings, native libs, certs, obfuscation) |
| `ApkAnalyzer` | High-level engine: `parse_bytes(&[u8]) -> Result<Apk>`, `analyze(Apk) -> ApkAnalysisResult` |
| `ApkAnalysisResult` | Threat score (0–10), indicators list, family guess, should-flag flag |
| `Permission` / `ProtectionLevel` | Permission model with `risk_score()`, `is_spyware_relevant()` |
| `Component` / `ComponentKind` | Activity / Service / BroadcastReceiver / ContentProvider |
| `DexClass` | JVM descriptor, superclass, access flags, `is_obfuscated()` |
| `StringEntry` | DEX/resource string with `is_url()`, `is_ip_address()`, `is_base64_like()` |
| `NativeLib` | SO file with `uses_ptrace()`, `uses_crypto()`, `references_shell()` |
| `Certificate` | X.509 with `is_debug_cert()`, `has_weak_key()` |
| `ObfuscationReport` | ProGuard/DexGuard/CFO/string-encryption flags + confidence |
| `PermissionGroup` | Categorised permission groups with risk levels |
| `ApktoolRunnerImpl` | Structural impl of `apktool d` / `apktool b` paths (path only, no subprocess) |

**Submodules (all in their own `.rs` files).**

| Module | Purpose |
|--------|---------|
| `android_manifest_parser` | Binary AXML + plain-XML manifest parsing |
| `dex_analysis` | DEX string/class extraction |
| `dex_obfuscation` | ProGuard/DexGuard detection heuristics |
| `dex_class_hierarchy` | Class inheritance graph |
| `android_security` | Security flag checks |
| `android_malware` | Malware indicator detection |
| `android_permissions` | Permission group mapping |
| `art_runtime` | ART runtime analysis |
| `jni_inference` | JNI bridge inference |
| `apk_security_full` | Aggregated security report |
| `smali_lifter` | Lifts DEX → smali text for use by `rustre-mobile-smali` |

**Integration.** `rustre-mobile-apktool` can call `ApkAnalyzer::parse_bytes()`.
`rustre-mobile-jadx` operates on the decoded smali/Java. The threat score feeds
an MCP tool in `rustre-mcp`.

**Status.** **PARTIAL → approaching FULL.**
- `parse_bytes()` is real: opens ZIP, extracts entries, parses AXML package
  name heuristically, parses DEX magic. DEX class-level parsing produces only a
  single synthetic entry per DEX file (no field/method enumeration yet).
- Full AXML decoding (attributes beyond `package`) is not implemented;
  permissions, components, SDK levels remain zero in a real parse.
- All analysis logic (`threat_score`, obfuscation, etc.) is **complete** and
  operates on pre-populated structs or mocks.

**Known gaps.**
- Full binary AXML parser (attributes, recursion) — only package name extracted.
- DEX class-level parse (real string pool, class defs).
- Certificate extraction from META-INF `.RSA/.DSA/.EC` entries.

---

### 2.3 `rustre-mobile-ios` — iOS Bundle and Binary Analysis

**Purpose.** iOS-specific analysis: plist, entitlements, ObjC/Swift metadata,
code-signature verification, PAC analysis, jailbreak detection, security report.

**External dependencies.** `serde`, `serde_json`, `thiserror`, `goblin`, `zip`.

**Key types (lib.rs, ~2 650 lines).**

| Type | Role |
|------|------|
| `BundleInfo` | Bundle ID, name, version, min-OS, platform |
| `IpaBundle` | Full bundle: info + code signature + frameworks + executable |
| `CodeSignature` | Team ID, signing ID, entitlements Vec |
| `Entitlement` / `EntitlementValue` | Bool/Str/Array entitlement value |
| `ObjcClass` / `ObjcMethod` / `ObjcIvar` / `ObjcProperty` | Full ObjC class descriptor |
| `IpaInfo` | Mach-O scan summary: class count, selector count, Swift symbols, bitcode, arch list |
| `IosAppInfo` / `IosAppInfoExtractor` | Info.plist extraction from IPA ZIP (binary + XML + text plist) |
| `IosSecurityReport` / `IosSecurityChecker` | ARC / PIE / stack canary / debug symbols via goblin |
| `IosClassDumper` | ObjC class and Swift type extraction |
| `SwiftDemangler` | Heuristic Swift 5 ABI demangler (`_$s` prefix) |
| `decode_type_encoding(enc: &str) -> Vec<String>` | ObjC type-encoding decoder |
| `scan_objc_selectors(binary: &[u8]) -> Vec<String>` | `__TEXT,__objc_methnames` scanner |
| `scan_objc_classes(binary: &[u8]) -> Vec<String>` | `__TEXT,__objc_classnames` scanner |

**Submodules (all in `.rs` files).**

| Module | Purpose |
|--------|---------|
| `plist` / `info_plist` | Plist parsing infrastructure |
| `bundle` | Bundle directory structure |
| `codesign` / `ios_codesign_verifier` | Code-signature blob extraction and verification |
| `entitlements` / `ios_entitlements_parser` | Entitlement plist parsing |
| `objc_runtime` / `objc_runtime_analysis` / `macho_objc_runtime` | ObjC runtime layout |
| `swift_metadata` / `ios_swift_metadata_parser` | Swift metadata section |
| `pac` | Pointer Authentication Code analysis |
| `ios_dylib_injector_detector` | Dylib injection detection |
| `ios_jailbreak_detector` / `jailbreak_detection` | Jailbreak indicators |
| `ios_malware` / `fairplay` | Malware and FairPlay DRM detection |

**Status.** **PARTIAL → approaching FULL.**
- `IosSecurityChecker::report()`, `scan_objc_selectors/classes()`, `IpaInfo::from_macho()`,
  `SwiftDemangler::demangle()`, `decode_type_encoding()` are all functionally complete with
  real goblin-based parsing.
- `IosAppInfoExtractor` has heuristic plist scanning that works for common XML and
  binary plists (byte-by-byte string scan, not a real bplist parser).
- Full binary plist (bplist00) decoding is not implemented; falls back to lossy UTF-8 scan.
- ObjC class layout walking (ivar offsets from `__DATA,__objc_data`) is not fully wired.

---

### 2.4 `rustre-mobile-apktool` — apktool CLI Wrapper

**Purpose.** Wraps the external `apktool` binary for APK decode/rebuild
operations, plus native parsers for ARSC, AXML, DEX, and APK signing.

**External dependencies.** `serde`, `serde_json`, `thiserror`, `anyhow`.

**Key types (lib.rs).**

| Type / Trait | Role |
|-------------|------|
| `ApktoolConfig` | Path, output dir, `--no-src`, `--no-res`, `--force` flags |
| `ApktoolRunner` (trait) | `decode(&str, &ApktoolConfig) -> Result<DecodeResult, ApktoolError>` / `build(...)` |
| `CliApktoolRunner` | Real subprocess runner; auto-discovers `apktool` via `$APKTOOL_PATH`, PATH, `.bat` |
| `MockApktoolRunner` | In-memory mock for tests |
| `ApktoolRunnerImpl` | Structural runner: validates extensions, computes output paths, no subprocess |
| `DecodeResult` / `BuildResult` | Output of decode/build |
| `ApkDecodeResult` / `ApkBuildResult` | Extended result types with `is_clean()`, `smali_count()` |

**Submodules.**

| Module | Purpose |
|--------|---------|
| `apk_analyzer` | High-level APK analysis coordination |
| `apk_rebuilder` | Rebuilding a modified APK |
| `apk_signing` / `apk_signature_verifier` | APK signature schemes (v1/v2/v3) |
| `android_manifest_parser` / `manifest` | AXML parsing |
| `arsc_parser` / `arsc_value_decoder` / `res_table_parser` | Resources ARSC parsing |
| `res_decompiler` / `res_rebuilder` / `resource_decoder` | Resource decoding/rebuild |
| `dex_parser` / `dex_analyzer` | DEX file parsing |
| `dalvik_disasm` | Dalvik disassembler |
| `cert_analyzer` | Certificate extraction and analysis |
| `apk_threat_model` | Threat modelling for APKs |

**Integration.** `CliApktoolRunner` is the bridge to the real `apktool` JVM tool.
The output directories contain smali source that `rustre-mobile-smali` and
`rustre-mobile-jadx` consume.

**Status.** **PARTIAL.**
- `CliApktoolRunner` subprocess invocation is complete and real (spawns process, captures output, checks exit code, discovers smali dirs).
- `ApktoolRunnerImpl` is structural — computes paths without actually running apktool.
- ARSC, AXML, DEX sub-parsers in their own modules: each module exists and defines types but depth varies (see submodule files).

---

### 2.5 `rustre-mobile-jadx` — JADX Decompiler Wrapper + Native Fallback

**Purpose.** Invokes the real `jadx` CLI for Java decompilation of APK/DEX,
with a complete fallback (`NativeDexDecompiler` / `NativeDexLifter`) for
environments without JADX installed.

**External dependencies.** `bitflags`, `petgraph`, `serde`, `serde_json`,
`thiserror`, `anyhow`, `tokio`, `tempfile`, `zip`.

**Key types (lib.rs, ~7 150 lines).**

| Type | Role |
|------|------|
| `JavaClass` / `JavaMethod` | Decompiled Java class and method with source text |
| `DecompiledProject` | Collection of `JavaClass` with `success_rate()`, `find_class()`, `in_package()` |
| `JadxRunner` (trait) | `decompile(&JadxConfig) -> Result<DecompiledProject, JadxError>` |
| `MockJadxRunner` | Returns `DecompiledProject::mock()` |
| `CliJadxRunner` | Async runner via `tokio::process::Command`; walks output directory, parses `.java` |
| `CliJadxRunner2` | Simpler API variant; `decompile_apk`, `decompile_class`, timeout support |
| `DalvikOpcode` (enum, 21 variants) | Common Dalvik opcodes with `from_byte()`, `mnemonic()` |
| `DalvikMethod` | Raw instruction list for native decompiler |
| `NativeDexDecompiler` | Text-based fallback: `decompile_method(&DalvikMethod) -> Result<String>` |
| `NativeDexLifter` | Byte-level Dalvik lifter: `lift_instruction(opcode, regs, payload)` |
| `DalvikOpcode` (smali lib) | Complete 256-entry table in `rustre-mobile-smali` |

**Free functions.**

```rust
pub async fn decompile_apk(apk_path: &Path, output_dir: &Path)
    -> Result<DecompiledProject, JadxError>;   // tries JADX, falls back to native

pub fn find_jadx() -> Option<PathBuf>;        // 3-strategy discovery
```

**Submodules.**

| Module | Purpose |
|--------|---------|
| `java_decompiler` | Java source-level decompiler infrastructure |
| `dalvik_lift` | Dalvik → pseudo-Java lifting |
| `dex_to_java` | DEX → Java translation |
| `java_ast` | Java AST types |
| `java_emitter` | Java source emitter |
| `kotlin_support` | Kotlin metadata and sugar detection |
| `lambda_recovery` | Lambda / anonymous class recovery |
| `jadx_output_parser` | Parses JADX stdout/stderr |
| `jadx_resource_decoder` | Resource decoding via JADX |
| `jadx_call_graph_builder` | Call graph construction from decompiled sources |
| `jadx_decompiler_analysis` | Post-decompilation analysis passes |
| `deobfuscation_pass` | Renaming and deobfuscation |

**Integration.** `CliJadxRunner` feeds `DecompiledProject` to `jadx_call_graph_builder`
(uses `petgraph`). The `NativeDexDecompiler` is the fallback for MCP endpoints when
JADX is absent.

**Status.** **PARTIAL → FULL on the decompiler wrapper side.**
- `CliJadxRunner::decompile()` and `CliJadxRunner2::decompile_apk()` are real: spawn
  process, capture output, walk output directory, parse `.java` files with heuristic
  method extraction.
- `NativeDexDecompiler` handles ~40 opcodes fully (const, move, field access, invoke,
  object/array ops, arithmetic, control flow, exceptions).
- Sub-modules (`java_ast`, `jadx_call_graph_builder`, `kotlin_support`, etc.) have
  types defined; depth of implementation in each varies.

---

### 2.6 `rustre-mobile-smali` — Smali IR, Full Dalvik Opcode Table

**Purpose.** Self-contained Smali assembly model: full `DalvikOpcode` table
(256 entries, const-fn decode), Smali IR types, lexer, parser, disassembler,
printer, patcher, optimizer, type resolver, annotation parser, control-flow.

**External dependencies.** `serde`, `serde_json`, `thiserror`, `anyhow`, `bitflags`.

**Key types (lib.rs, ~4 100 lines).**

| Type | Role |
|------|------|
| `SmaliClass` | Class with methods, fields, access flags, interfaces; `mock()`, `find_method()` |
| `SmaliMethod` | Method: access flags, register count, `Vec<SmaliInstr>`, `is_constructor()` |
| `SmaliField` | Name, type descriptor, access flags, initial value |
| `SmaliInstr` | Op + operands + optional label; `to_text()` |
| `SmaliOp` | 30-variant subset used in IR; `Display` → mnemonic |
| `SmaliOperand` | Reg / Literal / Str / TypeRef / FieldRef / MethodRef |
| `SmaliReg` | Register number; `v0`–`v63`, `p0`–`p63` display |
| `SmaliAccess` (bitflags) | PUBLIC / PRIVATE / PROTECTED / STATIC / FINAL / CONSTRUCTOR / NATIVE / ABSTRACT |
| `DalvikOpcode` | Complete 256-entry enum with `from_byte(u8)`, `as_byte()` |
| `opcode_to_smali(op) -> &'static str` | Const-fn mnemonic table |
| `instruction_size_bytes(op) -> usize` | Instruction width in bytes |

**Submodules.**

| Module | Purpose |
|--------|---------|
| `lexer` | Token stream from smali text |
| `parser` | Grammar-level parse of smali text → `SmaliClass` |
| `smali_parser` | Alternative / extended parser |
| `assembler` / `smali_assembler` | Smali → DEX bytecode encoding |
| `disassembler` | DEX bytes → `SmaliInstr` list |
| `printer` | Smali text emission |
| `smali_analysis` / `smali_analyzer` | Analysis passes on `SmaliClass` |
| `smali_patcher` | Instruction-level patch injection |
| `smali_optimizer` | Peephole and dead-code optimisation |
| `smali_type_resolver` | Type descriptor resolution |
| `smali_annotation_parser` | `.annotation` block parsing |
| `smali_control_flow` | CFG construction from `SmaliInstr` list |

**Status.** **PARTIAL → FULL on IR and opcode table.**
- `DalvikOpcode` table is complete and const-correct.
- `SmaliClass` / `SmaliMethod` / `SmaliInstr` types are complete with mock support.
- `opcode_to_smali` and `instruction_size_bytes` are complete const-fn tables.
- Lexer, parser, assembler, disassembler modules exist; depth varies per module.

---

### 2.7 `rustre-mobile-dyld` — dyld Shared Cache Parser

**Purpose.** Parse the `dyld_shared_cache` binary format (used by iOS/macOS to
combine all system dylibs). Extracts images, mappings, bind/rebase info,
export tries, and ObjC selector databases.

**External dependencies.** `anyhow`, `thiserror`, `serde`, `serde_json`, `goblin`, `bitflags`.

**Key types.**

| Type (module) | Role |
|--------------|------|
| `DyldHeader` (`cache_header`) | Re-exported primary type; cache header fields |
| `CacheArch` (`dyld_cache_parser`) | Architecture enum; `from_magic()` |
| `DyldCacheParser` | Main parser: `parse(&[u8])`, `extract_image(index)` |
| `MappingInfo` (`mappings`) | Address/size/file-offset of a mapping region |
| `ImageInfo` (`images`) | Per-image path, address, mod time, inode |
| `SlideInfo` (`slide_info`) | ASLR slide information (v1–v5) |
| `SubCacheInfo` (`subcaches`) | Sub-cache file info (iOS 16+ split caches) |
| `DyldBindInfoParser` (`dyld_bind_info_parser`) | Lazy/non-lazy bind opcodes |
| `DyldRebaseInfoParser` (`dyld_rebase_info_parser`) | Rebase opcodes |
| `DyldExportsTrie` (`dyld_exports_trie`) | Export trie traversal |
| `ObjcSelectorDb` (`objc_selector_db`) | Selector offset database |
| `DyldSharedCacheAnalyzer` (`dyld_shared_cache_analyzer`) | High-level analysis |
| `DyldCacheAnalysis` (`dyld_cache_analysis`) | Full analysis result |

**Status.** **PARTIAL.**
- `DyldCacheParser` with real magic-based architecture detection and
  header parsing is in `dyld_cache_parser.rs`.
- Bind/rebase/export-trie modules have type skeletons; parsing depth varies.

---

### 2.8 `rustre-mobile-ipa` — iOS IPA Archive Extractor

**Purpose.** Parse IPA (ZIP) archives: enumerate bundle entries, extract
binaries, parse provisioning profiles, entitlements, Info.plist, perform
FairPlay detection, Swift demangling, and security analysis.

**External dependencies.** `thiserror`, `serde`, `serde_json`, `zip`, `anyhow`,
`flate2`, `rustre-demangle`.

**Key types.**

| Type (module) | Role |
|--------------|------|
| `IpaPackage` (`lib.rs`) | Root type re-exported by hub |
| `BundleEntry` / `EntryKind` (`ipa_extractor`) | ZIP entry with kind classification |
| `IpaExtractor` | `extract(bytes) -> Result<IpaBundle>`, walks ZIP for `.app/` entries |
| `Entitlements` (`ipa_entitlement_analyzer`) | Key-value entitlement map |
| `EntitlementAnalyzer` (`entitlement_analyzer`) | Checks for risky entitlements |
| `ProvisioningProfile` (`provisioning`) | Embedded `.mobileprovision` parsing |
| `InfoPlistFull` (`ipa_manifest`) | Full Info.plist model |
| `BinaryExtractor` (`binary_extractor`) | Locate and extract the main Mach-O |
| `BitcodeExtractor` (`bitcode_extractor`) | Extract LLVM bitcode |
| `FairPlayDetect` (`fairplay_detect`) | FairPlay DRM markers |
| `SwiftMetadataIpa` (`swift_metadata_ipa`) | Swift section analysis |
| `SwiftDemangler` (`swift_demangler`) | Links to `rustre-demangle` |
| `IpaSecurityAnalysis` (`ipa_security_analysis`) | Aggregated security flags |
| `IpaBinaryFinder` (`ipa_binary_finder`) | Locate main binary in bundle |
| `ResourceAnalysis` (`resources`) | Asset catalogue and resource listing |
| `SimplePlistReader` | Heuristic plist key-value extraction used internally |

**Integration.** Uses `rustre-demangle` for Swift symbol demangling — only mobile
crate with an intra-workspace dep outside the mobile cluster.

**Status.** **PARTIAL.**
- ZIP walking, entry classification, and `BundleEntry` are complete.
- `InfoPlistFull` / provisioning parsing is heuristic (similar to `IosAppInfoExtractor`).
- FairPlay detection, bitcode extraction, and security analysis modules exist with
  type definitions; real parsing depth varies.

---

## 3. .NET Crates

### 3.1 `rustre-dotnet-metadata` — ECMA-335 PE/Metadata Parser (Foundation)

**Purpose.** Pure-Rust parser for PE files containing .NET managed code.
Exposes every metadata table, heap, and stream defined in ECMA-335.

**External dependencies.** `anyhow`, `thiserror`, `serde`.

**Error type.**

```rust
pub enum MetadataError {
    UnexpectedEof { offset, need, have },
    InvalidPeMagic(usize),
    InvalidMetadataSignature(u32),   // expected 0x424A5342
    StreamNotFound(String),
    // …
}
```

**Submodules.**

| Module | Role |
|--------|------|
| `metadata_tables` | All 45 ECMA-335 metadata table row types (TypeDef, MethodDef, Field, Param, MemberRef, …) |
| `metadata_full` | `MetadataReader` — primary entry point; reads PE, locates metadata root, parses streams |
| `metadata_resolver` | Token-to-row resolution, cross-table navigation |
| `generic_resolver` | Generic type/method instantiation resolution |
| `attribute_reader` | Custom attribute value decoding |
| `assembly_resolver` | Multi-assembly resolution (follows `AssemblyRef` rows) |
| `il_disassembler` | CIL byte stream → instruction sequence |
| `type_system` | .NET type system: `TypeRef`, `TypeSpec`, signatures |
| `metadata_analyzer` | Higher-level analysis over parsed metadata |

**Key types exported (used by `rustre-dotnet` and `rustre-dotnet-edit`).**

```rust
pub struct MetadataReader { /* PE bytes + parsed tables */ }
// Row types (one per metadata table):
pub struct TypeDefRow  { pub name: String, pub namespace: String, pub flags: u32, … }
pub struct MethodDefRow { pub name: String, pub flags: u32, pub rva: u32, … }
pub struct FieldRow    { pub name: String, pub flags: u16, … }
pub struct ParamRow    { pub name: String, pub sequence: u16, pub flags: u16 }
pub struct MemberRefRow { … }
pub struct AssemblyRow / AssemblyRefRow { … }
// … and all remaining 45 table rows
```

`rustre-dotnet-edit` imports nearly every row type from this crate.

**Status.** **PARTIAL → substantial.**
- The module structure and row types are complete.
- Real PE/metadata parsing is implemented (`MetadataReader`); depth of stream parsing (heaps, blob, signatures) varies across submodules. The broad allowlist in `lib.rs` (dozens of `#[allow(clippy::…)]`) indicates real, complex code was written to get past lint.

---

### 3.2 `rustre-dotnet` — High-Level .NET Model

**Purpose.** Ergonomic .NET assembly model built on `rustre-dotnet-metadata`.
Provides typed access to types, methods, fields, properties, events, generics,
custom attributes, CIL method bodies, obfuscation removal, string decryption.

**External dependencies.** `anyhow`, `thiserror`, `serde`, `rustre-dotnet-metadata`, `bitflags`, `ahash`.

**Key types (lib.rs).**

```rust
pub enum CilOperand {
    None, Int8(i8), Int32(i32), Int64(i64),
    Float32(f32), Float64(f64),
    String(String), Token(u32), Branch(u32), Switch(Vec<u32>),
}

pub struct CilInstruction {
    pub offset: u32,
    pub opcode: String,
    pub operand: CilOperand,
}
// Methods: simple(), branch(), with_token(), with_i32(),
//          is_unconditional_branch(), is_branch(), is_terminator(),
//          branch_targets(), byte_size()

pub struct MethodBody { pub instructions: Vec<CilInstruction>, … }
pub struct DotnetMethod { … }     // full method descriptor + optional body
pub struct DotnetType { … }       // type descriptor with methods, fields, properties
pub struct AssemblyFile { … }     // top-level assembly container
```

**Submodules.**

| Module | Role |
|--------|------|
| `il_decoder` | CIL byte stream decoder → `Vec<CilInstruction>` |
| `dotnet_il_printer` | Pretty-print CIL |
| `cil_control_flow` | CFG construction from CIL |
| `cil_stack_analyzer` | Stack-state tracking for CIL |
| `clr_loader` | Load an assembly from disk via `MetadataReader` |
| `clr_analysis` | CLR-level analysis (entry points, ref graph) |
| `clr_jit_analysis` | JIT-related analysis |
| `dotnet_metadata_tables` | Higher-level table wrappers |
| `dotnet_heap_analyzer` | Managed heap analysis |
| `dotnet_packer_detection` | .NET packer/protector detection (ConfuserEx, etc.) |
| `dotnet_string_decrypt` | Encrypted string detection and decryption |
| `obfuscation_remover` | Rename obfuscated identifiers |
| `csharp_reconstructor` | C# AST reconstruction from CIL |

**Status.** **PARTIAL.**
- `CilInstruction` and `CilOperand` are complete and rich.
- `il_decoder` and `dotnet_il_printer` are functional.
- Higher-level types (`DotnetType`, `DotnetMethod`, `AssemblyFile`) are defined and used as the interface to `rustre-dotnet-decompile` and `rustre-dotnet-edit`.
- Some analysis submodules (`dotnet_heap_analyzer`, `clr_jit_analysis`) are likely stub-level.

---

### 3.3 `rustre-dotnet-decompile` — CIL → C# Decompiler

**Purpose.** Converts `DotnetMethod` / `DotnetType` from `rustre-dotnet` into
readable C# source text.

**External dependencies.** `ahash`, `anyhow`, `thiserror`, `serde`,
`rustre-dotnet`, `rustre-dotnet-metadata`.

**Key public surface (lib.rs).**

```rust
pub mod casts {                        // numeric conversion helpers (no panics)
    pub fn usize_to_u32(v: usize) -> u32;
    pub fn usize_to_i32(v: usize) -> i32;
    pub fn i32_to_usize(v: i32) -> usize;
    // … 9 total helpers
}
```

The decompiler consumes `AssemblyFile`, `CilInstruction`, `CilOperand`,
`DotnetMethod`, `DotnetType`, `ExceptionHandlerKind`, `MethodBody` from
`rustre-dotnet`.

**Submodules.**

| Module | Role |
|--------|------|
| `linq_recovery` / `linq_recovery_full` | LINQ expression tree recovery from CIL patterns |
| `async_recovery` | `async/await` state-machine recovery |
| `csharp_patterns` | Common C# code-pattern detection and emission |

The main decompiler (`CilDecompiler` or equivalent) converts CIL instructions
to C# AST then emits source text. LINQ and async recovery are non-trivial
passes that reconstruct high-level idioms from state-machine CIL output.

**Status.** **PARTIAL.**
- Module structure and the `casts` helpers are complete.
- LINQ and async recovery modules exist and are non-trivial; completeness unknown without deeper inspection.
- The core decompiler loop (CIL → C# statement emission) resides in these submodules.

**Known gap.** No `todo!()` or `unimplemented!()` macros were visible in `lib.rs`;
actual completeness is in the submodule files not fully read here.

---

### 3.4 `rustre-dotnet-edit` — Assembly Editor / Patcher

**Purpose.** dnSpy-style assembly mutation: rename types/methods/fields, patch
method bodies, inject custom attributes, edit resources, mutate flags, insert/
delete IL instructions, add/remove types and methods, merge assemblies, strip
strong names.

**External dependencies.** `anyhow`, `thiserror`, `serde`, `rustre-dotnet`,
`rustre-dotnet-metadata` (imports nearly all 45 row types).

**Key types (lib.rs).**

```rust
pub enum EditError {
    TypeNotFound(String),
    MethodNotFound { type_name, method_name },
    FieldNotFound  { type_name, field_name },
    NoMethodBody   { type_name, method_name },
    InvalidIlOffset(u32),
    InvalidFlags(u32),
    ResourceNotFound(String),
    Custom(String),
}
```

**Submodules.**

| Module | Role |
|--------|------|
| `assembly_patcher` | Top-level patcher: coordinate all edits |
| `metadata_editor` | Metadata table row mutation |
| `method_body_editor` | IL instruction-level body editing |
| `cil_injector` | CIL instruction insertion |
| `cil_patcher` | CIL patch application |
| `cil_optimizer` | Peephole optimisation of edited bodies |
| `il_editor_extended` | Extended IL editing operations |
| `il_recompile` | Re-encode modified IL bodies |
| `type_injector` | Add new types to an assembly |
| `resource_editor` | Managed resource editing |
| `strong_name_editor` | Strong-name key stripping/replacement |
| `assembly_signer` | Re-sign an assembly |
| `assembly_merger` | Merge multiple assemblies |
| `dotnet_patcher` | Higher-level patch API |

The breadth here is wide — 13 modules covering the full mutation surface.

**Status.** **PARTIAL.**
- All modules are declared and connected.
- The `EditError` type and import surface (all 45 row types) indicate real
  implementation effort.
- Actual mutation completeness (write-back to PE bytes) in `il_recompile` and
  `assembly_patcher` likely requires further work to be end-to-end functional.

---

## 4. Dependency Graph

```
External                  Workspace
--------                  ---------
goblin         ←──────── rustre-mobile-ios
goblin         ←──────── rustre-mobile-dyld
zip            ←──────── rustre-mobile-android, rustre-mobile-apktool,
                          rustre-mobile-ipa, rustre-mobile-ios
petgraph       ←──────── rustre-mobile-jadx
tokio          ←──────── rustre-mobile-jadx
tempfile       ←──────── rustre-mobile-jadx
flate2         ←──────── rustre-mobile-ipa
rustre-demangle ←─────── rustre-mobile-ipa (only intra-workspace dep in mobile)

rustre-dotnet-metadata ←─ rustre-dotnet
rustre-dotnet          ←─ rustre-dotnet-decompile
rustre-dotnet          ←─ rustre-dotnet-edit
rustre-dotnet-metadata ←─ rustre-dotnet-edit (direct, for row types)
```

---

## 5. Implementation Status Summary

| Crate | Status | Notes |
|-------|--------|-------|
| `rustre-mobile` | FULL | Hub only; no logic |
| `rustre-mobile-android` | PARTIAL | ZIP/magic parse real; AXML attrs, full DEX class parse missing |
| `rustre-mobile-ios` | PARTIAL | goblin-based security + ObjC scan real; bplist parser heuristic |
| `rustre-mobile-apktool` | PARTIAL | `CliApktoolRunner` subprocess real; sub-parsers vary |
| `rustre-mobile-jadx` | PARTIAL | CLI runner + native fallback real; sub-analysis modules vary |
| `rustre-mobile-smali` | PARTIAL | Opcode table + IR types complete; assembler/parser depth varies |
| `rustre-mobile-dyld` | PARTIAL | Header/arch detect real; bind/export parsing partial |
| `rustre-mobile-ipa` | PARTIAL | ZIP walking + classification real; plist/provision heuristic |
| `rustre-dotnet-metadata` | PARTIAL | Row types + `MetadataReader` substantial; stream parsing depth varies |
| `rustre-dotnet` | PARTIAL | CIL IR complete; analysis submodules vary |
| `rustre-dotnet-decompile` | PARTIAL | Module structure + helpers complete; decompiler body depth unknown |
| `rustre-dotnet-edit` | PARTIAL | Wide module surface; write-back completeness unknown |

---

## 6. Integration with RE Pipeline

```
APK / IPA file
    │
    ├─► rustre-mobile-android  (ApkAnalyzer::parse_bytes)
    │       → AndroidManifest, DexClass, Certificate, ObfuscationReport
    │
    ├─► rustre-mobile-apktool  (CliApktoolRunner::decode)
    │       → smali/ directories on disk
    │       → rustre-mobile-smali (SmaliClass, DalvikOpcode)
    │       → rustre-mobile-jadx  (CliJadxRunner::decompile → DecompiledProject)
    │
    └─► rustre-mobile-ipa / rustre-mobile-ios
            → IpaBundle, ObjcClass, IosSecurityReport, IpaInfo
            → rustre-mobile-dyld (for system dylib resolution)

.NET assembly (PE/EXE/DLL)
    │
    ├─► rustre-dotnet-metadata  (MetadataReader)
    │       → TypeDefRow, MethodDefRow, FieldRow, …
    │
    ├─► rustre-dotnet  (AssemblyFile, DotnetType, CilInstruction)
    │
    ├─► rustre-dotnet-decompile  (CIL → C# source text)
    │       + LINQ / async recovery
    │
    └─► rustre-dotnet-edit  (patch, rename, inject, strip, merge)
```

The MCP server (`rustre-mcp`) exposes tools that call into these crates.
Mobile analysis tools call `ApkAnalyzer`, `CliJadxRunner`, and
`IpaExtractor`. .NET tools call `MetadataReader`, the decompiler, and
the editor. No cross-pillar calls exist.

---

## 7. Known Gaps and Priority TODOs

1. **Full AXML parser** (`rustre-mobile-android`, `rustre-mobile-apktool`):
   Only `package` attribute extracted from binary XML. Permissions, component
   declarations, SDK levels require a complete AXML attribute decoder.

2. **DEX class-level parse** (`rustre-mobile-android`): `parse_bytes()` emits
   one synthetic `DexClass` per DEX file. Full string-pool, class-def, and
   method parsing needed.

3. **Binary plist parser** (`rustre-mobile-ios`, `rustre-mobile-ipa`):
   `bplist00` format parsed by lossy UTF-8 scan. A proper object-tree decoder
   is needed for Info.plist fields like `CFBundleURLTypes` and permission arrays.

4. **dyld bind/rebase/export** (`rustre-mobile-dyld`): Opcode parsing modules
   exist but completeness is uncertain. Full rebase-chain walking is needed to
   fix-up extracted image pointers.

5. **CIL write-back** (`rustre-dotnet-edit`): Editing metadata rows in-memory
   is partial; re-serialising back to a valid PE file requires completed
   `il_recompile` and `assembly_patcher` write paths.

6. **Swift metadata section** (`rustre-mobile-ios`, `rustre-mobile-ipa`):
   `SwiftDemangler` is heuristic. Full Swift 5 ABI mangling grammar and
   `__TEXT,__swift5_types` section walking are missing.

7. **ObjC runtime layout walker** (`rustre-mobile-ios`): `scan_objc_classes`
   returns name strings; full ivar layout, method IMP walking, and protocol
   conformance graph require `macho_objc_runtime.rs` to be completed.
