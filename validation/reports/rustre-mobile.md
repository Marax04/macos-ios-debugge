# rustre-mobile

Composition hub crate that aggregates all `rustre-mobile-*` sub-crates for mobile (Android/iOS) binary analysis.

## Cargo.toml

- **name**: `rustre-mobile` v0.1.0, edition 2024
- **dependencies** (path deps, all in workspace):
  - `rustre-mobile-android`
  - `rustre-mobile-apktool`
  - `rustre-mobile-dyld`
  - `rustre-mobile-ios`
  - `rustre-mobile-ipa`
  - `rustre-mobile-jadx`
  - `rustre-mobile-smali`

## Public API (src/lib.rs)

### Re-exported primary types
- `pub use rustre_mobile_android::AndroidManifest;`
- `pub use rustre_mobile_apktool::ApktoolConfig;`
- `pub use rustre_mobile_dyld::DyldHeader;`
- `pub use rustre_mobile_ios::BundleInfo;`
- `pub use rustre_mobile_ipa::IpaPackage;`
- `pub use rustre_mobile_jadx::DecompiledProject;`
- `pub use rustre_mobile_smali::SmaliClass;`

### Re-exported namespaces (module aliases)
- `android` -> `rustre_mobile_android`
- `apktool` -> `rustre_mobile_apktool`
- `dyld` -> `rustre_mobile_dyld`
- `ios` -> `rustre_mobile_ios`
- `ipa` -> `rustre_mobile_ipa`
- `jadx` -> `rustre_mobile_jadx`
- `smali` -> `rustre_mobile_smali`

### `pub mod registry`
- `pub fn all() -> Vec<&'static str>`
  - **Input**: none
  - **Output**: `Vec` of the 7 short crate names of wired backends (`"rustre-mobile-android"`, ..., `"rustre-mobile-smali"`)
  - Marked `#[must_use]`

## I/O summary

- The hub crate itself performs no I/O: it only re-exports types/namespaces and provides a static registry listing.
- All actual file/process I/O (APK/IPA parsing, dyld header reading, apktool/jadx invocation, smali parsing) lives in the sub-crates.

## Testability

The crate is testable: `registry::all()` is a pure, deterministic function returning a fixed `Vec<&'static str>` of length 7; the re-exports can be smoke-tested by referencing each type at compile time.
