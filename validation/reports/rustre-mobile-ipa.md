# rustre-mobile-ipa

iOS IPA package parser for the RustRE Suite.

## Cargo.toml

- **name**: `rustre-mobile-ipa` v0.1.0, edition 2024
- **dependencies**: `thiserror`, `serde`, `serde_json`, `zip = "2"`, `anyhow`, `flate2`, `rustre-demangle` (path `../rustre-demangle`)
- **dev-dependencies**: `serde_json`

## Public Modules

`binary_extractor`, `bitcode_extractor`, `decrypt`, `entitlement_analyzer`, `fairplay_detect`, `ipa_analyzer`, `ipa_binary_finder`, `ipa_entitlement_analyzer`, `ipa_extractor`, `ipa_manifest`, `ipa_metadata_extractor`, `ipa_security_analysis`, `plist_binary`, `plist_parser`, `provisioning`, `resources`, `swift_demangler`, `swift_metadata_ipa`.

## Public API (lib.rs)

### Errors

- `enum IpaError`: `InvalidIpa`, `MissingFile`, `PlistParse`, `Io`, `FairPlay`, `Resource`.

### `struct InfoPlist`
Fields: `bundle_id`, `bundle_name`, `bundle_version`, `min_os_version`, `executable`, `supported_platforms: Vec<String>`, `entitlements: HashMap<String,String>`, `permissions: Vec<String>`.

Methods:
- `has_entitlements(&self) -> bool`
- `has_permission(&self, key: &str) -> bool`
- `parsed_min_os(&self) -> Option<(u32, u32)>`
- `targets_iphone(&self) -> bool`

### `struct CodeSignature`
Fields: `team_id`, `signing_id`, `flags: u32`, `cert_chain: Vec<CertInfo>`, `entitlements_xml`.

Methods: `is_developer_signed`, `is_enterprise`, `is_adhoc` (const), `leaf_cert`, `root_cert`.

### `struct CertInfo`
Fields: `subject`, `issuer`, `serial`, `not_before`, `not_after`.
- `is_apple_issued(&self) -> bool`

### `struct IpaEntry`
Fields: `path: String`, `size: u64`, `is_dir: bool`.
Methods: `filename`, `directory`, `extension`, `is_swift_module`, `is_likely_binary`.

### `struct IpaPackage`
Fields: `info_plist`, `code_signature: Option<CodeSignature>`, `entries: Vec<IpaEntry>`, `executable_path`, `frameworks: Vec<String>`, `plugins: Vec<String>`, `fairplay_info: Option<FairPlayInfo>`.

Methods:
- **I**: `parse(data: &[u8]) -> Result<Self, IpaError>` — parses raw IPA/ZIP bytes
- `executable_data(&self, raw: &[u8]) -> Result<Vec<u8>, IpaError>`
- `extract_file(&self, raw: &[u8], path: &str) -> Result<Vec<u8>, IpaError>`
- `entry_count(&self) -> usize` (const)
- `framework_count(&self) -> usize` (const)
- `has_entitlement(&self, key: &str) -> bool`
- `binary_entries`, `asset_catalog_entries`, `strings_entries` → `Vec<&IpaEntry>`
- `is_encrypted(&self) -> bool`
- `mock() -> Self` (test fixture)

Re-export: `pub use decrypt::FairPlayInfo;`

### `struct SimplePlistReader` (zero-dep XML/binary plist)
Static methods:
- `is_binary_plist(data: &[u8]) -> bool`
- `read_string(data: &[u8], offset: usize) -> Option<String>` — bplist ASCII/UTF-16BE
- `find_key_value(data: &[u8], key: &str) -> Option<String>`
- `all_strings(data: &[u8]) -> Vec<String>`

### `struct InfoPlistFull`
Fields: `bundle_id`, `bundle_name`, `bundle_version`, `min_os_version`, `platform`, `supported_devices: Vec<String>`, `required_capabilities: Vec<String>`, `url_schemes: Vec<String>`, `background_modes: Vec<String>`.

- `from_xml(xml: &str) -> anyhow::Result<Self>`
- `from_data(data: &[u8]) -> anyhow::Result<Self>` (XML or binary plist)

### `struct Entitlements` (Default)
Fields: `application_identifier: Option<String>`, `keychain_access_groups: Vec<String>`, `team_identifier: Option<String>`, `get_task_allow: bool`, `aps_environment: Option<String>`, `associated_domains: Vec<String>`.

- `from_plist(data: &[u8]) -> anyhow::Result<Self>`

### `struct ProvisioningProfile` (Default)
Fields: `uuid`, `name`, `team_name`, `team_identifier`, `bundle_id`, `expiration_date`, `provisioned_devices: Vec<String>`, `is_enterprise: bool`, `is_adhoc: bool`, `is_appstore: bool`.

- `parse_cms(data: &[u8]) -> anyhow::Result<Self>` — extracts inner plist from CMS/PKCS#7-wrapped `embedded.mobileprovision`.

### `struct IpaExtractor` (uses `zip` crate, supports DEFLATE)
- **I**: `open(path: &Path) -> anyhow::Result<Self>` — reads file from disk
- `read_binary(&self) -> anyhow::Result<Vec<u8>>` — main Mach-O
- `read_info_plist(&self) -> anyhow::Result<InfoPlistFull>`
- `read_entitlements(&self) -> anyhow::Result<Option<Entitlements>>`
- `read_provisioning_profile(&self) -> anyhow::Result<Option<ProvisioningProfile>>`
- `list_frameworks(&self) -> Vec<String>`
- `list_resources(&self) -> Vec<String>`
- `find_dylibs(&self) -> Vec<String>`

### `struct IpaReport`
Aggregated analysis output (serializable via serde).

### `struct IpaAnalyzer`
- **I**: `analyze(path: &Path) -> anyhow::Result<IpaReport>` — top-level convenience
- `suspicious_entitlements(...)`

### `enum BplistValue` + `struct BplistParser`
- `BplistValue::as_str/as_int/as_real/as_bool/get(key)`
- `BplistParser::parse(data) -> anyhow::Result<BplistValue>` — true binary plist parser
- `BplistParser::parse_xml(data)`
- `BplistParser::parse_any(data)` — autodetect

## I/O Summary

| API | Input | Output |
|---|---|---|
| `IpaPackage::parse` | `&[u8]` raw IPA | `IpaPackage` |
| `IpaPackage::executable_data` / `extract_file` | `&[u8]` + path | `Vec<u8>` |
| `IpaExtractor::open` | filesystem `&Path` | `IpaExtractor` |
| `IpaExtractor::read_*` / `list_*` | (self) | typed structs / `Vec<String>` |
| `IpaAnalyzer::analyze` | `&Path` | `IpaReport` (serde) |
| `InfoPlistFull::from_data` / `Entitlements::from_plist` / `ProvisioningProfile::parse_cms` | `&[u8]` plist | typed struct |
| `BplistParser::parse*` | `&[u8]` | `BplistValue` |

Internal ZIP support: hand-rolled central-directory parser (STORE + DEFLATE via `flate2`), plus full `zip` crate for `IpaExtractor`. Plist support: zero-dep XML + binary heuristic via `SimplePlistReader`, full bplist via `BplistParser`.

## Testability

Yes — `IpaPackage::mock()` builds an in-memory fixture without ZIP data; `parse` accepts `&[u8]` so unit tests can embed minimal ZIPs; `IpaExtractor::open` requires a file on disk (integration-style). All output types implement `serde::Serialize/Deserialize`.
