//! Binary loader abstraction layer.
//!
//! This module defines the [`Loader`] async trait and all supporting types used
//! to load binary files into [`BinaryView`] instances.
//!
//! Key types:
//! - [`Loader`] — the async trait that all format-specific loaders implement.
//! - [`LoaderInput`] — the data + metadata passed to a loader.
//! - [`LoaderHint`] — optional hints to guide loading.
//! - [`LoaderOptions`] — a builder for loader-specific configuration.
//! - [`LoadResult`] — what a successful load returns.
//! - [`NestedBinary`] — a sub-binary found inside a container format.
//! - [`BinaryType`] — classification of a binary's role.
//! - [`LoaderRegistry`] — global registry of all registered loaders.

use crate::binary_view::BinaryView;
use crate::errors::CoreError;
use crate::ids::ViewId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Global ViewId allocator
// ─────────────────────────────────────────────────────────────────────────────

/// Global monotonic counter for allocating unique [`ViewId`]s.
///
/// Starts at 1 (0 is the invalid sentinel). All loaders should call
/// [`next_view_id`] instead of hardcoding `ViewId::from_raw(1)`.
static VIEW_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Allocate the next unique [`ViewId`].
///
/// Thread-safe; uses a relaxed fetch-add. The returned ID is guaranteed to
/// be non-zero.
#[must_use]
pub fn next_view_id() -> ViewId {
    let raw = VIEW_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    ViewId::from_raw(raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryType
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a binary's role or format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryType {
    /// A standalone executable (`EXE`, `ELF ET_EXEC`, …).
    Executable,
    /// A shared library (`DLL`, `ELF ET_DYN`, `dylib`, …).
    Library,
    /// A relocatable object file (`OBJ`, `ELF ET_REL`, …).
    Object,
    /// A core dump.
    Core,
    /// Firmware / bare-metal binary.
    Firmware,
    /// WASM module.
    Wasm,
    /// Java class file or JAR.
    Java,
    /// .NET / CIL assembly.
    DotNet,
    /// An archive / static library (`LIB`, `AR`).
    Archive,
    /// Format unknown or unrecognised.
    Unknown,
}

impl BinaryType {
    /// Return `true` if this type is executable (can be run directly).
    #[must_use]
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Executable | Self::Firmware | Self::Wasm)
    }

    /// Return `true` if this type is a library.
    #[must_use]
    pub const fn is_library(self) -> bool {
        matches!(self, Self::Library | Self::Archive)
    }
}

impl std::fmt::Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Executable => write!(f, "executable"),
            Self::Library => write!(f, "library"),
            Self::Object => write!(f, "object"),
            Self::Core => write!(f, "core"),
            Self::Firmware => write!(f, "firmware"),
            Self::Wasm => write!(f, "wasm"),
            Self::Java => write!(f, "java"),
            Self::DotNet => write!(f, "dotnet"),
            Self::Archive => write!(f, "archive"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderHint
// ─────────────────────────────────────────────────────────────────────────────

/// A single hint provided by the caller to guide loading.
///
/// Hints are optional; loaders use them to override auto-detected defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoaderHint {
    /// Force a specific architecture name (e.g. `"x86_64"`, `"aarch64"`).
    Architecture(String),
    /// Override the base load address.
    BaseAddress(crate::address::Address),
    /// Override the entry-point address.
    EntryPoint(crate::address::Address),
    /// Force a specific endianness.
    Endian(crate::endian::Endian),
    /// Force a specific word size in bits (32 or 64).
    WordSize(u8),
    /// Hint about the operating system (e.g. `"linux"`, `"windows"`).
    Os(String),
    /// Force a specific file format name.
    Format(String),
    /// Disable automatic relocation application.
    NoRelocations,
    /// Load as a raw binary without any header parsing.
    Raw,
}

/// A collection of [`LoaderHint`] values for a single load operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HintSet {
    hints: Vec<LoaderHint>,
}

impl HintSet {
    /// Create an empty hint set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hint.
    pub fn add(&mut self, hint: LoaderHint) {
        self.hints.push(hint);
    }

    /// Return the first architecture hint, if any.
    #[must_use]
    pub fn architecture(&self) -> Option<&str> {
        for h in &self.hints {
            if let LoaderHint::Architecture(s) = h {
                return Some(s);
            }
        }
        None
    }

    /// Return the base-address hint, if any.
    #[must_use]
    pub fn base_address(&self) -> Option<crate::address::Address> {
        for h in &self.hints {
            if let LoaderHint::BaseAddress(a) = h {
                return Some(*a);
            }
        }
        None
    }

    /// Return the entry-point hint, if any.
    #[must_use]
    pub fn entry_point(&self) -> Option<crate::address::Address> {
        for h in &self.hints {
            if let LoaderHint::EntryPoint(a) = h {
                return Some(*a);
            }
        }
        None
    }

    /// Return the endian hint, if any.
    #[must_use]
    pub fn endian(&self) -> Option<crate::endian::Endian> {
        for h in &self.hints {
            if let LoaderHint::Endian(e) = h {
                return Some(*e);
            }
        }
        None
    }

    /// Return `true` if a [`LoaderHint::Raw`] is present.
    #[must_use]
    pub fn is_raw(&self) -> bool {
        self.hints.iter().any(|h| matches!(h, LoaderHint::Raw))
    }

    /// Return `true` if [`LoaderHint::NoRelocations`] is present.
    #[must_use]
    pub fn no_relocations(&self) -> bool {
        self.hints
            .iter()
            .any(|h| matches!(h, LoaderHint::NoRelocations))
    }

    /// Iterate over all hints.
    pub fn iter(&self) -> impl Iterator<Item = &LoaderHint> {
        self.hints.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderOptions
// ─────────────────────────────────────────────────────────────────────────────

/// A builder for loader-specific configuration options.
///
/// Options are stored as a string → JSON-value map so that loaders can define
/// their own keys without changing the trait signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoaderOptions {
    options: HashMap<String, String>,
}

impl LoaderOptions {
    /// Create an empty options builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a string option.
    #[must_use]
    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Retrieve a string option by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(String::as_str)
    }

    /// Retrieve a boolean option (stored as `"true"` / `"false"`).
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.options.get(key)?.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    }

    /// Retrieve an integer option.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        let s = self.options.get(key)?;
        s.strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .map_or_else(|| s.parse().ok(), |hex| u64::from_str_radix(hex, 16).ok())
    }

    /// Return `true` if the given key is set.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.options.contains_key(key)
    }

    /// Iterate over `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.options.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of set options.
    #[must_use]
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// Return `true` if no options are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderInput
// ─────────────────────────────────────────────────────────────────────────────

/// The input passed to a [`Loader::load`] call.
#[derive(Debug, Clone)]
pub struct LoaderInput {
    /// A URI identifying the source (e.g. `"file:///tmp/malware.exe"`).
    pub uri: String,
    /// The raw binary data.
    pub data: Vec<u8>,
    /// Optional hints to guide the loader.
    pub hints: HintSet,
    /// Loader-specific configuration options.
    pub options: LoaderOptions,
}

impl LoaderInput {
    /// Create a minimal `LoaderInput` from a URI and data bytes.
    #[must_use]
    pub fn new(uri: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            uri: uri.into(),
            data,
            hints: HintSet::new(),
            options: LoaderOptions::new(),
        }
    }

    /// Attach a hint set.
    #[must_use]
    pub fn with_hints(mut self, hints: HintSet) -> Self {
        self.hints = hints;
        self
    }

    /// Attach loader options.
    #[must_use]
    pub fn with_options(mut self, options: LoaderOptions) -> Self {
        self.options = options;
        self
    }

    /// Add a single hint inline.
    #[must_use]
    pub fn with_hint(mut self, hint: LoaderHint) -> Self {
        self.hints.add(hint);
        self
    }

    /// Return the first 16 bytes (magic / header signature) for quick probing.
    #[must_use]
    pub fn magic(&self) -> &[u8] {
        let end = self.data.len().min(16);
        &self.data[..end]
    }

    /// Return `true` if the data starts with `bytes`.
    #[must_use]
    pub fn starts_with(&self, bytes: &[u8]) -> bool {
        self.data.starts_with(bytes)
    }

    /// Return `true` if the data contains `needle` starting at `offset`.
    #[must_use]
    pub fn has_magic_at(&self, offset: usize, needle: &[u8]) -> bool {
        let Some(end) = offset.checked_add(needle.len()) else {
            return false;
        };
        self.data.get(offset..end) == Some(needle)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NestedBinary
// ─────────────────────────────────────────────────────────────────────────────

/// A sub-binary found inside a container format.
///
/// Examples: a PE file inside a ZIP archive, a firmware image inside an OTA
/// package, or a DEX file inside an APK.
#[derive(Debug, Clone)]
pub struct NestedBinary {
    /// Human-readable name (e.g. the filename within the container).
    pub name: String,
    /// The raw data of the nested binary.
    pub data: Vec<u8>,
    /// Byte offset of this binary within the parent container's data.
    pub offset_in_parent: u64,
    /// Best-guess type of the nested binary.
    pub binary_type: BinaryType,
}

impl NestedBinary {
    /// Create a new nested binary descriptor.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        data: Vec<u8>,
        offset_in_parent: u64,
        binary_type: BinaryType,
    ) -> Self {
        Self {
            name: name.into(),
            data,
            offset_in_parent,
            binary_type,
        }
    }

    /// Return the size in bytes of this binary.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Convert this `NestedBinary` into a [`LoaderInput`] suitable for
    /// passing to a nested loader.
    #[must_use]
    pub fn into_loader_input(self) -> LoaderInput {
        LoaderInput::new(self.name, self.data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result returned by a successful [`Loader::load`] call.
pub struct LoadResult {
    /// The constructed binary view.
    pub view: BinaryView,
    /// Non-fatal warnings generated during loading.
    pub warnings: Vec<String>,
    /// Nested binaries discovered within the container.
    pub nested: Vec<NestedBinary>,
}

impl LoadResult {
    /// Create a minimal result with no warnings or nested binaries.
    pub const fn new(view: BinaryView) -> Self {
        Self {
            view,
            warnings: Vec::new(),
            nested: Vec::new(),
        }
    }

    /// Attach a warning message.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Add a nested binary.
    pub fn add_nested(&mut self, n: NestedBinary) {
        self.nested.push(n);
    }

    /// Return `true` if there are warnings.
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

impl std::fmt::Debug for LoadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadResult")
            .field("view", &"<BinaryView>")
            .field("warnings", &self.warnings.len())
            .field("nested", &self.nested.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader trait
// ─────────────────────────────────────────────────────────────────────────────

/// The core loader trait.
///
/// Implementations live in crates like `rustre-loader-pe`, `rustre-loader-elf`, etc.
#[async_trait::async_trait]
pub trait Loader: Send + Sync + std::fmt::Debug {
    /// Short, unique loader identifier (e.g. `"pe"`, `"elf"`, `"macho"`).
    fn name(&self) -> &str;

    /// Human-readable format name (e.g. `"Portable Executable (PE32+)"`).
    fn format_name(&self) -> &str {
        self.name()
    }

    /// Return a priority value used to break ties when multiple loaders match.
    ///
    /// Higher is better; the default is `50`.
    fn priority(&self) -> u32 {
        50
    }

    /// Quick probe: return `true` if this loader thinks it can handle `input`.
    ///
    /// This should be fast (no allocation-heavy parsing) — it is called for
    /// every registered loader on every `probe` call.
    fn can_load(&self, input: &LoaderInput) -> bool;

    /// Confidence score in the range `[0, 100]`.
    ///
    /// Used to rank multiple matching loaders.  The default returns `100` when
    /// [`can_load`](Self::can_load) returns `true`.
    fn confidence(&self, input: &LoaderInput) -> u8 {
        if self.can_load(input) { 100 } else { 0 }
    }

    /// Fully load a binary from `input`, returning a [`LoadResult`].
    ///
    /// # Errors
    /// Returns a [`CoreError`] if the binary cannot be loaded.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError>;

    /// Scan `input` for nested binaries without performing a full load.
    ///
    /// # Errors
    /// Returns a [`CoreError`] on I/O or parse failure.
    async fn find_nested(&self, input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Global registry of all registered [`Loader`] implementations.
#[derive(Default)]
pub struct LoaderRegistry {
    loaders: parking_lot::RwLock<Vec<Arc<dyn Loader>>>,
}

impl std::fmt::Debug for LoaderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoaderRegistry")
            .field("count", &self.loaders.read().len())
            .finish_non_exhaustive()
    }
}

impl LoaderRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a loader.
    pub fn register(&self, loader: Arc<dyn Loader>) {
        self.loaders.write().push(loader);
    }

    /// Find a loader by its [`Loader::name`].
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<Arc<dyn Loader>> {
        self.loaders
            .read()
            .iter()
            .find(|l| l.name() == name)
            .cloned()
    }

    /// Return all loaders that report [`can_load`](Loader::can_load) as `true`
    /// for `input`, sorted by descending confidence.
    #[must_use]
    pub fn probe(&self, input: &LoaderInput) -> Vec<Arc<dyn Loader>> {
        // Collect into an owned Vec then drop the read guard before sorting,
        // so subsequent operations don't hold the lock unnecessarily.
        let mut results: Vec<(u8, Arc<dyn Loader>)> = {
            let guard = self.loaders.read();
            guard
                .iter()
                .filter(|l| l.can_load(input))
                .map(|l| (l.confidence(input), Arc::clone(l)))
                .collect()
        };
        results.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(b.1.priority().cmp(&a.1.priority())));
        results.into_iter().map(|(_, l)| l).collect()
    }

    /// Run `probe` and return only the single best loader (highest confidence),
    /// or `None` if no loader matches.
    #[must_use]
    pub fn best_loader(&self, input: &LoaderInput) -> Option<Arc<dyn Loader>> {
        self.probe(input).into_iter().next()
    }

    /// Return all registered loaders.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<dyn Loader>> {
        self.loaders.read().clone()
    }

    /// Return the names of all registered loaders.
    #[must_use]
    pub fn list_names(&self) -> Vec<String> {
        self.loaders
            .read()
            .iter()
            .map(|l| l.name().to_owned())
            .collect()
    }

    /// Remove a loader by name.  Returns `true` if it was present.
    pub fn unregister(&self, name: &str) -> bool {
        let mut guard = self.loaders.write();
        let before = guard.len();
        guard.retain(|l| l.name() != name);
        guard.len() < before
    }

    /// Number of registered loaders.
    #[must_use]
    pub fn count(&self) -> usize {
        self.loaders.read().len()
    }

    /// Probe all registered loaders and return ALL matches, each with their
    /// confidence score.
    #[must_use]
    pub fn probe_all(&self, input: &LoaderInput) -> Vec<(Arc<dyn Loader>, u8)> {
        self.loaders
            .read()
            .iter()
            .map(|l| {
                let conf = l.confidence(input);
                (Arc::clone(l), conf)
            })
            .filter(|(_, c)| *c > 0)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo};
    use crate::binary_view::{BinaryView, Memory};
    use crate::endian::Endian;
    use crate::errors::CoreError;
    use crate::ids::ViewId;

    // ── Stub loader for tests ─────────────────────────────────────────────────

    #[derive(Debug)]
    struct StubLoader {
        name: &'static str,
        magic: &'static [u8],
        confidence: u8,
    }

    impl StubLoader {
        fn new(name: &'static str, magic: &'static [u8]) -> Self {
            Self {
                name,
                magic,
                confidence: 80,
            }
        }

        fn with_confidence(mut self, c: u8) -> Self {
            self.confidence = c;
            self
        }
    }

    #[derive(Debug)]
    struct StubArch;

    impl Architecture for StubArch {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, addr: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
            Ok(Instruction::new(
                addr,
                bytes.len().min(1),
                "nop",
                vec![0x90],
            ))
        }
        fn get_branches(&self, _: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }

    fn make_view(uri: &str) -> BinaryView {
        BinaryView::new(
            ViewId::from_raw(1),
            uri.to_string(),
            Arc::new(StubArch),
            Endian::Little,
            64,
            vec![],
            Memory::new(),
        )
    }

    #[async_trait::async_trait]
    impl Loader for StubLoader {
        fn name(&self) -> &str {
            self.name
        }
        fn can_load(&self, input: &LoaderInput) -> bool {
            input.starts_with(self.magic)
        }
        fn confidence(&self, input: &LoaderInput) -> u8 {
            if self.can_load(input) {
                self.confidence
            } else {
                0
            }
        }
        async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
            Ok(LoadResult::new(make_view(&input.uri)))
        }
        async fn find_nested(&self, _: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
            Ok(vec![])
        }
    }

    // ── BinaryType ────────────────────────────────────────────────────────────

    #[test]
    fn binary_type_predicates() {
        assert!(BinaryType::Executable.is_runnable());
        assert!(!BinaryType::Library.is_runnable());
        assert!(BinaryType::Library.is_library());
        assert!(BinaryType::Archive.is_library());
        assert!(!BinaryType::Executable.is_library());
    }

    #[test]
    fn binary_type_display() {
        assert_eq!(BinaryType::Executable.to_string(), "executable");
        assert_eq!(BinaryType::DotNet.to_string(), "dotnet");
        assert_eq!(BinaryType::Unknown.to_string(), "unknown");
    }

    // ── HintSet ───────────────────────────────────────────────────────────────

    #[test]
    fn hint_set_add_and_query() {
        let mut hs = HintSet::new();
        hs.add(LoaderHint::Architecture("x86_64".into()));
        hs.add(LoaderHint::BaseAddress(Address::new(0x4000_0000)));
        hs.add(LoaderHint::Endian(Endian::Little));
        hs.add(LoaderHint::Raw);

        assert_eq!(hs.architecture(), Some("x86_64"));
        assert_eq!(hs.base_address(), Some(Address::new(0x4000_0000)));
        assert_eq!(hs.endian(), Some(Endian::Little));
        assert!(hs.is_raw());
        assert!(!hs.no_relocations());
    }

    #[test]
    fn hint_set_empty() {
        let hs = HintSet::new();
        assert!(hs.architecture().is_none());
        assert!(hs.base_address().is_none());
        assert!(!hs.is_raw());
    }

    #[test]
    fn hint_set_entry_point() {
        let mut hs = HintSet::new();
        hs.add(LoaderHint::EntryPoint(Address::new(0x1000)));
        assert_eq!(hs.entry_point(), Some(Address::new(0x1000)));
    }

    // ── LoaderOptions ─────────────────────────────────────────────────────────

    #[test]
    fn loader_options_builder() {
        let opts = LoaderOptions::new()
            .set("rebase", "true")
            .set("base_address", "0x400000")
            .set("count", "10");

        assert_eq!(opts.get("rebase"), Some("true"));
        assert_eq!(opts.get_bool("rebase"), Some(true));
        assert_eq!(opts.get_u64("base_address"), Some(0x0040_0000));
        assert_eq!(opts.get_u64("count"), Some(10));
        assert!(opts.contains("rebase"));
        assert!(!opts.contains("nonexistent"));
        assert_eq!(opts.len(), 3);
    }

    #[test]
    fn loader_options_empty() {
        let opts = LoaderOptions::new();
        assert!(opts.is_empty());
        assert!(opts.get("key").is_none());
        assert!(opts.get_bool("key").is_none());
    }

    #[test]
    fn loader_options_get_bool_variants() {
        let opts = LoaderOptions::new()
            .set("a", "1")
            .set("b", "0")
            .set("c", "yes")
            .set("d", "no")
            .set("e", "garbage");
        assert_eq!(opts.get_bool("a"), Some(true));
        assert_eq!(opts.get_bool("b"), Some(false));
        assert_eq!(opts.get_bool("c"), Some(true));
        assert_eq!(opts.get_bool("d"), Some(false));
        assert_eq!(opts.get_bool("e"), None);
    }

    // ── LoaderInput ───────────────────────────────────────────────────────────

    #[test]
    fn loader_input_magic() {
        let data = b"MZ\x90\x00some garbage bytes here".to_vec();
        let input = LoaderInput::new("file://test.exe", data);
        assert!(input.starts_with(b"MZ"));
        assert_eq!(input.magic(), b"MZ\x90\x00some garbage");
    }

    #[test]
    fn loader_input_has_magic_at() {
        let data = b"\x00\x00\x00\x00PE\x00\x00rest".to_vec();
        let input = LoaderInput::new("test", data);
        assert!(input.has_magic_at(4, b"PE\x00\x00"));
        assert!(!input.has_magic_at(0, b"PE"));
    }

    #[test]
    fn loader_input_with_hint() {
        let input =
            LoaderInput::new("test", vec![]).with_hint(LoaderHint::Architecture("arm".into()));
        assert_eq!(input.hints.architecture(), Some("arm"));
    }

    // ── NestedBinary ──────────────────────────────────────────────────────────

    #[test]
    fn nested_binary_into_input() {
        let nested = NestedBinary::new("inner.exe", vec![0xAA, 0xBB], 512, BinaryType::Executable);
        assert_eq!(nested.size(), 2);
        let input = nested.into_loader_input();
        assert_eq!(input.uri, "inner.exe");
        assert_eq!(input.data, [0xAA, 0xBB]);
    }

    // ── LoadResult ────────────────────────────────────────────────────────────

    #[test]
    fn load_result_warnings_and_nested() {
        let mut result = LoadResult::new(make_view("test://bin"));
        assert!(!result.has_warnings());

        result.warn("section alignment padded");
        result.warn("unknown relocation type 42");
        assert!(result.has_warnings());
        assert_eq!(result.warnings.len(), 2);

        result.add_nested(NestedBinary::new(
            "res.dll",
            vec![],
            0x1000,
            BinaryType::Library,
        ));
        assert_eq!(result.nested.len(), 1);
    }

    // ── LoaderRegistry ────────────────────────────────────────────────────────

    #[test]
    fn registry_register_and_probe() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("pe", b"MZ")));
        reg.register(Arc::new(StubLoader::new("elf", b"\x7fELF")));

        let pe_input = LoaderInput::new("test.exe", b"MZ\x00\x00".to_vec());
        let matches = reg.probe(&pe_input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name(), "pe");
    }

    #[test]
    fn registry_best_loader() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("low", b"AA").with_confidence(30)));
        reg.register(Arc::new(StubLoader::new("high", b"AA").with_confidence(90)));

        let input = LoaderInput::new("t", b"AA".to_vec());
        let best = reg.best_loader(&input).unwrap();
        assert_eq!(best.name(), "high");
    }

    #[test]
    fn registry_no_match() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("pe", b"MZ")));

        let input = LoaderInput::new("t", b"ELF".to_vec());
        assert!(reg.best_loader(&input).is_none());
    }

    #[test]
    fn registry_list_names() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("pe", b"MZ")));
        reg.register(Arc::new(StubLoader::new("elf", b"\x7f")));
        let names = reg.list_names();
        assert!(names.contains(&"pe".to_string()));
        assert!(names.contains(&"elf".to_string()));
    }

    #[test]
    fn registry_unregister() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("temp", b"XX")));
        assert_eq!(reg.count(), 1);
        assert!(reg.unregister("temp"));
        assert_eq!(reg.count(), 0);
        assert!(!reg.unregister("temp"));
    }

    #[test]
    fn registry_probe_all() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("a", b"ZZ").with_confidence(50)));
        reg.register(Arc::new(StubLoader::new("b", b"ZZ").with_confidence(70)));
        reg.register(Arc::new(StubLoader::new("c", b"XX").with_confidence(90)));

        let input = LoaderInput::new("t", b"ZZ".to_vec());
        let all = reg.probe_all(&input);
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn registry_load_via_probe() {
        let reg = LoaderRegistry::new();
        reg.register(Arc::new(StubLoader::new("pe", b"MZ")));

        let input = LoaderInput::new("test.exe", b"MZ\x00\x00".to_vec());
        let loader = reg.best_loader(&input).unwrap();
        let result = loader.load(input).await.unwrap();
        assert!(!result.has_warnings());
    }

    #[tokio::test]
    async fn loader_find_nested_returns_empty_for_stub() {
        let loader = StubLoader::new("pe", b"MZ");
        let input = LoaderInput::new("t", b"MZ".to_vec());
        let nested = loader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }
}
