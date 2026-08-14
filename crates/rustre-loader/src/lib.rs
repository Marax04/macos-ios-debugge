//! `rustre-loader`
//!
//! Root loader coordinator for the `RustRE` Suite. Re-exports core loader types
//! and provides [`LoaderCoordinator`] for multi-loader orchestration.

pub mod address_resolver;
pub mod binary_view;
pub mod format_detector;
pub mod multi_arch_loader;
pub mod probe_cascade;
pub mod relocation_engine;
pub mod section_analysis;
pub mod section_merger;
pub mod loader_registry;
pub mod symbol_table;
pub mod loader_cache;
pub mod fat_binary_loader;
pub mod firmware_image_loader;
pub mod minidump_loader;
pub mod raw_binary_loader;
pub mod ihex_loader;
pub mod srec_loader;
pub mod fat_binary_splitter;
pub mod overlay_detector;
pub mod loader_config_validator;
// Sub-crate adapters moved to the `rustre-loader-registry` crate to break
// the Cargo dependency cycle (sub-crates depend on this hub for shared
// traits; the registry composes hub + sub-crates).

pub use rustre_core::loader::{
    HintSet, LoadResult, Loader, LoaderHint, LoaderInput, LoaderOptions, LoaderRegistry,
    NestedBinary, next_view_id,
};

use rustre_core::{binary_view::BinaryView, errors::CoreError, ids::ViewId};
use std::sync::Arc;
use std::sync::atomic::Ordering;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoaderCoordinatorError
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors produced by [`LoaderCoordinator`] operations.
#[derive(thiserror::Error, Debug)]
pub enum LoaderCoordinatorError {
    /// No registered loader is capable of handling the input.
    #[error("No loader found for input: {0}")]
    NoLoader(String),
    /// The underlying loader returned an error.
    #[error("Load error: {0}")]
    Load(#[from] CoreError),
    /// Multiple loaders matched and the caller must pick one explicitly.
    #[error("Multiple loaders ambiguous: {0}")]
    Ambiguous(String),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoaderCoordinator
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Multi-loader coordinator.
///
/// Wraps a [`LoaderRegistry`] and provides higher-level APIs such as
/// [`auto_load`](Self::auto_load) (which probes all registered loaders and uses
/// the first match) and [`probe_all`](Self::probe_all).
pub struct LoaderCoordinator {
    registry: Arc<LoaderRegistry>,
    /// Monotonically-increasing count of loaders added via [`Self::register`].
    loader_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for LoaderCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoaderCoordinator")
            .field("loader_count", &self.loader_count())
            .finish_non_exhaustive()
    }
}

impl LoaderCoordinator {
    /// Create a coordinator backed by a fresh, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: Arc::new(LoaderRegistry::new()),
            loader_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Create a coordinator backed by an existing shared registry.
    #[must_use]
    pub fn new_with_registry(registry: Arc<LoaderRegistry>) -> Self {
        Self {
            registry,
            loader_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Access the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &LoaderRegistry {
        &self.registry
    }

    /// Register a loader with the underlying registry.
    pub fn register<L: Loader + 'static>(&self, loader: Arc<L>) {
        self.registry.register(loader);
        self.loader_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Probe all registered loaders and use the first that can handle `input`.
    ///
    /// # Errors
    /// - [`LoaderCoordinatorError::NoLoader`] —" no loader matched the input.
    /// - [`LoaderCoordinatorError::Load`]    —" the loader itself returned an error.
    pub async fn auto_load(
        &self,
        input: LoaderInput,
    ) -> Result<BinaryView, LoaderCoordinatorError> {
        let candidates = self.registry.probe(&input);
        if candidates.is_empty() {
            return Err(LoaderCoordinatorError::NoLoader(input.uri.clone()));
        }
        // Use the first matching loader.
        let loader = &candidates[0];
        let result = loader.load(input).await?;
        Ok(result.view)
    }

    /// Like [`auto_load`](Self::auto_load) but also returns the [`ViewId`] of
    /// the loaded [`BinaryView`], so callers can correlate the view with
    /// downstream services keyed by id (analysis cache, IR store, etc.).
    ///
    /// # Errors
    /// Same as [`auto_load`](Self::auto_load).
    pub async fn auto_load_with_id(
        &self,
        input: LoaderInput,
    ) -> Result<(ViewId, BinaryView), LoaderCoordinatorError> {
        let candidates = self.registry.probe(&input);
        if candidates.is_empty() {
            return Err(LoaderCoordinatorError::NoLoader(input.uri.clone()));
        }
        let loader = &candidates[0];
        let result = loader.load(input).await?;
        let id = result.view.id;
        Ok((id, result.view))
    }

    /// Probe all registered loaders and return every loader that reports it can
    /// handle `input`.
    #[must_use]
    pub fn probe_all(&self, input: &LoaderInput) -> Vec<Arc<dyn Loader>> {
        self.registry.probe(input)
    }

    /// Number of loaders registered in the underlying registry.
    ///
    /// Returns the exact count of loaders added via [`Self::register`].
    #[must_use]
    pub fn loader_count(&self) -> usize {
        self.loader_count.load(Ordering::Relaxed)
    }
}

impl LoaderCoordinator {
    /// Alias for [`loader_count`](Self::loader_count); kept for testing convenience.
    #[doc(hidden)]
    #[must_use]
    pub fn _loader_count_approx(&self) -> usize {
        self.loader_count()
    }
}

impl Default for LoaderCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BinaryFormat
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Recognised binary file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    /// ELF executable or shared library.
    Elf,
    /// Portable Executable (Windows).
    Pe,
    /// Mach-O binary (Apple platforms).
    MachO,
    /// Mach-O fat / universal binary.
    MachOFat,
    /// Java class file.
    JavaClass,
    /// ZIP/JAR archive.
    Zip,
    /// WebAssembly binary module.
    Wasm,
    /// Raw / unknown format.
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
            Self::MachOFat => write!(f, "Mach-O Fat"),
            Self::JavaClass => write!(f, "Java Class"),
            Self::Zip => write!(f, "ZIP/JAR"),
            Self::Wasm => write!(f, "WebAssembly"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FormatDetector
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Identifies binary file formats from magic bytes.
///
/// All detection is done without I/O —" operates purely on in-memory byte slices.
#[derive(Debug, Default)]
pub struct FormatDetector;

impl FormatDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect the format of `data` from its magic bytes.
    ///
    /// Returns [`BinaryFormat::Unknown`] for unrecognised formats.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> BinaryFormat {
        if data.starts_with(b"\x7fELF") {
            return BinaryFormat::Elf;
        }
        if data.starts_with(b"MZ") {
            return BinaryFormat::Pe;
        }
        // Mach-O little-endian 32-bit: 0xCEFAEDFE, 64-bit: 0xCFFAEDFE
        if data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
            || data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        {
            return BinaryFormat::MachO;
        }
        // Mach-O big-endian 32-bit: 0xFEEDFACE, 64-bit: 0xFEEDFACF
        if data.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
            || data.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        {
            return BinaryFormat::MachO;
        }
        // Mach-O fat binary: 0xCAFEBABE (also Java, disambiguate by length)
        if data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            // Java class: major version in bytes [6..8] is typically 44—"67
            if data.len() >= 8 {
                let major = u16::from_be_bytes([data[6], data[7]]);
                if (44..=80).contains(&major) {
                    return BinaryFormat::JavaClass;
                }
            }
            return BinaryFormat::MachOFat;
        }
        if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
            return BinaryFormat::Zip;
        }
        if data.starts_with(b"\x00asm") {
            return BinaryFormat::Wasm;
        }
        BinaryFormat::Unknown
    }

    /// Return `true` if `data` is an ELF binary.
    #[must_use]
    pub fn is_elf(&self, data: &[u8]) -> bool {
        self.detect(data) == BinaryFormat::Elf
    }

    /// Return `true` if `data` is a PE binary.
    #[must_use]
    pub fn is_pe(&self, data: &[u8]) -> bool {
        self.detect(data) == BinaryFormat::Pe
    }

    /// Return `true` if `data` is a Mach-O binary.
    #[must_use]
    pub fn is_macho(&self, data: &[u8]) -> bool {
        matches!(
            self.detect(data),
            BinaryFormat::MachO | BinaryFormat::MachOFat
        )
    }

    /// Return `true` if `data` appears to be a Java class file.
    #[must_use]
    pub fn is_java_class(&self, data: &[u8]) -> bool {
        self.detect(data) == BinaryFormat::JavaClass
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoadResult / BatchLoader
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Outcome of loading a single input in a batch operation.
pub struct BatchLoadOutcome {
    /// URI of the input that was loaded.
    pub uri: String,
    /// Detected format (if format detection was performed).
    pub format: BinaryFormat,
    /// The loaded view, if loading succeeded.
    pub view: Option<rustre_core::binary_view::BinaryView>,
    /// Error message, if loading failed.
    pub error: Option<String>,
}

impl std::fmt::Debug for BatchLoadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchLoadOutcome")
            .field("uri", &self.uri)
            .field("format", &self.format)
            .field("view", &self.view.as_ref().map(|_| "<BinaryView>"))
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl BatchLoadOutcome {
    /// Returns `true` if loading succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.view.is_some()
    }
}

/// Batch loader: load multiple [`LoaderInput`]s concurrently using a shared
/// [`LoaderCoordinator`].
pub struct BatchLoader {
    coordinator: std::sync::Arc<LoaderCoordinator>,
    detector: FormatDetector,
}

impl BatchLoader {
    /// Create a [`BatchLoader`] backed by `coordinator`.
    #[must_use]
    pub const fn new(coordinator: std::sync::Arc<LoaderCoordinator>) -> Self {
        Self {
            coordinator,
            detector: FormatDetector::new(),
        }
    }

    /// Load all inputs sequentially and collect outcomes.
    ///
    /// Never panics —" failures are captured as [`BatchLoadOutcome::error`].
    pub async fn load_all(&self, inputs: Vec<LoaderInput>) -> Vec<BatchLoadOutcome> {
        let mut outcomes = Vec::with_capacity(inputs.len());
        for input in inputs {
            let format = self.detector.detect(&input.data);
            let uri = input.uri.clone();
            match self.coordinator.auto_load(input).await {
                Ok(view) => outcomes.push(BatchLoadOutcome {
                    uri,
                    format,
                    view: Some(view),
                    error: None,
                }),
                Err(e) => outcomes.push(BatchLoadOutcome {
                    uri,
                    format,
                    view: None,
                    error: Some(e.to_string()),
                }),
            }
        }
        outcomes
    }

    /// Return a reference to the coordinator.
    #[must_use]
    pub fn coordinator(&self) -> &LoaderCoordinator {
        &self.coordinator
    }

    /// Return a reference to the format detector.
    #[must_use]
    pub const fn detector(&self) -> &FormatDetector {
        &self.detector
    }
}

impl std::fmt::Debug for BatchLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchLoader").finish_non_exhaustive()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoaderPipeline
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A loading pipeline: format detection â†' loader selection â†' view production.
///
/// Combines [`FormatDetector`] and [`LoaderCoordinator`] into a single
/// higher-level object with named pipeline stages and optional tracing.
pub struct LoaderPipeline {
    coordinator: LoaderCoordinator,
    detector: FormatDetector,
    name: String,
}

impl LoaderPipeline {
    /// Create a new pipeline.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            coordinator: LoaderCoordinator::new(),
            detector: FormatDetector::new(),
            name: name.into(),
        }
    }

    /// Register a loader with the pipeline.
    pub fn add_loader<L: Loader + 'static>(&self, loader: std::sync::Arc<L>) {
        self.coordinator.register(loader);
    }

    /// Return the pipeline name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Detect the format of `data` without loading.
    #[must_use]
    pub fn detect_format(&self, data: &[u8]) -> BinaryFormat {
        self.detector.detect(data)
    }

    /// Load `input`, returning the format and binary view.
    ///
    /// # Errors
    ///
    /// Returns [`LoaderCoordinatorError`] if no loader is found or loading fails.
    pub async fn run(
        &self,
        input: LoaderInput,
    ) -> Result<(BinaryFormat, rustre_core::binary_view::BinaryView), LoaderCoordinatorError> {
        let format = self.detector.detect(&input.data);
        let view = self.coordinator.auto_load(input).await?;
        Ok((format, view))
    }

    /// Return the number of registered loaders.
    #[must_use]
    pub fn loader_count(&self) -> usize {
        self.coordinator.loader_count()
    }
}

impl std::fmt::Debug for LoaderPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoaderPipeline")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DetectedFormat
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Fine-grained format detected purely from magic bytes, with ELF
/// class/endian split and Lua version carried inline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectedFormat {
    /// ELF 32-bit little-endian.
    Elf32Le,
    /// ELF 32-bit big-endian.
    Elf32Be,
    /// ELF 64-bit little-endian.
    Elf64Le,
    /// ELF 64-bit big-endian.
    Elf64Be,
    /// Portable Executable (Windows).
    Pe,
    /// Mach-O 64-bit little-endian (0xCFFAEDFE).
    MachoLe64,
    /// Mach-O 32-bit little-endian (0xCEFAEDFE).
    MachoLe32,
    /// Mach-O 32-bit big-endian (0xFEEDFACE).
    MachoBe32,
    /// Mach-O 64-bit big-endian (0xFEEDFACF).
    MachoBe64,
    /// Mach-O fat / universal binary (0xCAFEBABE, non-Java).
    FatMacho,
    /// WebAssembly binary module.
    Wasm,
    /// Lua bytecode; version byte at offset 4.
    LuaBytecode(u8),
    /// `LuaJIT` bytecode.
    LuaJit,
    /// .NET / CIL assembly.
    DotNet,
    /// Java class file.
    JavaClass,
    /// Android Dalvik Executable (.dex).
    AndroidDex,
    /// PDF document.
    Pdf,
    /// ZIP archive (includes JAR, APK, DOCX, —¦).
    Zip,
    /// OLE Compound Document (DOC, XLS, PPT, —¦).
    OleCompoundDoc,
    /// Intel HEX text records.
    IntelHex,
    /// Motorola S-record text format.
    MotorolaSrec,
    /// Unrecognised / raw format.
    Unknown,
}

impl std::fmt::Display for DetectedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf32Le => write!(f, "ELF-32LE"),
            Self::Elf32Be => write!(f, "ELF-32BE"),
            Self::Elf64Le => write!(f, "ELF-64LE"),
            Self::Elf64Be => write!(f, "ELF-64BE"),
            Self::Pe => write!(f, "PE"),
            Self::MachoLe64 => write!(f, "Mach-O LE64"),
            Self::MachoLe32 => write!(f, "Mach-O LE32"),
            Self::MachoBe32 => write!(f, "Mach-O BE32"),
            Self::MachoBe64 => write!(f, "Mach-O BE64"),
            Self::FatMacho => write!(f, "Mach-O Fat"),
            Self::Wasm => write!(f, "WebAssembly"),
            Self::LuaBytecode(v) => write!(f, "Lua Bytecode (version {v:#04x})"),
            Self::LuaJit => write!(f, "LuaJIT Bytecode"),
            Self::DotNet => write!(f, ".NET/CIL"),
            Self::JavaClass => write!(f, "Java Class"),
            Self::AndroidDex => write!(f, "Android DEX"),
            Self::Pdf => write!(f, "PDF"),
            Self::Zip => write!(f, "ZIP"),
            Self::OleCompoundDoc => write!(f, "OLE Compound Document"),
            Self::IntelHex => write!(f, "Intel HEX"),
            Self::MotorolaSrec => write!(f, "Motorola S-Record"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// AutoLoader  —" magic-byte based format auto-detection
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Stateless magic-byte detector that returns a [`DetectedFormat`].
///
/// All detection is O(1) and allocation-free; it operates on a shared byte
/// slice and does no I/O.
///
/// # Example
/// ```
/// use rustre_loader::AutoLoader;
/// let fmt = AutoLoader::detect_format(b"\x7fELF\x02\x01\x01\x00");
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct AutoLoader;

impl AutoLoader {
    /// Create a new `AutoLoader`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect the format of `bytes` from its magic signature.
    ///
    /// Returns [`DetectedFormat::Unknown`] for any unrecognised byte sequence.
    #[must_use]
    pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
        if bytes.len() < 2 {
            return DetectedFormat::Unknown;
        }

        // ELF: 0x7f 'E' 'L' 'F'
        if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
            return Self::detect_elf(bytes);
        }

        // PE: 'M' 'Z'
        if bytes.starts_with(b"MZ") {
            return DetectedFormat::Pe;
        }

        // Mach-O 64-bit LE: 0xCF 0xFA 0xED 0xFE
        if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
            return DetectedFormat::MachoLe64;
        }

        // Mach-O 32-bit LE: 0xCE 0xFA 0xED 0xFE
        if bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
            return DetectedFormat::MachoLe32;
        }

        // Mach-O 64-bit BE: 0xFE 0xED 0xFA 0xCF
        if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
            return DetectedFormat::MachoBe64;
        }

        // Mach-O 32-bit BE: 0xFE 0xED 0xFA 0xCE
        if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) {
            return DetectedFormat::MachoBe32;
        }

        // 0xCAFEBABE: Fat Mach-O *or* Java class —" disambiguate by Java major
        if bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            if bytes.len() >= 8 {
                let minor = u16::from_be_bytes([bytes[4], bytes[5]]);
                let major = u16::from_be_bytes([bytes[6], bytes[7]]);
                // Java class files have minor=0 (or 65535 for preview) and
                // major in [44, 80] (Java 1—"24).
                let _ = minor; // minor version unused for detection
                if (44..=80).contains(&major) {
                    return DetectedFormat::JavaClass;
                }
            }
            return DetectedFormat::FatMacho;
        }

        // WebAssembly: 0x00 'a' 's' 'm'
        if bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]) {
            return DetectedFormat::Wasm;
        }

        // Lua bytecode: 0x1b 'L' 'u' 'a' <version>
        if bytes.starts_with(&[0x1b, b'L', b'u', b'a']) {
            let ver = if bytes.len() >= 5 { bytes[4] } else { 0 };
            return DetectedFormat::LuaBytecode(ver);
        }

        // LuaJIT bytecode: 0x1b 'L' 'J'
        if bytes.starts_with(&[0x1b, b'L', b'J']) {
            return DetectedFormat::LuaJit;
        }

        // PDF: '%' 'P' 'D' 'F'
        if bytes.starts_with(b"%PDF") {
            return DetectedFormat::Pdf;
        }

        // ZIP: 'P' 'K' 0x03 0x04
        if bytes.starts_with(&[b'P', b'K', 0x03, 0x04]) {
            return DetectedFormat::Zip;
        }

        // OLE Compound Document: 0xD0 0xCF 0x11 0xE0
        if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
            return DetectedFormat::OleCompoundDoc;
        }

        // Android DEX: "dex\n"
        if bytes.starts_with(b"dex\n") {
            return DetectedFormat::AndroidDex;
        }

        // .NET PE is caught by the 'MZ' check above; mark here for completeness.
        // Standalone MSIL detection by COM descriptor magic would require
        // parsing the PE header fully —" defer to the PE loader's probe().

        // Intel HEX: first byte is ':'
        if bytes.first() == Some(&b':') {
            return DetectedFormat::IntelHex;
        }

        // Motorola S-Record: 'S' followed by a digit 0-9
        if bytes.len() >= 2 && bytes[0] == b'S' && bytes[1].is_ascii_digit() {
            return DetectedFormat::MotorolaSrec;
        }

        DetectedFormat::Unknown
    }

    // â"€â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn detect_elf(bytes: &[u8]) -> DetectedFormat {
        // ELF ident[4] = class  (1 = 32-bit, 2 = 64-bit)
        // ELF ident[5] = data   (1 = LE, 2 = BE)
        if bytes.len() < 6 {
            return DetectedFormat::Unknown;
        }
        let class = bytes[4];
        let endian = bytes[5];
        match (class, endian) {
            (1, 1) => DetectedFormat::Elf32Le,
            (1, 2) => DetectedFormat::Elf32Be,
            (2, 1) => DetectedFormat::Elf64Le,
            (2, 2) => DetectedFormat::Elf64Be,
            _ => DetectedFormat::Unknown,
        }
    }

    /// Convenience: detect and return whether `bytes` is any ELF variant.
    #[must_use]
    pub fn is_elf(bytes: &[u8]) -> bool {
        matches!(
            Self::detect_format(bytes),
            DetectedFormat::Elf32Le
                | DetectedFormat::Elf32Be
                | DetectedFormat::Elf64Le
                | DetectedFormat::Elf64Be
        )
    }

    /// Convenience: detect and return whether `bytes` is any Mach-O variant.
    #[must_use]
    pub fn is_macho(bytes: &[u8]) -> bool {
        matches!(
            Self::detect_format(bytes),
            DetectedFormat::MachoLe32
                | DetectedFormat::MachoLe64
                | DetectedFormat::MachoBe32
                | DetectedFormat::MachoBe64
                | DetectedFormat::FatMacho
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// SectionInfo / SymbolInfo / ImportInfo / ExportInfo
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Metadata for a single binary section or segment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SectionInfo {
    /// Section name (e.g. `.text`, `__TEXT`).
    pub name: String,
    /// Virtual address where the section is mapped at runtime.
    pub virtual_addr: u64,
    /// Virtual size of the section in bytes.
    pub virtual_size: u64,
    /// Offset of raw data within the file image.
    pub raw_offset: u64,
    /// Size of raw data in the file image.
    pub raw_size: u64,
    /// Platform-specific section flags / characteristics.
    pub flags: u32,
}

impl SectionInfo {
    /// Construct a new `SectionInfo`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        virtual_addr: u64,
        virtual_size: u64,
        raw_offset: u64,
        raw_size: u64,
        flags: u32,
    ) -> Self {
        Self {
            name: name.into(),
            virtual_addr,
            virtual_size,
            raw_offset,
            raw_size,
            flags,
        }
    }
}

/// A single symbol record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SymbolInfo {
    /// Demangled or raw symbol name.
    pub name: String,
    /// Symbol virtual address.
    pub addr: u64,
    /// Human-readable kind tag: `"function"`, `"object"`, `"section"`, —¦
    pub kind: String,
    /// Symbol size in bytes (0 if unknown).
    pub size: u64,
}

impl SymbolInfo {
    /// Construct a new `SymbolInfo`.
    #[must_use]
    pub fn new(name: impl Into<String>, addr: u64, kind: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            addr,
            kind: kind.into(),
            size,
        }
    }
}

/// An import record (function or data imported from another module).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportInfo {
    /// Originating DLL / shared library name.
    pub dll: String,
    /// Import name (may be empty for ordinal-only imports).
    pub name: String,
    /// Resolved import address / IAT slot address.
    pub addr: u64,
    /// Import ordinal, if present.
    pub ordinal: Option<u16>,
}

impl ImportInfo {
    /// Construct a named import.
    #[must_use]
    pub fn named(dll: impl Into<String>, name: impl Into<String>, addr: u64) -> Self {
        Self {
            dll: dll.into(),
            name: name.into(),
            addr,
            ordinal: None,
        }
    }

    /// Construct an ordinal-only import.
    #[must_use]
    pub fn ordinal(dll: impl Into<String>, ordinal: u16, addr: u64) -> Self {
        Self {
            dll: dll.into(),
            name: String::new(),
            addr,
            ordinal: Some(ordinal),
        }
    }
}

/// An export record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExportInfo {
    /// Export name (may be empty for unnamed ordinal exports).
    pub name: String,
    /// Export virtual address.
    pub addr: u64,
    /// Export ordinal.
    pub ordinal: u16,
    /// Forwarded target string, e.g. `"NTDLL.RtlAllocateHeap"`.
    pub forwarded_to: Option<String>,
}

impl ExportInfo {
    /// Construct a regular named export.
    #[must_use]
    pub fn named(name: impl Into<String>, addr: u64, ordinal: u16) -> Self {
        Self {
            name: name.into(),
            addr,
            ordinal,
            forwarded_to: None,
        }
    }

    /// Construct a forwarded export.
    #[must_use]
    pub fn forwarded(name: impl Into<String>, ordinal: u16, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            addr: 0,
            ordinal,
            forwarded_to: Some(target.into()),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RichLoadResult
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Rich result produced by the multi-format loader layer.
///
/// Unlike the thin [`LoadResult`] type from `rustre-core`, `RichLoadResult`
/// carries all the structured metadata that a format-specific loader can
/// surface: sections, symbols, imports, exports, and the raw byte image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RichLoadResult {
    /// Human-readable format string, e.g. `"ELF-64LE"`.
    pub format: String,
    /// Architecture tag, e.g. `"x86_64"`, `"arm64"`, `"wasm32"`.
    pub arch: String,
    /// Pointer / address width in bits (32 or 64).
    pub bits: u8,
    /// Endianness: `"little"` or `"big"`.
    pub endian: String,
    /// Optional entry-point virtual address.
    pub entry_point: Option<u64>,
    /// Image base address (0 for position-independent objects).
    pub base_address: u64,
    /// Section table.
    pub sections: Vec<SectionInfo>,
    /// Symbol table (static + dynamic).
    pub symbols: Vec<SymbolInfo>,
    /// Import table.
    pub imports: Vec<ImportInfo>,
    /// Export table.
    pub exports: Vec<ExportInfo>,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

impl RichLoadResult {
    /// Construct a minimal `RichLoadResult` from a raw byte image.
    ///
    /// The format, arch, endian, bits, and entry-point fields default to
    /// empty / `None`; use the builder setters to populate them.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            format: String::new(),
            arch: String::new(),
            bits: 0,
            endian: String::new(),
            entry_point: None,
            base_address: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            data,
        }
    }

    /// Builder: set the format string.
    #[must_use]
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = format.into();
        self
    }

    /// Builder: set the architecture tag.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = arch.into();
        self
    }

    /// Builder: set the pointer width.
    #[must_use]
    pub const fn with_bits(mut self, bits: u8) -> Self {
        self.bits = bits;
        self
    }

    /// Builder: set the endianness tag.
    #[must_use]
    pub fn with_endian(mut self, endian: impl Into<String>) -> Self {
        self.endian = endian.into();
        self
    }

    /// Builder: set the entry-point address.
    #[must_use]
    pub const fn with_entry_point(mut self, ep: u64) -> Self {
        self.entry_point = Some(ep);
        self
    }

    /// Builder: set the image base address.
    #[must_use]
    pub const fn with_base_address(mut self, base: u64) -> Self {
        self.base_address = base;
        self
    }

    /// Builder: add a section.
    #[must_use]
    pub fn with_section(mut self, section: SectionInfo) -> Self {
        self.sections.push(section);
        self
    }

    /// Builder: add a symbol.
    #[must_use]
    pub fn with_symbol(mut self, sym: SymbolInfo) -> Self {
        self.symbols.push(sym);
        self
    }

    /// Builder: add an import.
    #[must_use]
    pub fn with_import(mut self, imp: ImportInfo) -> Self {
        self.imports.push(imp);
        self
    }

    /// Builder: add an export.
    #[must_use]
    pub fn with_export(mut self, exp: ExportInfo) -> Self {
        self.exports.push(exp);
        self
    }

    /// Compute the SHA-256 digest of the raw data and return it as a
    /// lower-case hex string.
    ///
    /// Uses the `sha2` crate.
    #[must_use]
    pub fn sha256(&self) -> String {
        sha256(&self.data)
    }

    /// Compute the MD5 digest of the raw data and return it as a
    /// lower-case hex string.
    ///
    /// Uses the `md-5` crate.
    #[must_use]
    pub fn md5(&self) -> String {
        md5(&self.data)
    }

    /// Return the total number of mapped bytes across all sections.
    #[must_use]
    pub fn total_virtual_size(&self) -> u64 {
        self.sections.iter().map(|s| s.virtual_size).sum()
    }

    /// Return the section whose [`SectionInfo::virtual_addr`] range contains
    /// `va`, or `None` if no section covers that address.
    #[must_use]
    pub fn section_at(&self, va: u64) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|s| va >= s.virtual_addr && va < s.virtual_addr.saturating_add(s.virtual_size))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoaderInput (standalone, not re-exported from rustre-core)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Source of bytes for the multi-format loader layer.
///
/// Distinct from `rustre_core::loader::LoaderInput` (which is re-exported at
/// the crate root).  This type is used by [`MultiFormatRegistry`] and the
/// standalone `to_bytes` helper.
#[derive(Debug, Clone)]
pub enum MultiLoaderInput {
    /// In-memory byte buffer.
    Bytes(Vec<u8>),
    /// File to read from disk at load time.
    File(std::path::PathBuf),
    /// Already-mapped memory region at a known base address.
    Memory {
        /// Virtual base address of the region.
        base: u64,
        /// Raw bytes of the region.
        data: Vec<u8>,
    },
}

impl MultiLoaderInput {
    /// Consume the input and return its byte contents.
    ///
    /// For [`MultiLoaderInput::File`] this performs a synchronous file read.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] if the file cannot be read.
    pub fn to_bytes(self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Bytes(v) => Ok(v),
            Self::Memory { data, .. } => Ok(data),
            Self::File(path) => std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display())),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// MultiFormatLoader trait
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Format-specific loader trait used by [`MultiFormatRegistry`].
///
/// Implementations provide format identification and parsing; they operate
/// on raw byte slices and return a [`RichLoadResult`].
pub trait MultiFormatLoader: std::fmt::Debug + Send + Sync {
    /// Short, unique loader name (e.g. `"elf"`, `"pe"`, `"wasm"`).
    fn name(&self) -> &'static str;

    /// File extensions this loader typically handles (without leading dot).
    ///
    /// Used as a fallback hint when magic-byte confidence is low.
    fn extensions(&self) -> &[&str];

    /// Probe `bytes` and return a confidence score.
    ///
    /// * `0`   —" definitely not this format.
    /// * `128` —" plausible match (e.g. extension-only heuristic).
    /// * `255` —" perfect magic-byte match.
    fn probe(&self, bytes: &[u8]) -> u8;

    /// One-line human-readable description of the format this loader handles.
    fn description(&self) -> &'static str;

    /// Parse `bytes` into a [`RichLoadResult`].
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on parse failure.
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult>;
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// MultiFormatRegistry
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Registry and coordinator for [`MultiFormatLoader`] implementations.
///
/// Provides magic-byte auto-detection, per-confidence ranking, and
/// by-name loader lookup.
pub struct MultiFormatRegistry {
    loaders: parking_lot::RwLock<Vec<Arc<dyn MultiFormatLoader>>>,
}

impl std::fmt::Debug for MultiFormatRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.loaders.read().len();
        f.debug_struct("MultiFormatRegistry")
            .field("loader_count", &count)
            .finish_non_exhaustive()
    }
}

impl Default for MultiFormatRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiFormatRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            loaders: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a loader.
    pub fn register<L: MultiFormatLoader + 'static>(&self, loader: L) {
        self.loaders.write().push(Arc::new(loader));
    }

    /// Register a loader behind an existing `Arc`.
    pub fn register_arc(&self, loader: Arc<dyn MultiFormatLoader>) {
        self.loaders.write().push(loader);
    }

    /// Probe `data` with all registered loaders and return a list of
    /// `(loader_name, confidence)` tuples sorted by confidence descending.
    #[must_use]
    pub fn probe_all(&self, data: &[u8]) -> Vec<(String, u8)> {
        let mut results: Vec<(String, u8)> = {
            let loaders = self.loaders.read();
            loaders
                .iter()
                .map(|l| (l.name().to_owned(), l.probe(data)))
                .filter(|(_, conf)| *conf > 0)
                .collect()
        };
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    /// Auto-detect the format of `data` and load it with the highest-confidence
    /// loader.
    ///
    /// # Errors
    /// - `anyhow::Error` with "no loader found" if no loader has confidence > 0.
    /// - Propagates the loader's parse error on failure.
    pub fn auto_load(&self, data: &[u8]) -> anyhow::Result<RichLoadResult> {
        let best = {
            let loaders = self.loaders.read();
            loaders
                .iter()
                .map(|l| (Arc::clone(l), l.probe(data)))
                .filter(|(_, c)| *c > 0)
                .max_by_key(|(_, c)| *c)
                .map(|(l, _)| l)
        };

  best.map_or_else(|| {
            let detected = AutoLoader::detect_format(data);
            Err(anyhow::anyhow!(
                "no registered loader can handle format: {detected}"
            ))
        }, |loader| loader.load(data))
    }

    /// Load `data` using the loader identified by `loader_name`.
    ///
    /// # Errors
    /// - `anyhow::Error` with "loader not found" if the name is unknown.
    /// - Propagates the loader's parse error on failure.
    pub fn load_with(&self, loader_name: &str, data: &[u8]) -> anyhow::Result<RichLoadResult> {
        let loader = {
            let loaders = self.loaders.read();
            loaders
                .iter()
                .find(|l| l.name() == loader_name)
                .map(Arc::clone)
        };

  loader.map_or_else(|| Err(anyhow::anyhow!("loader not found: {loader_name}")), |l| l.load(data))
    }

    /// Return the loader with the given name, or `None`.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<dyn MultiFormatLoader>> {
        self.loaders
            .read()
            .iter()
            .find(|l| l.name() == name)
            .map(Arc::clone)
    }

    /// Number of registered loaders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaders.read().len()
    }

    /// Returns `true` if no loaders are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaders.read().is_empty()
    }

    /// Return names of all registered loaders.
    #[must_use]
    pub fn loader_names(&self) -> Vec<String> {
        self.loaders
            .read()
            .iter()
            .map(|l| l.name().to_owned())
            .collect()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// sha256 helper
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Compute the SHA-256 digest of `data` and return it as a lower-case hex
/// string.
///
/// Uses the `sha2` crate (added to `Cargo.toml`).
///
/// # Example
/// ```
/// use rustre_loader::sha256;
/// let digest = sha256(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
#[must_use]
pub fn sha256(data: &[u8]) -> String {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in &hash {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Compute the MD5 digest of `data` and return its lower-case hex
/// string.
///
/// Uses the `md-5` crate (added to `Cargo.toml`).
///
/// # Example
/// ```
/// use rustre_loader::md5;
/// let digest = md5(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn md5(data: &[u8]) -> String {
    use md5::Digest as _;
    let hash = md5::Md5::digest(data);
    let mut out = String::with_capacity(32);
    for byte in &hash {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Built-in stub loaders
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// These provide correct probe() scores so auto_load() can dispatch correctly
// even before a full format-specific loader crate is registered.

/// Stub loader for ELF binaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct ElfStubLoader;

impl MultiFormatLoader for ElfStubLoader {
    fn name(&self) -> &'static str {
        "elf"
    }
    fn extensions(&self) -> &[&str] {
        &["elf", "so", "axf", "out"]
    }
    fn description(&self) -> &'static str {
        "ELF executable / shared library / relocatable"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
            255
        } else {
            0
        }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        if bytes.len() < 6 {
            return Err(anyhow::anyhow!("ELF image too short"));
        }
        let fmt = AutoLoader::detect_format(bytes);
        let (bits, endian) = match fmt {
            DetectedFormat::Elf32Le => (32u8, "little"),
            DetectedFormat::Elf32Be => (32u8, "big"),
            DetectedFormat::Elf64Le => (64u8, "little"),
            DetectedFormat::Elf64Be => (64u8, "big"),
            _ => (0u8, "unknown"),
        };
        Ok(RichLoadResult::new(bytes.to_vec())
            .with_format(fmt.to_string())
            .with_bits(bits)
            .with_endian(endian))
    }
}

/// Stub loader for PE / COFF binaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct PeStubLoader;

impl MultiFormatLoader for PeStubLoader {
    fn name(&self) -> &'static str {
        "pe"
    }
    fn extensions(&self) -> &[&str] {
        &["exe", "dll", "sys", "efi", "scr", "ocx"]
    }
    fn description(&self) -> &'static str {
        "Windows Portable Executable (PE32/PE32+)"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(b"MZ") {
            200
        } else {
            0
        }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        // Distinguish the two rejection reasons: reporting "missing MZ magic"
        // for a well-formed magic that is merely truncated sends whoever reads
        // the diagnostic looking in the wrong place.
        if !bytes.starts_with(b"MZ") {
            return Err(anyhow::anyhow!("missing MZ magic"));
        }
        if bytes.len() < 0x40 {
            return Err(anyhow::anyhow!(
                "DOS header truncated: {} bytes, need at least 0x40",
                bytes.len()
            ));
        }
        // Parse e_lfanew → PE\0\0 → COFF header → optional header → sections.
        let read_u16 = |o: usize| -> Option<u16> {
            bytes.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
        };
        let read_u32 = |o: usize| -> Option<u32> {
            bytes
                .get(o..o + 4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        let read_u64 = |o: usize| -> Option<u64> {
            bytes.get(o..o + 8).map(|s| {
                u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            })
        };

        let mut result = RichLoadResult::new(bytes.to_vec())
            .with_format("PE")
            .with_endian("little");

        let e_lfanew = match read_u32(0x3C) {
            Some(v) => v as usize,
            None => return Ok(result),
        };
        if e_lfanew + 24 > bytes.len()
            || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0"
        {
            return Ok(result);
        }

        // COFF header @ e_lfanew + 4
        let coff = e_lfanew + 4;
        let machine = read_u16(coff).unwrap_or(0);
        let num_sections = read_u16(coff + 2).unwrap_or(0) as usize;
        let opt_size = read_u16(coff + 16).unwrap_or(0) as usize;
        let opt = coff + 20;

        // Optional header magic
        let opt_magic = read_u16(opt).unwrap_or(0);
        let is_pe64 = opt_magic == 0x20b;
        let bits: u8 = if is_pe64 { 64 } else { 32 };
        let arch = match machine {
            0x8664 => "x86_64",
            0x14c => "x86",
            0xaa64 => "arm64",
            0x1c0 | 0x1c4 => "arm",
            _ => if is_pe64 { "x86_64" } else { "x86" },
        };

        // entry_point = ImageBase + AddressOfEntryPoint
        let entry_rva = u64::from(read_u32(opt + 16).unwrap_or(0));
        let image_base: u64 = if is_pe64 {
            read_u64(opt + 24).unwrap_or(0)
        } else {
            u64::from(read_u32(opt + 28).unwrap_or(0))
        };

        result.bits = bits;
        result.arch = arch.to_string();
        result.base_address = image_base;
        if entry_rva != 0 {
            result.entry_point = Some(image_base.saturating_add(entry_rva));
        }

        // Section table immediately after optional header
        let sec_start = opt + opt_size;
        for i in 0..num_sections {
            let so = sec_start + i * 40;
            if so + 40 > bytes.len() {
                break;
            }
            let name_raw = &bytes[so..so + 8];
            let nlen = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_raw[..nlen]).into_owned();
            let virtual_size = u64::from(read_u32(so + 8).unwrap_or(0));
            let virtual_addr = u64::from(read_u32(so + 12).unwrap_or(0));
            let raw_size = u64::from(read_u32(so + 16).unwrap_or(0));
            let raw_offset = u64::from(read_u32(so + 20).unwrap_or(0));
            let flags = read_u32(so + 36).unwrap_or(0);
            result.sections.push(SectionInfo {
                name,
                virtual_addr: image_base.saturating_add(virtual_addr),
                virtual_size,
                raw_offset,
                raw_size,
                flags,
            });
        }

        // Import directory (data directory index 1). Without this the IAT and
        // every dynamic import stay anonymous `off_<hex>` — this is what lets
        // call sites resolve to `GetProcAddress`, `printf`, etc.
        let dd_base = if is_pe64 { opt + 112 } else { opt + 96 };
        let import_rva = read_u32(dd_base + 8).unwrap_or(0);
        // RVA → file offset via the (rva, span, raw_offset) of each section.
        let secs: Vec<(u64, u64, u64)> = result
            .sections
            .iter()
            .map(|s| {
                (
                    s.virtual_addr.wrapping_sub(image_base),
                    s.virtual_size.max(s.raw_size),
                    s.raw_offset,
                )
            })
            .collect();
        let rva_to_off = |rva: u64| -> Option<usize> {
            if rva == 0 {
                return None;
            }
            secs.iter().find_map(|&(sr, span, ro)| {
                (rva >= sr && rva < sr + span).then(|| usize::try_from(ro + (rva - sr)).ok())?
            })
        };
        let read_cstr = |off: usize| -> String {
            let end = bytes[off..]
                .iter()
                .position(|&b| b == 0)
                .map_or(bytes.len(), |p| off + p);
            String::from_utf8_lossy(&bytes[off..end.min(bytes.len())]).into_owned()
        };
        if let Some(mut desc_off) = rva_to_off(u64::from(import_rva)) {
            let thunk_size: u64 = if is_pe64 { 8 } else { 4 };
            let ord_flag: u64 = if is_pe64 {
                0x8000_0000_0000_0000
            } else {
                0x8000_0000
            };
            // Bounded loops: never trust attacker-controlled descriptor/thunk
            // counts to terminate.
            for _ in 0..4096 {
                if desc_off + 20 > bytes.len() {
                    break;
                }
                let oft = read_u32(desc_off).unwrap_or(0);
                let name_rva = read_u32(desc_off + 12).unwrap_or(0);
                let ft = read_u32(desc_off + 16).unwrap_or(0);
                if oft == 0 && name_rva == 0 && ft == 0 {
                    break; // null descriptor terminates the table
                }
                let dll = rva_to_off(u64::from(name_rva))
                    .map(&read_cstr)
                    .unwrap_or_default();
                let int_rva = if oft != 0 { oft } else { ft };
                if let Some(mut thunk_off) = rva_to_off(u64::from(int_rva)) {
                    for idx in 0..8192u64 {
                        let entry = if is_pe64 {
                            read_u64(thunk_off).unwrap_or(0)
                        } else {
                            u64::from(read_u32(thunk_off).unwrap_or(0))
                        };
                        if entry == 0 {
                            break;
                        }
                        let iat_addr = image_base
                            .saturating_add(u64::from(ft))
                            .saturating_add(idx * thunk_size);
                        if entry & ord_flag == 0 {
                            // IMAGE_IMPORT_BY_NAME: 2-byte hint then the name.
                            if let Some(noff) = rva_to_off(entry & 0x7fff_ffff) {
                                let fname = read_cstr(noff + 2);
                                if !fname.is_empty() {
                                    result.imports.push(ImportInfo::named(
                                        dll.clone(),
                                        fname,
                                        iat_addr,
                                    ));
                                }
                            }
                        } else {
                            result.imports.push(ImportInfo::ordinal(
                                dll.clone(),
                                (entry & 0xffff) as u16,
                                iat_addr,
                            ));
                        }
                        thunk_off += thunk_size as usize;
                    }
                }
                desc_off += 20;
            }
        }

        Ok(result)
    }
}

/// Stub loader for WebAssembly modules.
#[derive(Debug, Default, Clone, Copy)]
pub struct WasmStubLoader;

impl MultiFormatLoader for WasmStubLoader {
    fn name(&self) -> &'static str {
        "wasm"
    }
    fn extensions(&self) -> &[&str] {
        &["wasm"]
    }
    fn description(&self) -> &'static str {
        "WebAssembly binary module"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]) {
            255
        } else {
            0
        }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        if !bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]) {
            return Err(anyhow::anyhow!("missing Wasm magic"));
        }
        Ok(RichLoadResult::new(bytes.to_vec())
            .with_format("WebAssembly")
            .with_arch("wasm32")
            .with_bits(32)
            .with_endian("little"))
    }
}

/// Stub loader for Mach-O binaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachoStubLoader;

impl MultiFormatLoader for MachoStubLoader {
    fn name(&self) -> &'static str {
        "macho"
    }
    fn extensions(&self) -> &[&str] {
        &["dylib", "o", "macho"]
    }
    fn description(&self) -> &'static str {
        "Mach-O binary (Apple platforms)"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if AutoLoader::is_macho(bytes) { 255 } else { 0 }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        let fmt = AutoLoader::detect_format(bytes);
        if !AutoLoader::is_macho(bytes) {
            return Err(anyhow::anyhow!("not a Mach-O image"));
        }
        let (bits, endian) = match fmt {
            DetectedFormat::MachoLe32 => (32u8, "little"),
            DetectedFormat::MachoLe64 => (64u8, "little"),
            DetectedFormat::MachoBe32 => (32u8, "big"),
            DetectedFormat::MachoBe64 => (64u8, "big"),
            DetectedFormat::FatMacho => (0u8, "mixed"),
            _ => (0u8, "unknown"),
        };
        Ok(RichLoadResult::new(bytes.to_vec())
            .with_format(fmt.to_string())
            .with_bits(bits)
            .with_endian(endian))
    }
}

/// Stub loader for Lua bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct LuaStubLoader;

impl MultiFormatLoader for LuaStubLoader {
    fn name(&self) -> &'static str {
        "lua"
    }
    fn extensions(&self) -> &[&str] {
        &["luac", "luab"]
    }
    fn description(&self) -> &'static str {
        "Lua compiled bytecode"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(&[0x1b, b'L', b'u', b'a']) {
            255
        } else if bytes.starts_with(&[0x1b, b'L', b'J']) {
            240
        } else {
            0
        }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        let fmt = AutoLoader::detect_format(bytes);
        match fmt {
            DetectedFormat::LuaBytecode(_) | DetectedFormat::LuaJit => {
                Ok(RichLoadResult::new(bytes.to_vec()).with_format(fmt.to_string()))
            }
            _ => Err(anyhow::anyhow!("not Lua bytecode")),
        }
    }
}

/// Stub loader for Java class files.
#[derive(Debug, Default, Clone, Copy)]
pub struct JavaClassStubLoader;

impl MultiFormatLoader for JavaClassStubLoader {
    fn name(&self) -> &'static str {
        "java-class"
    }
    fn extensions(&self) -> &[&str] {
        &["class"]
    }
    fn description(&self) -> &'static str {
        "Java compiled class file"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if matches!(AutoLoader::detect_format(bytes), DetectedFormat::JavaClass) {
            255
        } else {
            0
        }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        if !matches!(AutoLoader::detect_format(bytes), DetectedFormat::JavaClass) {
            return Err(anyhow::anyhow!("not a Java class file"));
        }
        Ok(RichLoadResult::new(bytes.to_vec())
            .with_format("Java Class")
            .with_arch("jvm")
            .with_bits(64)
            .with_endian("big"))
    }
}

/// Stub loader for Android DEX.
#[derive(Debug, Default, Clone, Copy)]
pub struct AndroidDexStubLoader;

impl MultiFormatLoader for AndroidDexStubLoader {
    fn name(&self) -> &'static str {
        "android-dex"
    }
    fn extensions(&self) -> &[&str] {
        &["dex"]
    }
    fn description(&self) -> &'static str {
        "Android Dalvik Executable (.dex)"
    }
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(b"dex\n") { 255 } else { 0 }
    }
    fn load(&self, bytes: &[u8]) -> anyhow::Result<RichLoadResult> {
        if !bytes.starts_with(b"dex\n") {
            return Err(anyhow::anyhow!("not an Android DEX file"));
        }
        Ok(RichLoadResult::new(bytes.to_vec())
            .with_format("Android DEX")
            .with_arch("dex")
            .with_bits(32)
            .with_endian("little"))
    }
}

/// Build a [`MultiFormatRegistry`] pre-populated with all built-in stub
/// loaders.
///
/// This is the recommended starting point; downstream crates can add their
/// own higher-fidelity loaders via [`MultiFormatRegistry::register`].
#[must_use]
pub fn default_multi_format_registry() -> MultiFormatRegistry {
    let r = MultiFormatRegistry::new();
    r.register(ElfStubLoader);
    r.register(PeStubLoader);
    r.register(WasmStubLoader);
    r.register(MachoStubLoader);
    r.register(LuaStubLoader);
    r.register(JavaClassStubLoader);
    r.register(AndroidDexStubLoader);
    r
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{
        address::{Address, AddressRange},
        arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo},
        binary_view::{Memory, Segment},
        endian::Endian,
        errors::CoreError,
        permissions::Permissions,
    };

    // â"€â"€ Test helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    const MAGIC: &[u8] = b"RSTR";

    #[derive(Debug)]
    struct FakeArch;
    impl Architecture for FakeArch {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
            Ok(Instruction::new(address, 1, "nop", vec![0x90]))
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

    #[derive(Debug)]
    struct FakeLoader {
        name: String,
    }

    impl FakeLoader {
        fn named(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
            })
        }
    }

    #[async_trait::async_trait]
    impl Loader for FakeLoader {
        fn name(&self) -> &str {
            &self.name
        }

        fn can_load(&self, input: &LoaderInput) -> bool {
            input.data.starts_with(MAGIC)
        }

        async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
            let mut mem = Memory::new();
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: vec![0; 0x1000],
            });
            let view = BinaryView::new(
                crate::next_view_id(),
                input.uri,
                Arc::new(FakeArch),
                Endian::Little,
                64,
                vec![Address::new(0x1000)],
                mem,
            );
            Ok(LoadResult::new(view))
        }

        async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
            Ok(vec![])
        }
    }

    fn rstr_input() -> LoaderInput {
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&[0u8; 256]);
        LoaderInput::new("test://binary", d)
    }

    fn unknown_input() -> LoaderInput {
        LoaderInput::new("test://unknown", vec![0xDE, 0xAD, 0xBE, 0xEF])
    }

    // â"€â"€ LoaderCoordinatorError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_error_no_loader_display() {
        let e = LoaderCoordinatorError::NoLoader("test://file".into());
        assert!(e.to_string().contains("No loader found"));
    }

    #[test]
    fn test_error_load_from_core() {
        let core_err = CoreError::LoaderError {
            loader: "test".into(),
            message: "bad header".into(),
        };
        let e: LoaderCoordinatorError = core_err.into();
        assert!(e.to_string().contains("Load error"));
    }

    #[test]
    fn test_error_ambiguous_display() {
        let e = LoaderCoordinatorError::Ambiguous("PE/ELF".into());
        assert!(e.to_string().contains("Multiple loaders ambiguous"));
    }

    // â"€â"€ LoaderCoordinator construction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coordinator_new_is_empty() {
        let coord = LoaderCoordinator::new();
        assert_eq!(coord.probe_all(&rstr_input()).len(), 0);
    }

    #[test]
    fn test_coordinator_default() {
        let coord = LoaderCoordinator::default();
        assert_eq!(coord.probe_all(&rstr_input()).len(), 0);
    }

    #[test]
    fn test_coordinator_debug() {
        let coord = LoaderCoordinator::new();
        let s = format!("{coord:?}");
        assert!(s.contains("LoaderCoordinator"));
    }

    #[test]
    fn test_coordinator_with_registry() {
        let reg = Arc::new(LoaderRegistry::new());
        reg.register(FakeLoader::named("fake"));
        let coord = LoaderCoordinator::new_with_registry(Arc::clone(&reg));
        assert_eq!(coord.probe_all(&rstr_input()).len(), 1);
    }

    // â"€â"€ register / probe_all â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_and_probe() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("loader1"));
        let matches = coord.probe_all(&rstr_input());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name(), "loader1");
    }

    #[test]
    fn test_probe_returns_empty_for_unknown() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("loader1"));
        let matches = coord.probe_all(&unknown_input());
        assert!(matches.is_empty());
    }

    #[test]
    fn test_multiple_loaders_probe() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("loader_a"));
        coord.register(FakeLoader::named("loader_b"));
        let matches = coord.probe_all(&rstr_input());
        assert_eq!(matches.len(), 2);
    }

    // â"€â"€ auto_load â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_auto_load_success() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("first"));
        let view = coord.auto_load(rstr_input()).await.unwrap();
        assert_eq!(view.uri, "test://binary");
    }

    #[tokio::test]
    async fn test_auto_load_no_loader() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("only_rstr"));
        let result = coord.auto_load(unknown_input()).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, LoaderCoordinatorError::NoLoader(_)));
        }
    }

    #[tokio::test]
    async fn test_auto_load_empty_coordinator() {
        let coord = LoaderCoordinator::new();
        let result = coord.auto_load(rstr_input()).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, LoaderCoordinatorError::NoLoader(_)));
        }
    }

    #[tokio::test]
    async fn test_auto_load_uses_first_matching() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("first_match"));
        coord.register(FakeLoader::named("second_match"));
        // Both can load RSTR, auto_load should succeed (uses first).
        let view = coord.auto_load(rstr_input()).await.unwrap();
        assert!(!view.uri.is_empty());
    }

    // â"€â"€ registry access â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_registry_find_by_name() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("my_loader"));
        let found = coord.registry().find_by_name("my_loader");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "my_loader");
    }

    #[test]
    fn test_registry_find_by_name_missing() {
        let coord = LoaderCoordinator::new();
        assert!(coord.registry().find_by_name("nonexistent").is_none());
    }

    // â"€â"€ type re-exports â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_loader_input_fields() {
        let input = LoaderInput::new("file://test.bin", vec![0x7f, 0x45, 0x4c, 0x46]);
        assert_eq!(input.uri, "file://test.bin");
        assert_eq!(input.data.len(), 4);
    }

    #[test]
    fn test_loader_hint_variants() {
        let hint_arch = LoaderHint::Architecture("x86_64".into());
        let hint_base = LoaderHint::BaseAddress(rustre_core::address::Address(0x0040_0000));
        match &hint_arch {
            LoaderHint::Architecture(a) => assert_eq!(a, "x86_64"),
            _ => panic!("wrong variant"),
        }
        match &hint_base {
            LoaderHint::BaseAddress(a) => assert_eq!(a.0, 0x0040_0000),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_nested_binary_fields() {
        use rustre_core::loader::BinaryType;
        let nb = NestedBinary {
            name: "inner.bin".into(),
            data: vec![0u8; 0x200],
            offset_in_parent: 0x100,
            binary_type: BinaryType::Unknown,
        };
        assert_eq!(nb.name, "inner.bin");
        assert_eq!(nb.data.len(), 0x200);
        assert_eq!(nb.offset_in_parent, 0x100);
    }

    // â"€â"€ shared registry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_shared_registry_across_coordinators() {
        let reg = Arc::new(LoaderRegistry::new());
        reg.register(FakeLoader::named("shared_loader"));
        let coord1 = LoaderCoordinator::new_with_registry(Arc::clone(&reg));
        let coord2 = LoaderCoordinator::new_with_registry(Arc::clone(&reg));
        assert_eq!(coord1.probe_all(&rstr_input()).len(), 1);
        assert_eq!(coord2.probe_all(&rstr_input()).len(), 1);
    }

    // â"€â"€ additional coverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coordinator_registry_returns_same_registry() {
        let reg = Arc::new(LoaderRegistry::new());
        reg.register(FakeLoader::named("test_loader"));
        let coord = LoaderCoordinator::new_with_registry(Arc::clone(&reg));
        let found = coord.registry().find_by_name("test_loader");
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_auto_load_result_has_correct_uri() {
        let coord = LoaderCoordinator::new();
        coord.register(FakeLoader::named("uri_test"));
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&[0u8; 64]);
        let input = LoaderInput::new("test://my_binary.bin", d);
        let view = coord.auto_load(input).await.unwrap();
        assert_eq!(view.uri, "test://my_binary.bin");
    }

    #[test]
    fn test_probe_all_returns_all_matching_loaders() {
        let coord = LoaderCoordinator::new();
        for i in 0..5 {
            coord.register(FakeLoader::named(&format!("loader_{i}")));
        }
        let matches = coord.probe_all(&rstr_input());
        assert_eq!(matches.len(), 5);
    }

    #[test]
    fn test_error_load_display() {
        let e = LoaderCoordinatorError::Load(CoreError::LoaderError {
            loader: "test".into(),
            message: "elf truncated".into(),
        });
        assert!(e.to_string().contains("Load error"));
    }

    #[test]
    fn test_fake_loader_can_load_false_for_non_magic() {
        let loader = FakeLoader::named("fl");
        let input = unknown_input();
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_fake_loader_can_load_true_for_magic() {
        let loader = FakeLoader::named("fl");
        let input = rstr_input();
        assert!(loader.can_load(&input));
    }

    // â"€â"€ BinaryFormat â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_format_display_elf() {
        assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
    }

    #[test]
    fn test_format_display_pe() {
        assert_eq!(BinaryFormat::Pe.to_string(), "PE");
    }

    #[test]
    fn test_format_display_wasm() {
        assert_eq!(BinaryFormat::Wasm.to_string(), "WebAssembly");
    }

    // â"€â"€ FormatDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_elf() {
        let d = FormatDetector::new();
        assert_eq!(d.detect(b"\x7fELF\x02\x01\x01\x00"), BinaryFormat::Elf);
        assert!(d.is_elf(b"\x7fELF\x02\x01\x01\x00"));
    }

    #[test]
    fn test_detect_pe() {
        let d = FormatDetector::new();
        assert_eq!(d.detect(b"MZ\x90\x00"), BinaryFormat::Pe);
        assert!(d.is_pe(b"MZ\x90\x00"));
    }

    #[test]
    fn test_detect_macho_le32() {
        let d = FormatDetector::new();
        assert_eq!(
            d.detect(&[0xCE, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
        assert!(d.is_macho(&[0xCE, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]));
    }

    #[test]
    fn test_detect_macho_le64() {
        let d = FormatDetector::new();
        assert_eq!(
            d.detect(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
    }

    #[test]
    fn test_detect_macho_be32() {
        let d = FormatDetector::new();
        assert_eq!(
            d.detect(&[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
    }

    #[test]
    fn test_detect_java_class() {
        let d = FormatDetector::new();
        // Java 8 class: major = 52 = 0x0034
        let data = [0xCA_u8, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
        assert_eq!(d.detect(&data), BinaryFormat::JavaClass);
        assert!(d.is_java_class(&data));
    }

    #[test]
    fn test_detect_zip() {
        let d = FormatDetector::new();
        assert_eq!(d.detect(b"PK\x03\x04extra"), BinaryFormat::Zip);
    }

    #[test]
    fn test_detect_wasm() {
        let d = FormatDetector::new();
        assert_eq!(d.detect(b"\x00asm\x01\x00\x00\x00"), BinaryFormat::Wasm);
    }

    #[test]
    fn test_detect_unknown() {
        let d = FormatDetector::new();
        assert_eq!(d.detect(b"randomdata"), BinaryFormat::Unknown);
        assert_eq!(d.detect(&[]), BinaryFormat::Unknown);
    }

    #[test]
    fn test_detect_default() {
        let _d = FormatDetector;
    }

    // â"€â"€ BatchLoader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_batch_load_success() {
        let coord = std::sync::Arc::new(LoaderCoordinator::new());
        coord.register(FakeLoader::named("batch_loader"));
        let batch = BatchLoader::new(coord);
        let inputs = vec![rstr_input(), rstr_input()];
        let outcomes = batch.load_all(inputs).await;
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(super::BatchLoadOutcome::is_ok));
    }

    #[tokio::test]
    async fn test_batch_load_failure() {
        let coord = std::sync::Arc::new(LoaderCoordinator::new());
        coord.register(FakeLoader::named("batch_loader"));
        let batch = BatchLoader::new(coord);
        let outcomes = batch.load_all(vec![unknown_input()]).await;
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].is_ok());
        assert!(outcomes[0].error.is_some());
    }

    #[tokio::test]
    async fn test_batch_load_detects_format() {
        let coord = std::sync::Arc::new(LoaderCoordinator::new());
        coord.register(FakeLoader::named("bl"));
        let batch = BatchLoader::new(coord);
        // rstr_input has unknown format (magic "RSTR" not in FormatDetector)
        let outcomes = batch.load_all(vec![rstr_input()]).await;
        assert_eq!(outcomes[0].format, BinaryFormat::Unknown);
    }

    #[test]
    fn test_batch_loader_debug() {
        let coord = std::sync::Arc::new(LoaderCoordinator::new());
        let batch = BatchLoader::new(coord);
        assert!(format!("{batch:?}").contains("BatchLoader"));
    }

    #[test]
    fn test_batch_loader_coordinator_accessor() {
        let coord = std::sync::Arc::new(LoaderCoordinator::new());
        coord.register(FakeLoader::named("accessor_test"));
        let batch = BatchLoader::new(Arc::clone(&coord));
        let found = batch.coordinator().registry().find_by_name("accessor_test");
        assert!(found.is_some());
    }

    #[test]
    fn test_batch_outcome_is_ok_false_when_no_view() {
        let o = BatchLoadOutcome {
            uri: "test".into(),
            format: BinaryFormat::Unknown,
            view: None,
            error: Some("failed".into()),
        };
        assert!(!o.is_ok());
    }

    // â"€â"€ LoaderPipeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pipeline_name() {
        let p = LoaderPipeline::new("my_pipeline");
        assert_eq!(p.name(), "my_pipeline");
    }

    #[test]
    fn test_pipeline_debug() {
        let p = LoaderPipeline::new("test");
        assert!(format!("{p:?}").contains("LoaderPipeline"));
    }

    #[test]
    fn test_pipeline_detect_format() {
        let p = LoaderPipeline::new("test");
        assert_eq!(p.detect_format(b"\x7fELF\x02\x01\x01"), BinaryFormat::Elf);
    }

    #[test]
    fn test_pipeline_loader_count_empty() {
        let p = LoaderPipeline::new("test");
        assert_eq!(p.loader_count(), 0);
    }

    #[test]
    fn test_pipeline_add_loader() {
        let p = LoaderPipeline::new("test");
        p.add_loader(FakeLoader::named("pl1"));
        // `loader_count` reports registered loaders (not probe matches), so adding
        // one loader yields exactly 1.
        assert_eq!(p.loader_count(), 1);
    }

    #[tokio::test]
    async fn test_pipeline_run_success() {
        let p = LoaderPipeline::new("run_test");
        p.add_loader(FakeLoader::named("runner"));
        let (fmt, view) = p.run(rstr_input()).await.unwrap();
        assert_eq!(fmt, BinaryFormat::Unknown);
        assert_eq!(view.uri, "test://binary");
    }

    #[tokio::test]
    async fn test_pipeline_run_failure() {
        let p = LoaderPipeline::new("fail_test");
        let result = p.run(unknown_input()).await;
        assert!(result.is_err());
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests —" new multi-format layer
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod multi_format_tests {
    use super::*;

    // â"€â"€ DetectedFormat display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn detected_format_display_all_variants() {
        assert_eq!(DetectedFormat::Elf32Le.to_string(), "ELF-32LE");
        assert_eq!(DetectedFormat::Elf32Be.to_string(), "ELF-32BE");
        assert_eq!(DetectedFormat::Elf64Le.to_string(), "ELF-64LE");
        assert_eq!(DetectedFormat::Elf64Be.to_string(), "ELF-64BE");
        assert_eq!(DetectedFormat::Pe.to_string(), "PE");
        assert_eq!(DetectedFormat::MachoLe32.to_string(), "Mach-O LE32");
        assert_eq!(DetectedFormat::MachoLe64.to_string(), "Mach-O LE64");
        assert_eq!(DetectedFormat::MachoBe32.to_string(), "Mach-O BE32");
        assert_eq!(DetectedFormat::MachoBe64.to_string(), "Mach-O BE64");
        assert_eq!(DetectedFormat::FatMacho.to_string(), "Mach-O Fat");
        assert_eq!(DetectedFormat::Wasm.to_string(), "WebAssembly");
        assert_eq!(DetectedFormat::LuaJit.to_string(), "LuaJIT Bytecode");
        assert_eq!(DetectedFormat::DotNet.to_string(), ".NET/CIL");
        assert_eq!(DetectedFormat::JavaClass.to_string(), "Java Class");
        assert_eq!(DetectedFormat::AndroidDex.to_string(), "Android DEX");
        assert_eq!(DetectedFormat::Pdf.to_string(), "PDF");
        assert_eq!(DetectedFormat::Zip.to_string(), "ZIP");
        assert_eq!(
            DetectedFormat::OleCompoundDoc.to_string(),
            "OLE Compound Document"
        );
        assert_eq!(DetectedFormat::IntelHex.to_string(), "Intel HEX");
        assert_eq!(
            DetectedFormat::MotorolaSrec.to_string(),
            "Motorola S-Record"
        );
        assert_eq!(DetectedFormat::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn detected_format_lua_bytecode_display() {
        assert!(
            DetectedFormat::LuaBytecode(0x53)
                .to_string()
                .contains("0x53")
        );
    }

    // â"€â"€ AutoLoader::detect_format â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn auto_detect_elf32_le() {
        // Class=1 (32-bit), Data=1 (LE)
        assert_eq!(
            AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]),
            DetectedFormat::Elf32Le
        );
    }

    #[test]
    fn auto_detect_elf32_be() {
        assert_eq!(
            AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 1, 2, 1, 0]),
            DetectedFormat::Elf32Be
        );
    }

    #[test]
    fn auto_detect_elf64_le() {
        assert_eq!(
            AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
            DetectedFormat::Elf64Le
        );
    }

    #[test]
    fn auto_detect_elf64_be() {
        assert_eq!(
            AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 2, 2, 1, 0]),
            DetectedFormat::Elf64Be
        );
    }

    #[test]
    fn auto_detect_pe() {
        assert_eq!(AutoLoader::detect_format(b"MZ\x90\x00"), DetectedFormat::Pe);
    }

    #[test]
    fn auto_detect_macho_le64() {
        assert_eq!(
            AutoLoader::detect_format(&[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01]),
            DetectedFormat::MachoLe64
        );
    }

    #[test]
    fn auto_detect_macho_le32() {
        assert_eq!(
            AutoLoader::detect_format(&[0xCE, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x00]),
            DetectedFormat::MachoLe32
        );
    }

    #[test]
    fn auto_detect_macho_be32() {
        assert_eq!(
            AutoLoader::detect_format(&[0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x00, 0x00, 0x07]),
            DetectedFormat::MachoBe32
        );
    }

    #[test]
    fn auto_detect_macho_be64() {
        assert_eq!(
            AutoLoader::detect_format(&[0xFE, 0xED, 0xFA, 0xCF, 0x00, 0x00, 0x00, 0x07]),
            DetectedFormat::MachoBe64
        );
    }

    #[test]
    fn auto_detect_fat_macho() {
        // 0xCAFEBABE with non-Java major
        let mut d = [0xCA_u8, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(AutoLoader::detect_format(&d), DetectedFormat::FatMacho);
        // major=2 is not a valid Java class major
        d[7] = 2;
        assert_eq!(AutoLoader::detect_format(&d), DetectedFormat::FatMacho);
    }

    #[test]
    fn auto_detect_java_class() {
        // Java 11 class: major = 55
        let d = [0xCA_u8, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 55];
        assert_eq!(AutoLoader::detect_format(&d), DetectedFormat::JavaClass);
    }

    #[test]
    fn auto_detect_wasm() {
        assert_eq!(
            AutoLoader::detect_format(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
            DetectedFormat::Wasm
        );
    }

    #[test]
    fn auto_detect_lua_bytecode_with_version() {
        let d = [0x1b, b'L', b'u', b'a', 0x53, 0x00];
        assert_eq!(
            AutoLoader::detect_format(&d),
            DetectedFormat::LuaBytecode(0x53)
        );
    }

    #[test]
    fn auto_detect_lua_bytecode_no_version_byte() {
        let d = [0x1b, b'L', b'u', b'a'];
        assert_eq!(
            AutoLoader::detect_format(&d),
            DetectedFormat::LuaBytecode(0x00)
        );
    }

    #[test]
    fn auto_detect_luajit() {
        let d = [0x1b, b'L', b'J', 0x02, 0x00];
        assert_eq!(AutoLoader::detect_format(&d), DetectedFormat::LuaJit);
    }

    #[test]
    fn auto_detect_pdf() {
        assert_eq!(AutoLoader::detect_format(b"%PDF-1.7"), DetectedFormat::Pdf);
    }

    #[test]
    fn auto_detect_zip() {
        assert_eq!(
            AutoLoader::detect_format(&[b'P', b'K', 0x03, 0x04]),
            DetectedFormat::Zip
        );
    }

    #[test]
    fn auto_detect_ole() {
        assert_eq!(
            AutoLoader::detect_format(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
            DetectedFormat::OleCompoundDoc
        );
    }

    #[test]
    fn auto_detect_android_dex() {
        assert_eq!(
            AutoLoader::detect_format(b"dex\n035\x00"),
            DetectedFormat::AndroidDex
        );
    }

    #[test]
    fn auto_detect_intel_hex() {
        assert_eq!(
            AutoLoader::detect_format(b":10000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00"),
            DetectedFormat::IntelHex
        );
    }

    #[test]
    fn auto_detect_motorola_srec() {
        assert_eq!(
            AutoLoader::detect_format(b"S0"),
            DetectedFormat::MotorolaSrec
        );
        assert_eq!(
            AutoLoader::detect_format(b"S1"),
            DetectedFormat::MotorolaSrec
        );
        assert_eq!(
            AutoLoader::detect_format(b"S9"),
            DetectedFormat::MotorolaSrec
        );
    }

    #[test]
    fn auto_detect_unknown_empty() {
        assert_eq!(AutoLoader::detect_format(&[]), DetectedFormat::Unknown);
        assert_eq!(AutoLoader::detect_format(&[0x00]), DetectedFormat::Unknown);
    }

    #[test]
    fn auto_detect_unknown_random() {
        assert_eq!(
            AutoLoader::detect_format(b"DEADBEEF"),
            DetectedFormat::Unknown
        );
    }

    #[test]
    fn auto_loader_is_elf() {
        assert!(AutoLoader::is_elf(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]));
        assert!(!AutoLoader::is_elf(b"MZ\x90\x00"));
    }

    #[test]
    fn auto_loader_is_macho() {
        assert!(AutoLoader::is_macho(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]));
        assert!(AutoLoader::is_macho(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]));
        assert!(!AutoLoader::is_macho(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]));
    }

    // â"€â"€ sha256 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn sha256_empty_is_known_digest() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let d = sha256(b"");
        assert_eq!(
            d,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello_world() {
        let d = sha256(b"hello world");
        assert_eq!(d.len(), 64);
        // Exact digest of "hello world"
        assert_eq!(
            d,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_result_is_lowercase_hex() {
        let d = sha256(b"test");
        assert!(
            d.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // â"€â"€ SectionInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn section_info_roundtrip() {
        let s = SectionInfo::new(".text", 0x1000, 0x500, 0x200, 0x480, 0x6000_0020);
        assert_eq!(s.name, ".text");
        assert_eq!(s.virtual_addr, 0x1000);
        assert_eq!(s.virtual_size, 0x500);
        assert_eq!(s.raw_offset, 0x200);
        assert_eq!(s.raw_size, 0x480);
        assert_eq!(s.flags, 0x6000_0020);
    }

    #[test]
    fn section_info_serde() {
        let s = SectionInfo::new(".data", 0x2000, 0x100, 0x400, 0x100, 0xC000_0040);
        let json = serde_json::to_string(&s).unwrap();
        let back: SectionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // â"€â"€ SymbolInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn symbol_info_fields() {
        let sym = SymbolInfo::new("main", 0x0040_1000, "function", 42);
        assert_eq!(sym.name, "main");
        assert_eq!(sym.addr, 0x0040_1000);
        assert_eq!(sym.kind, "function");
        assert_eq!(sym.size, 42);
    }

    // â"€â"€ ImportInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn import_info_named() {
        let imp = ImportInfo::named("kernel32.dll", "CreateFileW", 0x7ff8_0000_0000_0000);
        assert_eq!(imp.dll, "kernel32.dll");
        assert_eq!(imp.name, "CreateFileW");
        assert!(imp.ordinal.is_none());
    }

    #[test]
    fn import_info_ordinal() {
        let imp = ImportInfo::ordinal("ws2_32.dll", 3, 0x7ff9_0000_0000_0000);
        assert_eq!(imp.ordinal, Some(3));
        assert!(imp.name.is_empty());
    }

    // â"€â"€ ExportInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn export_info_named() {
        let exp = ExportInfo::named("DllMain", 0x0040_1000401000, 1);
        assert_eq!(exp.name, "DllMain");
        assert!(exp.forwarded_to.is_none());
    }

    #[test]
    fn export_info_forwarded() {
        let exp = ExportInfo::forwarded("HeapAlloc", 5, "NTDLL.RtlAllocateHeap");
        assert_eq!(exp.forwarded_to.as_deref(), Some("NTDLL.RtlAllocateHeap"));
        assert_eq!(exp.addr, 0);
    }

    // â"€â"€ RichLoadResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn rich_load_result_builder() {
        let r = RichLoadResult::new(vec![0u8; 64])
            .with_format("ELF-64LE")
            .with_arch("x86_64")
            .with_bits(64)
            .with_endian("little")
            .with_entry_point(0x0040_1000)
            .with_base_address(0x0040_0000)
            .with_section(SectionInfo::new(".text", 0x1000, 0x500, 0x200, 0x480, 0))
            .with_symbol(SymbolInfo::new("main", 0x1000, "function", 0))
            .with_import(ImportInfo::named("libc.so", "printf", 0x2000))
            .with_export(ExportInfo::named("foo", 0x3000, 1));

        assert_eq!(r.format, "ELF-64LE");
        assert_eq!(r.arch, "x86_64");
        assert_eq!(r.bits, 64);
        assert_eq!(r.endian, "little");
        assert_eq!(r.entry_point, Some(0x0040_1000));
        assert_eq!(r.base_address, 0x0040_0000);
        assert_eq!(r.sections.len(), 1);
        assert_eq!(r.symbols.len(), 1);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.exports.len(), 1);
        assert_eq!(r.data.len(), 64);
    }

    #[test]
    fn rich_load_result_sha256() {
        let r = RichLoadResult::new(b"hello world".to_vec());
        assert_eq!(r.sha256().len(), 64);
    }

    #[test]
    fn rich_load_result_total_virtual_size() {
        let r = RichLoadResult::new(vec![])
            .with_section(SectionInfo::new(".text", 0x1000, 0x500, 0, 0x500, 0))
            .with_section(SectionInfo::new(".data", 0x2000, 0x200, 0, 0x200, 0));
        assert_eq!(r.total_virtual_size(), 0x700);
    }

    #[test]
    fn rich_load_result_section_at_hit() {
        let r = RichLoadResult::new(vec![])
            .with_section(SectionInfo::new(".text", 0x1000, 0x1000, 0, 0x1000, 0));
        assert!(r.section_at(0x1000).is_some());
        assert!(r.section_at(0x1FFF).is_some());
    }

    #[test]
    fn rich_load_result_section_at_miss() {
        let r = RichLoadResult::new(vec![])
            .with_section(SectionInfo::new(".text", 0x1000, 0x1000, 0, 0x1000, 0));
        assert!(r.section_at(0x0FFF).is_none());
        assert!(r.section_at(0x2000).is_none());
    }

    // â"€â"€ MultiLoaderInput â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn multi_loader_input_bytes_roundtrip() {
        let bytes = vec![1u8, 2, 3, 4];
        let input = MultiLoaderInput::Bytes(bytes.clone());
        assert_eq!(input.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn multi_loader_input_memory_roundtrip() {
        let data = vec![0xAA_u8; 32];
        let input = MultiLoaderInput::Memory {
            base: 0x0040_0000,
            data: data.clone(),
        };
        assert_eq!(input.to_bytes().unwrap(), data);
    }

    #[test]
    fn multi_loader_input_file_missing_errors() {
        let input = MultiLoaderInput::File(std::path::PathBuf::from(
            "C:/does_not_exist_rustre_test_84920.bin",
        ));
        assert!(input.to_bytes().is_err());
    }

    // â"€â"€ MultiFormatRegistry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn registry_empty() {
        let r = MultiFormatRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn registry_register_and_len() {
        let r = MultiFormatRegistry::new();
        r.register(ElfStubLoader);
        r.register(PeStubLoader);
        assert_eq!(r.len(), 2);
        assert!(!r.is_empty());
    }

    #[test]
    fn registry_loader_names() {
        let r = MultiFormatRegistry::new();
        r.register(ElfStubLoader);
        r.register(PeStubLoader);
        let names = r.loader_names();
        assert!(names.contains(&"elf".to_owned()));
        assert!(names.contains(&"pe".to_owned()));
    }

    #[test]
    fn registry_find_by_name() {
        let r = MultiFormatRegistry::new();
        r.register(WasmStubLoader);
        assert!(r.find("wasm").is_some());
        assert!(r.find("nonexistent").is_none());
    }

    #[test]
    fn registry_probe_all_elf() {
        let r = default_multi_format_registry();
        let elf = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0u8];
        let results = r.probe_all(&elf);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "elf");
        assert_eq!(results[0].1, 255);
    }

    #[test]
    fn registry_probe_all_pe() {
        let r = default_multi_format_registry();
        let mut pe = vec![b'M', b'Z'];
        pe.extend_from_slice(&[0u8; 62]);
        let results = r.probe_all(&pe);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "pe");
    }

    #[test]
    fn registry_probe_all_sorted_descending() {
        let r = default_multi_format_registry();
        let wasm = [0x00u8, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
        let results = r.probe_all(&wasm);
        // Must be sorted high â†' low
        let confs: Vec<u8> = results.iter().map(|(_, c)| *c).collect();
        let mut sorted = confs.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(confs, sorted);
    }

    #[test]
    fn registry_probe_all_empty_for_unknown() {
        let r = default_multi_format_registry();
        let results = r.probe_all(b"RANDOM_GARBAGE_DATA_XXXX");
        assert!(results.is_empty());
    }

    #[test]
    fn registry_auto_load_elf() {
        let r = default_multi_format_registry();
        let elf = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0u8];
        let result = r.auto_load(&elf).unwrap();
        assert!(result.format.contains("ELF"));
        assert_eq!(result.bits, 64);
        assert_eq!(result.endian, "little");
    }

    #[test]
    fn registry_auto_load_wasm() {
        let r = default_multi_format_registry();
        let wasm = [0x00u8, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
        let result = r.auto_load(&wasm).unwrap();
        assert_eq!(result.format, "WebAssembly");
        assert_eq!(result.arch, "wasm32");
    }

    #[test]
    fn registry_auto_load_unknown_errors() {
        let r = default_multi_format_registry();
        assert!(r.auto_load(b"GARBAGE").is_err());
    }

    #[test]
    fn registry_load_with_elf() {
        let r = default_multi_format_registry();
        let elf = [0x7f, b'E', b'L', b'F', 1, 2, 1, 0u8];
        let result = r.load_with("elf", &elf).unwrap();
        assert_eq!(result.bits, 32);
        assert_eq!(result.endian, "big");
    }

    #[test]
    fn registry_load_with_unknown_name_errors() {
        let r = default_multi_format_registry();
        assert!(r.load_with("nonexistent", b"data").is_err());
    }

    #[test]
    fn registry_debug_contains_count() {
        let r = default_multi_format_registry();
        let s = format!("{r:?}");
        assert!(s.contains("MultiFormatRegistry"));
    }

    // â"€â"€ Default registry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn default_registry_has_expected_loaders() {
        let r = default_multi_format_registry();
        for name in &[
            "elf",
            "pe",
            "wasm",
            "macho",
            "lua",
            "java-class",
            "android-dex",
        ] {
            assert!(r.find(name).is_some(), "missing loader: {name}");
        }
    }

    // â"€â"€ Stub loaders —" probe values â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn elf_stub_probe_255_on_magic() {
        let l = ElfStubLoader;
        assert_eq!(l.probe(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]), 255);
        assert_eq!(l.probe(b"MZ"), 0);
    }

    #[test]
    fn pe_stub_probe_200_on_mz() {
        let l = PeStubLoader;
        assert_eq!(l.probe(b"MZ\x90\x00"), 200);
        assert_eq!(l.probe(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]), 0);
    }

    #[test]
    fn wasm_stub_probe_255_on_magic() {
        let l = WasmStubLoader;
        assert_eq!(l.probe(&[0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), 255);
        assert_eq!(l.probe(b"garbage"), 0);
    }

    #[test]
    fn macho_stub_probe_255_on_macho() {
        let l = MachoStubLoader;
        assert_eq!(l.probe(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]), 255);
        assert_eq!(l.probe(b"garbage"), 0);
    }

    #[test]
    fn lua_stub_probe_lua_bytecode() {
        let l = LuaStubLoader;
        assert_eq!(l.probe(&[0x1b, b'L', b'u', b'a', 0x53]), 255);
        assert_eq!(l.probe(&[0x1b, b'L', b'J', 0x02]), 240);
        assert_eq!(l.probe(b"garbage"), 0);
    }

    #[test]
    fn java_class_stub_probe() {
        let l = JavaClassStubLoader;
        let d = [0xCA_u8, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
        assert_eq!(l.probe(&d), 255);
        assert_eq!(l.probe(b"garbage"), 0);
    }

    #[test]
    fn android_dex_stub_probe() {
        let l = AndroidDexStubLoader;
        assert_eq!(l.probe(b"dex\n035\x00"), 255);
        assert_eq!(l.probe(b"garbage"), 0);
    }

    // â"€â"€ Stub loader descriptions / extensions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn stub_loader_metadata() {
        let checks: &[(&dyn MultiFormatLoader, &str, &[&str])] = &[
            (&ElfStubLoader, "elf", &["elf", "so"]),
            (&PeStubLoader, "pe", &["exe", "dll"]),
            (&WasmStubLoader, "wasm", &["wasm"]),
            (&MachoStubLoader, "macho", &["dylib"]),
            (&LuaStubLoader, "lua", &["luac"]),
            (&JavaClassStubLoader, "java-class", &["class"]),
            (&AndroidDexStubLoader, "android-dex", &["dex"]),
        ];
        for (loader, name, ext_subset) in checks {
            assert_eq!(loader.name(), *name);
            assert!(!loader.description().is_empty());
            for ext in *ext_subset {
                assert!(
                    loader.extensions().contains(ext),
                    "loader {name} should list extension {ext}"
                );
            }
        }
    }
}


