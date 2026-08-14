//! Core trait abstractions shared across the `RustRE` workspace.
//!
//! Per spec §2, every downstream crate plugs into the platform through one of
//! the traits defined in this module. Concrete implementations live in their
//! respective crates (`rustre-decompiler`, `rustre-debugger`,
//! `rustre-loader-*`, `rustre-arch-*`, `rustre-script-*`, etc.).
//!
//! These trait definitions intentionally use opaque associated types and
//! reference-counted handles so that implementations are free to choose any
//! internal representation, and so that this crate has **no** heavyweight
//! dependencies on the rest of the workspace.

use crate::address::{Address, AddressRange};
use crate::arch::Architecture;
use crate::endian::Endian;
use crate::errors::{CoreError, Result};
use crate::ids::ViewId;
use crate::permissions::Permissions;
use async_trait::async_trait;
use std::any::Any;
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// MemoryProvider — spec §2.3
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for a memory snapshot taken from a live `MemoryProvider`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SnapshotId(pub u64);

/// Description of a single mapped region exposed by a [`MemoryProvider`].
#[derive(Clone, Debug)]
pub struct MemoryRegion {
    /// Address range covered by the region.
    pub range: AddressRange,
    /// Effective access permissions.
    pub perms: Permissions,
    /// Optional human-readable name (section, module, etc.).
    pub name: Option<String>,
    /// Where this region came from.
    pub source: RegionSource,
}

/// Origin of a [`MemoryRegion`].
#[derive(Clone, Debug)]
pub enum RegionSource {
    /// Mapped from a file section.
    FileSection {
        /// Path of the underlying file.
        file: String,
        /// Section / segment name.
        section: String,
        /// Offset into the file.
        file_offset: u64,
    },
    /// Mapped from a module inside a live process.
    ProcessModule {
        /// Module / library name.
        module: String,
        /// Process identifier.
        pid: u32,
    },
    /// Anonymous mapping.
    Anonymous,
    /// Heap region.
    Heap,
    /// Stack region.
    Stack,
    /// Region backed by an emulator.
    Emulated,
    /// Region synthesised by analysis (unpacked code, etc.).
    Reconstructed,
}

/// Central abstraction over readable / writable memory.
///
/// Every analyzer, debugger, decompiler, and visualizer reads bytes through
/// this trait. Concrete implementations live in `rustre-mem`.
#[async_trait]
pub trait MemoryProvider: Send + Sync + fmt::Debug {
    /// Read `len` bytes at `addr`.
    ///
    /// # Errors
    /// Returns an error if the range is not mapped or readable.
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>>;

    /// Write `data` at `addr`.
    ///
    /// # Errors
    /// Returns an error if the range is readonly or not mapped.
    fn write(&mut self, addr: Address, data: &[u8]) -> Result<()>;

    /// Currently mapped regions.
    fn regions(&self) -> Vec<MemoryRegion>;

    /// `true` if this provider reflects runtime (process / emulator) state.
    fn is_live(&self) -> bool {
        false
    }

    /// Invalidate caches and refresh region list. Default is no-op.
    ///
    /// # Errors
    /// Returns an error if the underlying provider fails to refresh.
    async fn refresh(&mut self) -> Result<()> {
        Ok(())
    }

    /// Take a snapshot. Default returns [`CoreError::Unsupported`].
    ///
    /// # Errors
    /// Returns an error if snapshots are not supported by this provider.
    async fn snapshot(&mut self) -> Result<SnapshotId> {
        Err(CoreError::Unsupported {
            feature: "snapshot".into(),
        })
    }

    /// Restore a previously taken snapshot.
    ///
    /// # Errors
    /// Returns an error if snapshots are not supported or `id` is invalid.
    async fn restore(&mut self, _id: SnapshotId) -> Result<()> {
        Err(CoreError::Unsupported {
            feature: "restore".into(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryView — spec §2.4 (trait abstraction over the concrete struct)
// ─────────────────────────────────────────────────────────────────────────────

/// The minimal trait that every "loaded binary" type implements.
///
/// Concrete types (such as [`crate::binary_view::BinaryView`] and
/// [`crate::binary_view_impl::BinaryViewFull`]) implement this so that
/// generic analysis / UI code can operate on either representation.
pub trait BinaryViewTrait: Send + Sync {
    /// Unique session-scoped identifier.
    fn id(&self) -> ViewId;
    /// Architecture handle.
    fn arch(&self) -> Arc<dyn Architecture>;
    /// Endianness of the loaded binary.
    fn endian(&self) -> Endian;
    /// Address width in bits (16 / 32 / 64 / 128).
    fn bits(&self) -> u8;
    /// Entry points.
    fn entry_points(&self) -> Vec<Address>;
}

// ─────────────────────────────────────────────────────────────────────────────
// FormatParser — spec §3 family (PE, ELF, Mach-O, .NET, JVM, DEX, ...)
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque, format-specific parse result wrapped for cross-crate transport.
pub type FormatParseResult = Box<dyn Any + Send + Sync>;

/// Parser for a concrete container / object format.
///
/// Distinct from [`crate::loader::Loader`] in that a `FormatParser` only
/// produces a structured representation of the file (headers, sections,
/// imports, ...) without building a `BinaryView`. A `Loader` typically wraps
/// one or more `FormatParser`s to assemble the final view.
pub trait FormatParser: Send + Sync + fmt::Debug {
    /// Canonical format name (e.g. `"pe"`, `"elf"`, `"mach-o"`, `"dex"`).
    fn name(&self) -> &str;

    /// File extensions handled by this parser.
    fn extensions(&self) -> &[&str];

    /// Magic-bytes confidence score in `0..=255`.
    fn probe(&self, bytes: &[u8]) -> u8;

    /// Parse the bytes into a format-specific representation.
    ///
    /// # Errors
    /// Returns an error if the bytes are malformed for this format.
    fn parse(&self, bytes: &[u8]) -> Result<FormatParseResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demangler
// ─────────────────────────────────────────────────────────────────────────────

/// Symbol demangler (Itanium C++, MSVC, Rust, Swift, ...).
pub trait Demangler: Send + Sync + fmt::Debug {
    /// Identifier for the mangling scheme (e.g. `"itanium"`, `"msvc"`, `"rust"`).
    fn name(&self) -> &str;

    /// `true` if `symbol` looks like it belongs to this scheme.
    fn matches(&self, symbol: &str) -> bool;

    /// Demangle a symbol. Implementations should fail gracefully and return
    /// `Ok(None)` for unrecognised inputs rather than an error.
    ///
    /// # Errors
    /// Returns an error only on truly unrecoverable parse failures.
    fn demangle(&self, symbol: &str) -> Result<Option<String>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeSystem trait — generic interface over the concrete type store
// ─────────────────────────────────────────────────────────────────────────────

/// Generic interface that every concrete type store implements.
///
/// Concrete stores: [`crate::types::TypeStore`] and the richer
/// [`crate::type_system_full`] module.
pub trait TypeSystem: Send + Sync {
    /// Number of defined types.
    fn type_count(&self) -> usize;

    /// Lookup a type's printable name by raw id.
    fn type_name(&self, raw_id: u64) -> Option<String>;

    /// Compute the size in bytes of a type, if statically known.
    fn size_of(&self, raw_id: u64) -> Option<usize>;

    /// Compute alignment, if statically known.
    fn align_of(&self, raw_id: u64) -> Option<usize>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Decompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Output of a [`Decompiler`].
#[derive(Clone, Debug)]
pub struct DecompilerOutput {
    /// Pseudo-source text (C-like by default).
    pub text: String,
    /// Optional structured AST blob (decompiler-specific).
    pub ast: Option<Vec<u8>>,
    /// Map source line → original instruction address, when available.
    pub line_to_addr: Vec<(u32, Address)>,
}

/// Function-level decompiler.
pub trait Decompiler: Send + Sync + fmt::Debug {
    /// Decompiler name (`"hexrays"`, `"ghidra"`, `"rustre-native"`, ...).
    fn name(&self) -> &str;

    /// Architectures supported by this decompiler.
    fn supported_archs(&self) -> Vec<String>;

    /// Decompile a single function.
    ///
    /// # Errors
    /// Returns an error if the function cannot be lifted or decompiled.
    fn decompile_function(
        &self,
        view: &dyn BinaryViewTrait,
        entry: Address,
    ) -> Result<DecompilerOutput>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Debugger
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for a thread in a debugged target.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ThreadId(pub u64);

/// Reason a debugged target stopped.
#[derive(Clone, Debug)]
pub enum StopReason {
    /// User-requested pause.
    Paused,
    /// A breakpoint was hit.
    Breakpoint {
        /// Address of the breakpoint.
        address: Address,
    },
    /// Single-step completed.
    Step,
    /// A signal / exception was raised.
    Signal {
        /// Implementation-specific signal name.
        name: String,
    },
    /// The target exited.
    Exited {
        /// Exit code.
        code: i32,
    },
}

/// Dynamic-analysis driver (process, emulator, remote stub).
#[async_trait]
pub trait Debugger: Send + Sync + fmt::Debug {
    /// Debugger backend name.
    fn name(&self) -> &str;

    /// Start / attach to a target.
    ///
    /// # Errors
    /// Returns an error if the target cannot be launched or attached.
    async fn launch(&mut self, target: &str) -> Result<()>;

    /// Resume execution of all threads.
    ///
    /// # Errors
    /// Returns an error if the target cannot be resumed.
    async fn resume(&mut self) -> Result<()>;

    /// Pause execution of all threads.
    ///
    /// # Errors
    /// Returns an error if the target cannot be paused.
    async fn pause(&mut self) -> Result<()>;

    /// Step one machine instruction in `thread`.
    ///
    /// # Errors
    /// Returns an error if the step fails.
    async fn step(&mut self, thread: ThreadId) -> Result<StopReason>;

    /// Install a software breakpoint at `address`.
    ///
    /// # Errors
    /// Returns an error if the breakpoint cannot be installed.
    async fn set_breakpoint(&mut self, address: Address) -> Result<()>;

    /// Remove a previously-installed breakpoint.
    ///
    /// # Errors
    /// Returns an error if the breakpoint cannot be removed.
    async fn clear_breakpoint(&mut self, address: Address) -> Result<()>;

    /// List currently-known threads.
    fn threads(&self) -> Vec<ThreadId>;
}

// ─────────────────────────────────────────────────────────────────────────────
// ScriptEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Scripting backend (Python, Rhai, Lua, JS, ...).
pub trait ScriptEngine: Send + Sync + fmt::Debug {
    /// Engine name (e.g. `"python"`, `"rhai"`).
    fn name(&self) -> &str;

    /// File extensions recognised by this engine.
    fn extensions(&self) -> &[&str];

    /// Evaluate a snippet, returning a printable representation of the result.
    ///
    /// # Errors
    /// Returns an error if the script fails to compile or execute.
    fn eval(&mut self, source: &str) -> Result<String>;

    /// Load and execute a script file.
    ///
    /// # Errors
    /// Returns an error if the script fails to load or execute.
    fn load_file(&mut self, path: &str) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Visualizer
// ─────────────────────────────────────────────────────────────────────────────

/// Format of a visualizer's output.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VisualizationFormat {
    /// Plain text (e.g. ASCII art, mermaid).
    Text,
    /// Scalable Vector Graphics.
    Svg,
    /// PNG bitmap.
    Png,
    /// `GraphViz` DOT source.
    Dot,
    /// HTML fragment.
    Html,
}

/// Renders some aspect of a [`BinaryViewTrait`] into a visual artefact.
pub trait Visualizer: Send + Sync + fmt::Debug {
    /// Visualizer name (`"cfg-graph"`, `"call-graph"`, `"entropy-heatmap"`...).
    fn name(&self) -> &str;

    /// Output format produced by this visualizer.
    fn format(&self) -> VisualizationFormat;

    /// Render a view into bytes of the declared [`format`](Self::format).
    ///
    /// # Errors
    /// Returns an error if rendering fails.
    fn render(&self, view: &dyn BinaryViewTrait) -> Result<Vec<u8>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin host abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle context handed to plugins at load time.
///
/// This is distinct from [`crate::plugin_context::PluginContext`] (which is
/// per-view state). `PluginHostContext` represents the *host application*'s
/// services available to a plugin.
pub trait PluginHostContext: Send + Sync {
    /// Host application name, e.g. `"rustre-gui"`, `"rustre-cli"`.
    fn host_name(&self) -> &str;

    /// Host application version.
    fn host_version(&self) -> &str;

    /// Workspace data directory (where plugins may persist state).
    fn data_dir(&self) -> &str;
}

/// Application-wide service that loads, unloads, and dispatches to plugins.
///
/// Implemented by the host application (CLI / daemon / GUI). The plugin
/// loader (`rustre-plugin-loader`) typically holds one of these and
/// instantiates `dyn Plugin` objects.
pub trait PluginHost: Send + Sync {
    /// Register a plugin instance under `id`.
    ///
    /// # Errors
    /// Returns an error if a plugin with the same id is already registered.
    fn register(&mut self, id: &str, plugin: Box<dyn crate::plugin_registry::Plugin>)
    -> Result<()>;

    /// Unregister a previously registered plugin.
    ///
    /// # Errors
    /// Returns an error if no plugin with `id` is registered.
    fn unregister(&mut self, id: &str) -> Result<()>;

    /// Iterate over the ids of currently registered plugins.
    fn plugin_ids(&self) -> Vec<String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Aliases — spec uses shorter names in several places
// ─────────────────────────────────────────────────────────────────────────────

/// Alias for [`Architecture`] — matches the short name used in spec §2.7.
pub use crate::arch::Architecture as Arch;

/// Alias for [`crate::analysis::AnalysisPass`] — matches the short name used
/// in spec §2.10 and the public README.
pub use crate::analysis::AnalysisPass as Analyzer;

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DummyDemangler;
    impl Demangler for DummyDemangler {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn matches(&self, s: &str) -> bool {
            s.starts_with("_Z")
        }
        fn demangle(&self, s: &str) -> Result<Option<String>> {
            Ok(if self.matches(s) {
                Some(s[2..].to_string())
            } else {
                None
            })
        }
    }

    #[test]
    fn demangler_basic() {
        let d = DummyDemangler;
        assert!(d.matches("_ZN3foo"));
        assert_eq!(d.demangle("_ZN3foo").unwrap().as_deref(), Some("N3foo"));
        assert_eq!(d.demangle("other").unwrap(), None);
    }

    #[test]
    fn snapshot_id_eq() {
        assert_eq!(SnapshotId(1), SnapshotId(1));
        assert_ne!(SnapshotId(1), SnapshotId(2));
    }

    #[test]
    fn visualization_format_variants() {
        let f = VisualizationFormat::Svg;
        assert_eq!(f, VisualizationFormat::Svg);
        assert_ne!(f, VisualizationFormat::Png);
    }
}
