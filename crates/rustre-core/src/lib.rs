//! # rustre-core
//!
//! The foundational crate for the `RustRE` reverse-engineering platform.
//!
//! This crate defines the core abstractions shared by every other crate in the
//! workspace:
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`address`] | Virtual/physical/file-offset address types and ranges |
//! | [`arch`] | Architecture trait, instruction/operand/register types |
//! | [`binary_view`] | In-memory binary view with symbol table, type system, function table, xrefs, patches, comments, bookmarks |
//! | [`endian`] | Endianness enum and byte-order-aware I/O helpers |
//! | [`errors`] | [`CoreError`] and [`Result`] type alias |
//! | [`ids`] | Typed ID newtypes and allocators |
//! | [`loader`] | Binary loader trait, registry, hints, options |
//! | [`permissions`] | Memory permission bitflags and protection models |

// ─────────────────────────────────────────────────────────────────────────────
// Crate version (exposed so callers can print it without re-reading their own
// CARGO_PKG_VERSION, which may differ from this crate's version).
// ─────────────────────────────────────────────────────────────────────────────

/// The version of `rustre-core` as declared in its `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─────────────────────────────────────────────────────────────────────────────
// Modules
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual/physical/file-offset address types, ranges, and translations.
pub mod address;

/// Architecture abstraction: trait, instructions, registers, calling conventions.
pub mod arch;

/// In-memory binary view with all associated analysis stores.
pub mod binary_view;

/// Endianness modelling and byte-order-aware I/O helpers.
pub mod endian;

/// Unified error type and `Result<T>` alias.
pub mod errors;

/// Typed ID newtypes and allocators.
pub mod ids;

/// Binary loader abstraction: trait, registry, hints, options.
pub mod loader;

/// Memory permission bitflags and protection models.
pub mod permissions;

/// Patch management, comment storage, and bookmark tracking.
pub mod patches;

/// Async event bus for platform-wide change notifications.
pub mod events;

/// Comprehensive type system: `TypeId`, `TypeKind`, `TypeDef`, `TypeStore`.
pub mod types;

/// Complete type system.
///
/// Provides `TypeId`, `TypeKind`, `TypeSystem` (define/lookup/resolve/merge),
/// `TypeLayout` (size/alignment/padding), `TypePrinter` (C-style), and
/// `DwarfTypeImporter`.
pub mod type_system_full;

/// Symbol table, function registry, basic-block CFG, and cross-reference store.
pub mod symbols;

/// Analysis pass infrastructure: trait, dependency graph, pass manager.
pub mod analysis;

/// Plugin context registry for per-view plugin state.
pub mod plugin;

/// Disassembly style and display options.
pub mod disasm_style;

/// Mode enumeration for multi-mode architectures.
pub mod arch_mode;

/// Full `BinaryView` implementation.
///
/// Provides `BinaryUri`, `ArchHandle`, `FunctionTable`, `TypeSystem`,
/// `XrefIndex`, `PatchSet`, `CommentStore`, `BookmarkSet`, and
/// `BinaryViewBuilder`.
pub mod binary_view_impl;

/// Analysis pipeline: pass ordering, scheduling, progress reporting, PassScheduler, BuiltinPassKind, AutoAnalysis.
pub mod analysis_pipeline;

/// Per-view plugin context: ViewPlugin trait, PluginContext, PluginAction, ActionHistory, PluginInterop.
pub mod plugin_context;

/// Complete analysis session management: AnalysisSession, SessionState, SessionConfig, SessionLog, SessionExport, SessionRestore.
pub mod analysis_session;

/// Event bus: EventBus, Event trait, EventKind, Subscription, subscribe(), publish().
pub mod event_bus;

/// Plugin registry: PluginRegistry, PluginEntry, PluginHandle, register_plugin(), unload_plugin().
pub mod plugin_registry;

/// Workspace manager: WorkspaceManager, Workspace, WorkspaceConfig, open_workspace(), save_workspace().
pub mod workspace_manager;

/// Cross-crate trait abstractions per spec §2.
///
/// Includes: `MemoryProvider`, `BinaryViewTrait`, `FormatParser`, `Demangler`,
/// `TypeSystem`, `Decompiler`, `Debugger`, `ScriptEngine`, `Visualizer`,
/// `PluginHost`, `PluginHostContext`, plus the `Arch` / `Analyzer` aliases.
pub mod traits;

// ─────────────────────────────────────────────────────────────────────────────
// Flat re-exports — most commonly used items
// ─────────────────────────────────────────────────────────────────────────────

// Address types.
pub use address::{
    Address, AddressRange, AddressSpace, AddressSpaceKind, AddressTranslation, FileOffset,
    FileOffsetRange, PhysicalAddress, RVA, SegmentMapping, TypedAddress, VirtualAddress,
};

// Architecture types.
pub use arch::{
    Architecture, ArchitectureRegistry, BranchCondition, BranchInfo, BranchKind, CallingConvention,
    DisassemblyContext, InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind,
};

// Binary view.
pub use binary_view::{BinaryView, Memory, Segment};

// Endian.
pub use endian::{
    Endian, EndianBuf, EndianRead, EndianReader, EndianWriter, decode_sleb128, decode_uleb128,
    encode_sleb128, encode_uleb128, swap_endian_u16, swap_endian_u32, swap_endian_u64,
    swap_endian_u128,
};

// Errors.
pub use errors::{CoreError, ErrorContext, Result, ResultExt};

// IDs.
pub use ids::{
    BasicBlockId, DataVarId, FunctionId, IdAllocator, IdMap, IdPool, IdType, InstructionId,
    SectionId, SegmentId, SymbolId, TagId, TypeId, ViewId,
};

// Loader.
pub use loader::Loader;
pub use loader::{
    BinaryType, HintSet, LoadResult, LoaderHint, LoaderInput, LoaderOptions, LoaderRegistry,
    NestedBinary,
};

// Permissions.
pub use permissions::{
    InheritFlags, MemoryProtection, PermissionChange, PermissionPolicy, PermissionRule,
    PermissionSet, Permissions,
};

// Patches.
pub use patches::{
    Bookmark, BookmarkColor, BookmarkId, BookmarkSet, Comment, CommentId, CommentStore, Patch,
    PatchId, PatchKind, PatchSet,
};

// Events.
pub use events::{CoreEvent, EventBus, EventFilter, EventRecorder, FilteredReceiver};

// Types.
pub use types::{
    CallConvId, EnumMember, FloatKind, FunctionParam, FunctionSignature, IntType, StructField,
    TypeDef, TypeId as AnalysisTypeId, TypeKind, TypeStore,
};

// Symbols.
pub use symbols::{
    BBEdge, BBEdgeKind, BasicBlock, FnFlags, FunctionRecord, FunctionRegistry, SymbolBinding,
    SymbolEntry, SymbolFlags, SymbolIndex, XrefKind, XrefRecord, XrefStore,
};

// Analysis.
pub use analysis::{AnalysisPass, AnalysisPassInfo, PassDependency, PassManager, PassResult};

// Plugin.
pub use plugin::{PluginContext, PluginId, PluginRegistry, PluginState};

// Disassembly style.
pub use disasm_style::{
    AddressStyle, DisasmStyle, ImmediateStyle, MnemonicCase, OperandSeparator, PseudoInstrMode,
    SyntaxFlavor,
};

// Arch mode.
pub use arch_mode::Mode;

// binary_view_impl re-exports.
pub use binary_view_impl::{
    ArchHandle, BinaryUri, BinaryViewBuilder, BinaryViewFull,
    BookmarkColor as BinaryViewBookmarkColor, BookmarkEntry, BookmarkId as BinaryViewBookmarkId,
    BookmarkSet as BinaryViewBookmarkSet, CommentEntry, CommentId as BinaryViewCommentId,
    CommentStore as BinaryViewCommentStore, FunctionEntry,
    FunctionTable as BinaryViewFunctionTable, PatchConflict as BinaryViewPatchConflict, PatchEntry,
    PatchSet as BinaryViewPatchSet, TypeDefinition, TypeSource, TypeSystem as BinaryViewTypeSystem,
    XrefEntry, XrefIndex as BinaryViewXrefIndex, XrefKind as BinaryViewXrefKind,
};

// analysis_pipeline re-exports.
pub use analysis_pipeline::{
    AnalysisPassImpl, AnalysisPipeline, AnalysisProgress, AutoAnalysis, BuiltinPassKind,
    PassFinding, PassInfo, PassScheduler, PassStatus, PipelinePassResult,
};

// plugin_context re-exports.
pub use plugin_context::{
    ActionHistory, PluginAction, PluginContext as ViewPluginContext, PluginId as ViewPluginId,
    PluginInterop, PluginLifecycle, PluginMessage, PluginStateBox, ViewPlugin,
};

// Core trait abstractions (spec §2).
pub use traits::{
    Arch, Analyzer, BinaryViewTrait, Debugger, Decompiler, DecompilerOutput, Demangler,
    FormatParseResult, FormatParser, MemoryProvider, MemoryRegion, PluginHost, PluginHostContext,
    RegionSource, ScriptEngine, SnapshotId, StopReason, ThreadId, TypeSystem as TypeSystemTrait,
    VisualizationFormat, Visualizer,
};

// Plugin trait from plugin_registry (avoids name clash with PluginRegistry from plugin.rs).
pub use plugin_registry::{Plugin, PluginMetadata};

// async_trait re-export for downstream crates that implement Loader.
pub use async_trait::async_trait;

// Workspace event bus, knowledge base, and storage layer re-exports.
pub use rustre_events;
pub use rustre_knowledge;
pub use rustre_db;

/// Process-wide singleton wiring for the [`rustre_events`] platform event bus.
///
/// Provides [`platform_event_bus::platform_bus`] /
/// [`platform_event_bus::platform_dispatcher`] /
/// [`platform_event_bus::platform_logger`] singletons plus a [`publish`]
/// helper so any crate in the workspace can fire platform-wide
/// [`rustre_events::CoreEvent`]s without threading an `Arc<EventBus>` through
/// its API.
pub mod platform_event_bus;

// Platform-wide event bus singletons (from rustre-events).  These live
// alongside the local `events::EventBus` (which is scoped to a single
// `BinaryView`'s lifecycle) and provide the workspace-global broadcast
// channel that every subsystem can publish to.
pub use platform_event_bus::{
    platform_bus, platform_dispatcher, platform_logger, publish as publish_platform_event,
    register_hook as register_platform_hook,
};

// ─────────────────────────────────────────────────────────────────────────────
// Macro re-exports
// ─────────────────────────────────────────────────────────────────────────────

// bail_core! and ensure_core! are defined with #[macro_export] in errors.rs,
// so they are automatically accessible at crate root.

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ── Stub architecture ─────────────────────────────────────────────────────

    #[derive(Debug)]
    struct DummyArch;

    impl Architecture for DummyArch {
        fn name(&self) -> &'static str {
            "dummy-arch"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }

        fn disassemble(&self, address: Address, bytes: &[u8]) -> errors::Result<Instruction> {
            let size = bytes.len().min(4);
            Ok(Instruction::new(
                address,
                size.max(1),
                "nop",
                bytes[..size.max(1)].to_vec(),
            ))
        }

        fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }

    // ── Stub loader ───────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct DummyLoader;

    #[async_trait]
    impl Loader for DummyLoader {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn can_load(&self, input: &LoaderInput) -> bool {
            input.starts_with(b"DUMMY")
        }

        async fn load(&self, input: LoaderInput) -> errors::Result<LoadResult> {
            let view_id = ViewId::from_raw(1);
            let arch = Arc::new(DummyArch);
            let mut mem = Memory::new();
            mem.add_segment(binary_view::Segment {
                range: AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: vec![0; 0x100],
            });
            let view = BinaryView::new(
                view_id,
                input.uri,
                arch,
                Endian::Little,
                64,
                vec![Address::new(0x1000)],
                mem,
            );
            Ok(LoadResult::new(view))
        }

        async fn find_nested(&self, _input: &LoaderInput) -> errors::Result<Vec<NestedBinary>> {
            Ok(vec![])
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_registries_and_loading() {
        let loader_registry = LoaderRegistry::new();
        let arch_registry = ArchitectureRegistry::new();

        let dummy_loader = Arc::new(DummyLoader);
        let dummy_arch = Arc::new(DummyArch);

        loader_registry.register(dummy_loader.clone());
        arch_registry.register(dummy_arch);

        assert!(loader_registry.find_by_name("dummy").is_some());
        assert!(arch_registry.find_by_name("dummy-arch").is_some());

        let input = LoaderInput::new("file://dummy_bin", b"DUMMY_HEADER_BYTES_GO_HERE".to_vec());

        let probed = loader_registry.probe(&input);
        assert_eq!(probed.len(), 1);
        assert_eq!(probed[0].name(), "dummy");

        let result = probed[0].load(input).await.unwrap();
        let view = result.view;
        assert_eq!(view.uri, "file://dummy_bin");
        assert_eq!(view.entry_points.len(), 1);
        assert_eq!(view.entry_points[0].0, 0x1000);

        let (seg_count, first_seg_start) = {
            let mem = view.mem.read();
            (mem.segments.len(), mem.segments[0].range.start.0)
        };
        assert_eq!(seg_count, 1);
        assert_eq!(first_seg_start, 0x1000);
    }

    #[test]
    fn test_id_allocator_integration() {
        let func_alloc = IdAllocator::<FunctionId>::new();
        let mut func_pool = IdPool::<FunctionId>::new();
        let mut map: IdMap<FunctionId, String> = IdMap::new();

        for i in 0..5u64 {
            let id = func_alloc.next();
            map.insert(id, format!("fn_{i}"));
        }
        assert_eq!(map.len(), 5);

        let id = func_pool.alloc();
        func_pool.reclaim(id);
        let reused = func_pool.alloc();
        assert_eq!(reused, id);
    }

    #[test]
    fn test_address_range_iter() {
        let range = AddressRange::new(Address::new(0x100), Address::new(0x104));
        let addrs: Vec<u64> = range.iter().map(super::address::Address::as_u64).collect();
        assert_eq!(addrs, [0x100, 0x101, 0x102, 0x103]);
    }

    #[test]
    fn test_rva_resolve() {
        let base = Address::new(0x4000_0000);
        let rva = RVA::new(0x1000);
        assert_eq!(rva.resolve(base), Address::new(0x4000_1000));
    }

    #[test]
    fn test_segment_mapping_translation() {
        let seg = SegmentMapping::new(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            FileOffsetRange::new(FileOffset::new(0x400), FileOffset::new(0x1400)),
        );
        let fo = seg.va_to_file_offset(Address::new(0x1100)).unwrap();
        assert_eq!(fo, FileOffset::new(0x500));
        let va = seg.file_offset_to_va(FileOffset::new(0x500)).unwrap();
        assert_eq!(va, Address::new(0x1100));
    }

    #[test]
    fn test_permissions_rwx() {
        let p = Permissions::READ | Permissions::EXECUTE;
        assert!(p.is_readable());
        assert!(!p.is_writable());
        assert!(p.is_executable());
        assert_eq!(p.as_rwx_string(), "r-x");
    }

    #[test]
    fn test_endian_buf_roundtrip() {
        let mut buf = EndianBuf::new(Endian::Little);
        buf.write_u64(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(buf.read_u64(0), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_uleb128_sleb128_roundtrip() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            16383,
            u64::from(u32::MAX),
            u64::MAX / 2,
        ] {
            let enc = encode_uleb128(v);
            let (dec, _) = decode_uleb128(&enc, 0).unwrap();
            assert_eq!(dec, v);
        }
        for v in [
            0i64,
            -1,
            63,
            -64,
            300,
            -300,
            i64::from(i32::MAX),
            i64::from(i32::MIN),
        ] {
            let enc = encode_sleb128(v);
            let (dec, _) = decode_sleb128(&enc, 0).unwrap();
            assert_eq!(dec, v);
        }
    }

    #[test]
    fn test_core_error_variants() {
        let e = CoreError::io("disk error");
        assert!(e.is_io());
        assert!(!e.is_transient());

        let e2 = CoreError::Timeout { millis: 1000 };
        assert!(e2.is_transient());
    }

    #[test]
    fn test_error_context_ext() {
        use errors::ResultExt;
        let r: errors::Result<()> = Err(CoreError::io("oops"));
        let ctx_err = r.attach_context("loading binary").unwrap_err();
        assert_eq!(ctx_err.context, "loading binary");
    }

    #[test]
    fn test_disassembly_context() {
        let mut ctx = DisassemblyContext::new();
        assert!(!ctx.in_it_block());
        ctx.enter_it_block(2, 0x0);
        assert!(ctx.in_it_block());
        ctx.advance_it_block();
        ctx.advance_it_block();
        assert!(!ctx.in_it_block());
    }

    #[test]
    fn test_branch_info_constructors() {
        let j = BranchInfo::unconditional_jump(0x4000);
        assert_eq!(j.target, Some(0x4000));
        assert!(j.is_unconditional());

        let r = BranchInfo::ret();
        assert!(r.kind == BranchKind::Return);
    }

    #[test]
    fn test_register_info() {
        let r = RegisterInfo::new("rax", 0, 8, RegisterKind::General);
        assert!(r.is_general());
        assert!(!r.is_stack_pointer());
        assert_eq!(r.size_bits(), 64);
    }

    #[test]
    fn test_permission_policy() {
        let mut policy = PermissionPolicy::new();
        policy.add_rule(PermissionRule::deny(Permissions::EXECUTE));
        assert!(policy.is_denied(Permissions::EXECUTE));
        assert!(policy.is_allowed(Permissions::READ));
    }

    #[test]
    fn test_memory_protection_conversions() {
        let p = MemoryProtection::LinuxReadExec.to_permissions();
        assert!(p.is_readable());
        assert!(p.is_executable());
        assert!(!p.is_writable());
    }

    #[test]
    fn test_inherit_flags() {
        assert!(InheritFlags::Copy.is_private_copy());
        assert!(!InheritFlags::None.is_inherited());
        assert_eq!(InheritFlags::Share.to_string(), "share");
    }

    #[test]
    fn test_loader_options() {
        let opts = LoaderOptions::new()
            .set("verbose", "true")
            .set("base", "0x1000");
        assert_eq!(opts.get_bool("verbose"), Some(true));
        assert_eq!(opts.get_u64("base"), Some(0x1000));
        assert_eq!(opts.len(), 2);
    }

    #[test]
    fn test_binary_type() {
        assert!(BinaryType::Executable.is_runnable());
        assert!(!BinaryType::Library.is_runnable());
        assert!(BinaryType::Archive.is_library());
    }

    // ── Analysis pass tests ───────────────────────────────────────────────────

    #[test]
    fn test_pass_manager_basic() {
        let mut manager = PassManager::new();
        assert_eq!(manager.pass_count(), 0);
        // Adding a pass by name (no-op pass).
        manager.register_pass(AnalysisPassInfo::new("cfg-build", &[]));
        manager.register_pass(AnalysisPassInfo::new("type-infer", &["cfg-build"]));
        assert_eq!(manager.pass_count(), 2);
        let order = manager.topological_order().unwrap();
        assert_eq!(order[0], "cfg-build");
        assert_eq!(order[1], "type-infer");
    }

    #[test]
    fn test_pass_manager_cycle_detection() {
        let mut manager = PassManager::new();
        manager.register_pass(AnalysisPassInfo::new("a", &["b"]));
        manager.register_pass(AnalysisPassInfo::new("b", &["a"]));
        assert!(manager.topological_order().is_err());
    }

    // ── Plugin context tests ──────────────────────────────────────────────────

    #[test]
    fn test_plugin_registry() {
        let mut reg: PluginRegistry = PluginRegistry::new();
        let id = PluginId::new("test-plugin");
        reg.register(id.clone(), Box::new(42u32));
        assert!(reg.contains(&id));
        reg.unregister(&id);
        assert!(!reg.contains(&id));
    }

    // ── DisasmStyle tests ─────────────────────────────────────────────────────

    #[test]
    fn test_disasm_style_default() {
        let style = DisasmStyle::default();
        assert_eq!(style.mnemonic_case, MnemonicCase::Lower);
        assert_eq!(style.syntax_flavor, SyntaxFlavor::Intel);
    }

    #[test]
    fn test_disasm_style_at_t() {
        let style = DisasmStyle::at_t();
        assert_eq!(style.syntax_flavor, SyntaxFlavor::AtT);
    }

    // ── Mode tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_mode_display() {
        assert_eq!(Mode::X86_64.to_string(), "x86_64");
        assert_eq!(Mode::Thumb.to_string(), "Thumb");
        assert_eq!(Mode::Mips16.to_string(), "MIPS16");
    }

    #[test]
    fn test_mode_pointer_size() {
        assert_eq!(Mode::X86_64.pointer_size(), 8);
        assert_eq!(Mode::X86_32.pointer_size(), 4);
        assert_eq!(Mode::X86_16.pointer_size(), 2);
        assert_eq!(Mode::Arm32.pointer_size(), 4);
        assert_eq!(Mode::Aarch64.pointer_size(), 8);
    }

    // ── Symbol table extended tests ───────────────────────────────────────────

    #[test]
    fn test_symbol_index_range_query() {
        let mut idx = SymbolIndex::new();
        idx.insert(SymbolEntry::new("fn_a", Address::new(0x1000)));
        idx.insert(SymbolEntry::new("fn_b", Address::new(0x2000)));
        idx.insert(SymbolEntry::new("fn_c", Address::new(0x3000)));
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x2500));
        let results = idx.symbols_in_range(range);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_xref_store_callers_callees() {
        let mut store = XrefStore::new();
        store.add(XrefRecord::certain(
            Address::new(0x100),
            Address::new(0x200),
            XrefKind::Call,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x150),
            Address::new(0x200),
            XrefKind::Call,
        ));
        store.add(XrefRecord::certain(
            Address::new(0x100),
            Address::new(0x300),
            XrefKind::DataRead,
        ));

        let callers = store.callers_of(Address::new(0x200));
        assert_eq!(callers.len(), 2);

        let callees_of_100 = store.callees_of(Address::new(0x100));
        assert_eq!(callees_of_100.len(), 1);
    }

    // ── Function registry overlap test ────────────────────────────────────────

    #[test]
    fn test_function_registry_in_range() {
        let mut reg = FunctionRegistry::new();
        reg.insert(
            FunctionRecord::new(Address::new(0x1000), "alpha").with_end(Address::new(0x1100)),
        );
        reg.insert(
            FunctionRecord::new(Address::new(0x2000), "beta").with_end(Address::new(0x2100)),
        );
        reg.insert(
            FunctionRecord::new(Address::new(0x3000), "gamma").with_end(Address::new(0x3100)),
        );

        let range = AddressRange::new(Address::new(0x1000), Address::new(0x2500));
        let in_range = reg.in_range(range);
        assert_eq!(in_range.len(), 2);
    }

    // ── PatchSet tests ────────────────────────────────────────────────────────

    #[test]
    fn test_patch_set_add_and_undo() {
        let mut ps = PatchSet::new();
        let id = ps.insert(Patch::new(
            0x1000u64,
            vec![0xCC, 0xCC],
            vec![0x90, 0x90],
            PatchKind::Nop,
        ));
        assert_eq!(ps.len(), 1);
        let removed = ps.remove(id);
        assert!(removed.is_some());
        assert_eq!(ps.len(), 0);
    }

    // ── CommentStore tests ────────────────────────────────────────────────────

    #[test]
    fn test_comment_store_add_and_get() {
        let mut cs = CommentStore::new();
        let id = cs.add_text(0xDEADu64, "stack canary check");
        let comments = cs.at(0xDEAD);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].1.text, "stack canary check");
        cs.remove(id);
        assert!(cs.at(0xDEAD).is_empty());
    }

    // ── BookmarkSet tests ─────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_set() {
        let mut bs = BookmarkSet::new();
        let id = bs.insert(Bookmark::new(0x1234u64, "interesting").with_color(BookmarkColor::Red));
        assert_eq!(bs.len(), 1);
        let found = bs.at(0x1234);
        assert!(!found.is_empty());
        assert_eq!(found[0].1.label, "interesting");
        bs.remove(id);
        assert!(bs.is_empty());
    }
}
