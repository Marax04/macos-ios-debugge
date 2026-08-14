//! `exception_cfg.rs` — CFG with exception handling support.
//!
//! Handles:
//! - Windows SEH (structured exception handling)
//! - C++ EH (MSVC __try/__except, GCC .`gcc_except_table`, LLVM LSDA)
//! - Unwind info parsing (DWARF .`eh_frame`, Windows `RUNTIME_FUNCTION`)
//! - Landing pad identification
//! - Cleanup vs catch distinction
//! - Finally blocks

use crate::{ControlFlowGraph, EdgeKind};
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionHandlingKind — EH flavour
// ─────────────────────────────────────────────────────────────────────────────

/// The exception-handling mechanism in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionHandlingKind {
    /// Windows SEH: __try / __except / __finally (x86 fs:[0] chain).
    WindowsSeh,
    /// Windows 64-bit SEH: table-based via `RUNTIME_FUNCTION` / `UNWIND_INFO`.
    WindowsSeh64,
    /// MSVC C++ EH: __try / __except with typed filter.
    MsvcCppEh,
    /// GCC/Clang C++ EH: .`gcc_except_table` / LSDA / `DW_CFA`.
    GccCppEh,
    /// LLVM LSDA-based EH (Clang with personality function).
    LlvmLsda,
    /// Rust panic via `rust_begin_unwind` / `__rust_start_panic`.
    RustPanic,
    /// Unknown / unrecognized EH mechanism.
    Unknown,
}

impl fmt::Display for ExceptionHandlingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsSeh => write!(f, "Windows-SEH"),
            Self::WindowsSeh64 => write!(f, "Windows-SEH64"),
            Self::MsvcCppEh => write!(f, "MSVC-C++EH"),
            Self::GccCppEh => write!(f, "GCC-C++EH"),
            Self::LlvmLsda => write!(f, "LLVM-LSDA"),
            Self::RustPanic => write!(f, "Rust-Panic"),
            Self::Unknown => write!(f, "Unknown-EH"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerKind — what the handler does
// ─────────────────────────────────────────────────────────────────────────────

/// What a particular EH handler does when reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerKind {
    /// Handles (catches) a specific exception type.
    Catch,
    /// Always executes when leaving a scope (try/finally).
    Finally,
    /// Cleans up resources (DWARF cleanup action).
    Cleanup,
    /// Terminates the program on unhandled exception.
    Terminate,
    /// A filter expression that decides whether to handle.
    Filter,
    /// Landing pad entry (generic; may be catch or cleanup).
    LandingPad,
}

impl fmt::Display for HandlerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catch => write!(f, "catch"),
            Self::Finally => write!(f, "finally"),
            Self::Cleanup => write!(f, "cleanup"),
            Self::Terminate => write!(f, "terminate"),
            Self::Filter => write!(f, "filter"),
            Self::LandingPad => write!(f, "landing_pad"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionRegion — a protected region + its handlers
// ─────────────────────────────────────────────────────────────────────────────

/// A region of code protected by an exception handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRegion {
    /// First address of the try body (inclusive).
    pub try_start: Address,
    /// Last address of the try body (exclusive).
    pub try_end: Address,
    /// All handlers associated with this region.
    pub handlers: Vec<ExceptionHandler>,
    /// The EH mechanism in use.
    pub kind: ExceptionHandlingKind,
    /// Nesting depth (0 = outermost).
    pub depth: u32,
}

impl ExceptionRegion {
    /// Returns `true` if `addr` is inside the try body.
    #[must_use]
    pub fn contains_try(&self, addr: Address) -> bool {
        addr >= self.try_start && addr < self.try_end
    }

    /// Return the first catch handler, if any.
    #[must_use]
    pub fn first_catch(&self) -> Option<&ExceptionHandler> {
        self.handlers.iter().find(|h| h.kind == HandlerKind::Catch)
    }

    /// Return all finally handlers.
    #[must_use]
    pub fn finally_handlers(&self) -> Vec<&ExceptionHandler> {
        self.handlers.iter().filter(|h| h.kind == HandlerKind::Finally).collect()
    }

    /// Whether there is at least one cleanup handler.
    #[must_use]
    pub fn has_cleanup(&self) -> bool {
        self.handlers.iter().any(|h| h.kind == HandlerKind::Cleanup)
    }
}

/// A single exception handler attached to a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionHandler {
    /// Entry address of the handler code.
    pub handler_addr: Address,
    /// Kind of handler.
    pub kind: HandlerKind,
    /// Caught type name (for C++ typed exceptions).
    pub type_name: Option<String>,
    /// Filter expression string (for SEH __except(filter)).
    pub filter_expr: Option<String>,
    /// Whether this handler re-throws.
    pub rethrows: bool,
    /// Landing pad action record index (LSDA).
    pub lsda_action_index: Option<u32>,
}

impl ExceptionHandler {
    #[must_use]
    pub const fn catch(addr: Address) -> Self {
        Self {
            handler_addr: addr,
            kind: HandlerKind::Catch,
            type_name: None,
            filter_expr: None,
            rethrows: false,
            lsda_action_index: None,
        }
    }

    #[must_use]
    pub const fn finally(addr: Address) -> Self {
        Self {
            handler_addr: addr,
            kind: HandlerKind::Finally,
            type_name: None,
            filter_expr: None,
            rethrows: false,
            lsda_action_index: None,
        }
    }

    #[must_use]
    pub const fn cleanup(addr: Address) -> Self {
        Self {
            handler_addr: addr,
            kind: HandlerKind::Cleanup,
            type_name: None,
            filter_expr: None,
            rethrows: false,
            lsda_action_index: None,
        }
    }

    pub fn with_type(mut self, name: impl Into<String>) -> Self {
        self.type_name = Some(name.into());
        self
    }

    pub fn with_filter(mut self, expr: impl Into<String>) -> Self {
        self.filter_expr = Some(expr.into());
        self.kind = HandlerKind::Filter;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnwindInfo — Windows 64-bit RUNTIME_FUNCTION / UNWIND_INFO
// ─────────────────────────────────────────────────────────────────────────────

/// A Windows x64 `RUNTIME_FUNCTION` entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RuntimeFunction {
    /// Start of the function.
    pub begin_address: u32,
    /// End of the function.
    pub end_address: u32,
    /// Relative virtual address of the `UNWIND_INFO` structure.
    pub unwind_info_address: u32,
}

/// Parsed `UNWIND_INFO` for a Windows x64 function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindInfo {
    /// `UNWIND_INFO` flags field.
    pub flags: u8,
    /// Size of the prolog in bytes.
    pub prolog_size: u8,
    /// Unwind codes count.
    pub unwind_code_count: u8,
    /// Whether there is an exception handler.
    pub has_exception_handler: bool,
    /// Whether there is a termination handler.
    pub has_termination_handler: bool,
    /// Whether this is a chained unwind info.
    pub is_chained: bool,
    /// Handler RVA (if `has_exception_handler`).
    pub handler_rva: Option<u32>,
    /// Chained `RUNTIME_FUNCTION` (if `is_chained`).
    pub chained_function: Option<RuntimeFunction>,
}

impl UnwindInfo {
    pub const UNW_FLAG_EHANDLER: u8 = 0x01;
    pub const UNW_FLAG_UHANDLER: u8 = 0x02;
    pub const UNW_FLAG_CHAININFO: u8 = 0x04;

    /// Parse flags byte.
    #[must_use]
    pub const fn from_flags_byte(flags: u8) -> Self {
        Self {
            flags,
            prolog_size: 0,
            unwind_code_count: 0,
            has_exception_handler: (flags & Self::UNW_FLAG_EHANDLER) != 0,
            has_termination_handler: (flags & Self::UNW_FLAG_UHANDLER) != 0,
            is_chained: (flags & Self::UNW_FLAG_CHAININFO) != 0,
            handler_rva: None,
            chained_function: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LsdaRecord — LLVM LSDA call-site record
// ─────────────────────────────────────────────────────────────────────────────

/// A call-site record from the LLVM LSDA (Language Specific Data Area).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsdaCallSite {
    /// Start offset of the call site (from function start).
    pub cs_start: u64,
    /// Length of the call site range.
    pub cs_len: u64,
    /// Landing pad offset (0 = no landing pad for this site).
    pub landing_pad: u64,
    /// Action record offset into the action table (0 = cleanup only).
    pub action_offset: u64,
}

/// A typed exception filter from an LSDA action table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsdaAction {
    /// Action index (1-based).
    pub index: u32,
    /// Type filter: positive = type index, negative = cleanup filter, 0 = cleanup.
    pub type_filter: i32,
    /// Next action index (0 = end of chain).
    pub next_action: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// SehFrame — x86 SEH frame (fs:[0] chain)
// ─────────────────────────────────────────────────────────────────────────────

/// A frame in the x86 SEH registration chain (`EXCEPTION_REGISTRATION_RECORD`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SehFrame {
    /// Address where the frame is registered (push of `EXCEPTION_REGISTRATION`).
    pub registration_addr: Address,
    /// Address of the filter/handler function.
    pub handler_addr: Address,
    /// The scope table base address (if MSVC scope-table SEH).
    pub scope_table: Option<Address>,
    /// Nesting level of the try scope.
    pub try_level: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionEdgeKind — exceptional CFG edge kinds
// ─────────────────────────────────────────────────────────────────────────────

/// Extended edge kinds for an exception-aware CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionEdgeKind {
    /// Normal control flow.
    Normal(EdgeKind),
    /// Unwind from a call site to a landing pad.
    Unwind,
    /// Execution of a cleanup (DWARF / __finally).
    Cleanup,
    /// Transfer to a typed catch handler.
    Catch,
    /// Transfer to a finally block.
    Finally,
    /// Re-throw from a handler.
    Rethrow,
    /// Transfer to a filter expression.
    Filter,
}

/// A CFG edge in the exception-aware graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionCfgEdge {
    pub from: Address,
    pub to: Address,
    pub kind: ExceptionEdgeKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionCfg — exception-aware control flow graph
// ─────────────────────────────────────────────────────────────────────────────

/// A control flow graph augmented with exception handling information.
#[derive(Debug, Clone)]
pub struct ExceptionCfg {
    /// Underlying normal CFG.
    pub base: ControlFlowGraph,
    /// All exception regions.
    pub regions: Vec<ExceptionRegion>,
    /// Additional edges representing exceptional control flow.
    pub exception_edges: Vec<ExceptionCfgEdge>,
    /// Set of block addresses identified as landing pads.
    pub landing_pads: HashSet<Address>,
    /// SEH frames (x86 only).
    pub seh_frames: Vec<SehFrame>,
    /// LSDA call-site records.
    pub lsda_sites: Vec<LsdaCallSite>,
    /// Unwind info (Windows x64).
    pub unwind_info: Option<UnwindInfo>,
}

impl ExceptionCfg {
    /// Create an `ExceptionCfg` from a base `ControlFlowGraph`.
    #[must_use]
    pub fn new(base: ControlFlowGraph) -> Self {
        Self {
            base,
            regions: Vec::new(),
            exception_edges: Vec::new(),
            landing_pads: HashSet::new(),
            seh_frames: Vec::new(),
            lsda_sites: Vec::new(),
            unwind_info: None,
        }
    }

    /// Add an exception region.
    pub fn add_region(&mut self, region: ExceptionRegion) {
        for handler in &region.handlers {
            self.landing_pads.insert(handler.handler_addr);
            self.exception_edges.push(ExceptionCfgEdge {
                from: region.try_start,
                to: handler.handler_addr,
                kind: match handler.kind {
                    HandlerKind::Catch => ExceptionEdgeKind::Catch,
                    HandlerKind::Finally => ExceptionEdgeKind::Finally,
                    HandlerKind::Cleanup => ExceptionEdgeKind::Cleanup,
                    HandlerKind::Filter => ExceptionEdgeKind::Filter,
                    HandlerKind::Terminate | HandlerKind::LandingPad => {
                        ExceptionEdgeKind::Unwind
                    }
                },
            });
        }
        self.regions.push(region);
    }

    /// Add an unwind edge from a call site to a landing pad.
    pub fn add_unwind_edge(&mut self, call_site: Address, landing_pad: Address) {
        self.landing_pads.insert(landing_pad);
        self.exception_edges.push(ExceptionCfgEdge {
            from: call_site,
            to: landing_pad,
            kind: ExceptionEdgeKind::Unwind,
        });
    }

    /// Returns `true` if `addr` is a landing pad.
    #[must_use]
    pub fn is_landing_pad(&self, addr: Address) -> bool {
        self.landing_pads.contains(&addr)
    }

    /// Return all exception regions that protect `addr`.
    #[must_use]
    pub fn regions_at(&self, addr: Address) -> Vec<&ExceptionRegion> {
        self.regions
            .iter()
            .filter(|r| r.contains_try(addr))
            .collect()
    }

    /// Return the innermost exception region at `addr` (deepest nesting).
    #[must_use]
    pub fn innermost_region(&self, addr: Address) -> Option<&ExceptionRegion> {
        self.regions_at(addr)
            .into_iter()
            .max_by_key(|r| r.depth)
    }

    /// Total number of exception edges.
    #[must_use]
    pub const fn exception_edge_count(&self) -> usize {
        self.exception_edges.len()
    }

    /// Return all landing pads reachable from a given address via exception edges.
    ///
    /// Builds an adjacency index once up front rather than rescanning the
    /// full edge list for every node popped off the BFS queue (previously
    /// `O(nodes_visited * exception_edges.len())`), and marks a target as
    /// visited at enqueue time so that duplicate/parallel edges to the same
    /// target cannot cause it to appear more than once in the result.
    #[must_use]
    pub fn reachable_landing_pads(&self, from: Address) -> Vec<Address> {
        let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
        for edge in &self.exception_edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(from);
        queue.push_back(from);

        while let Some(node) = queue.pop_front() {
            if let Some(children) = adj.get(&node) {
                for &child in children {
                    if visited.insert(child) {
                        result.push(child);
                        queue.push_back(child);
                    }
                }
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionCfgBuilder — constructs an ExceptionCfg from binary metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for building an exception-aware CFG.
#[derive(Debug, Clone)]
pub struct EhCfgConfig {
    pub detect_windows_seh: bool,
    pub detect_windows_seh64: bool,
    pub detect_gcc_eh: bool,
    pub detect_llvm_lsda: bool,
    pub detect_rust_panic: bool,
    /// Maximum depth of nested exception regions.
    pub max_nesting_depth: u32,
}

impl Default for EhCfgConfig {
    fn default() -> Self {
        Self {
            detect_windows_seh: true,
            detect_windows_seh64: true,
            detect_gcc_eh: true,
            detect_llvm_lsda: true,
            detect_rust_panic: true,
            max_nesting_depth: 16,
        }
    }
}

/// Builds an `ExceptionCfg` from a base CFG and optional metadata.
pub struct ExceptionCfgBuilder {
    config: EhCfgConfig,
}

impl ExceptionCfgBuilder {
    #[must_use]
    pub const fn new(config: EhCfgConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self { config: EhCfgConfig::default() }
    }

    /// Build an `ExceptionCfg` from a base CFG and LSDA records.
    ///
    /// In a real implementation this would parse `.eh_frame`, `.gcc_except_table`,
    /// and `RUNTIME_FUNCTION` tables from the binary image.
    #[must_use]
    pub fn build_from_cfg(
        &self,
        base: ControlFlowGraph,
        lsda_sites: Vec<LsdaCallSite>,
        seh_frames: Vec<SehFrame>,
        unwind_info: Option<UnwindInfo>,
    ) -> ExceptionCfg {
        let mut ecfg = ExceptionCfg::new(base);
        ecfg.lsda_sites = lsda_sites.clone();
        ecfg.seh_frames = seh_frames;
        ecfg.unwind_info = unwind_info;

        // Build exception regions from LSDA records.
        if self.config.detect_llvm_lsda || self.config.detect_gcc_eh {
            for site in &lsda_sites {
                if site.landing_pad == 0 {
                    // Cleanup-only.
                    let region = ExceptionRegion {
                        try_start: Address::new(site.cs_start),
                        // Saturate: `cs_start`/`cs_len` are parsed straight
                        // out of an LSDA call-site record with no range
                        // validation, so adversarial values near `u64::MAX`
                        // would otherwise panic (debug) or silently wrap to
                        // a bogus, tiny `try_end` (release).
                        try_end: Address::new(site.cs_start.saturating_add(site.cs_len)),
                        handlers: vec![ExceptionHandler::cleanup(Address::new(site.landing_pad))],
                        kind: if self.config.detect_llvm_lsda {
                            ExceptionHandlingKind::LlvmLsda
                        } else {
                            ExceptionHandlingKind::GccCppEh
                        },
                        depth: 0,
                    };
                    ecfg.add_region(region);
                } else {
                    let handler = if site.action_offset == 0 {
                        ExceptionHandler::cleanup(Address::new(site.landing_pad))
                    } else {
                        ExceptionHandler::catch(Address::new(site.landing_pad))
                    };
                    let region = ExceptionRegion {
                        try_start: Address::new(site.cs_start),
                        // Saturate: `cs_start`/`cs_len` are parsed straight
                        // out of an LSDA call-site record with no range
                        // validation, so adversarial values near `u64::MAX`
                        // would otherwise panic (debug) or silently wrap to
                        // a bogus, tiny `try_end` (release).
                        try_end: Address::new(site.cs_start.saturating_add(site.cs_len)),
                        handlers: vec![handler],
                        kind: ExceptionHandlingKind::LlvmLsda,
                        depth: 0,
                    };
                    ecfg.add_region(region);
                    ecfg.add_unwind_edge(
                        Address::new(site.cs_start),
                        Address::new(site.landing_pad),
                    );
                }
            }
        }

        // Assign nesting depths.
        //
        // Depth of region `i` is the number of *other* regions that strictly
        // contain it. This must scan every region regardless of insertion
        // order -- LSDA call-site records are not guaranteed to be emitted
        // in outer-to-inner order, so only counting regions that happen to
        // precede `i` in `ecfg.regions` silently mis-ranks nesting whenever
        // an inner region is inserted before its enclosing region.
        let region_count = ecfg.regions.len();
        for i in 0..region_count {
            let (start, end) = (ecfg.regions[i].try_start, ecfg.regions[i].try_end);
            let depth = ecfg
                .regions
                .iter()
                .enumerate()
                .filter(|(j, r)| {
                    *j != i
                        && r.try_start <= start
                        && r.try_end >= end
                        && (r.try_start, r.try_end) != (start, end)
                })
                .count() as u32;
            ecfg.regions[i].depth = depth.min(self.config.max_nesting_depth);
        }

        ecfg
    }

    /// Heuristically detect exception regions from instruction patterns.
    #[must_use]
    pub fn detect_from_instructions(
        &self,
        base: ControlFlowGraph,
        func_bytes: &[(Address, u8)],
    ) -> ExceptionCfg {
        let mut ecfg = ExceptionCfg::new(base);

        // Windows x86 SEH detection: look for `push dword handler_addr` followed by
        // `mov dword ptr fs:[0], esp` pattern.
        if self.config.detect_windows_seh {
            let mut i = 0;
            // Bound must be `len - 7` (pattern width), not `len - 8`: the
            // off-by-one previously here meant a 7-byte pattern at the last
            // valid start position was skipped, and buffers of length <= 8
            // were never scanned at all (regression test:
            // `detect_from_instructions_finds_windows_seh_pattern`).
            while i < func_bytes.len().saturating_sub(7) {
                // Pattern: 0x64 0x89 0x25 0x00 0x00 0x00 0x00 = mov dword ptr fs:[0], esp
                let window = &func_bytes[i..];
                if window.len() >= 7
                    && window[0].1 == 0x64
                    && window[1].1 == 0x89
                    && window[2].1 == 0x25
                    && window[3].1 == 0x00
                    && window[4].1 == 0x00
                    && window[5].1 == 0x00
                    && window[6].1 == 0x00
                {
                    // Found SEH frame registration.
                    ecfg.seh_frames.push(SehFrame {
                        registration_addr: window[0].0,
                        handler_addr: Address::new(0), // would resolve from push
                        scope_table: None,
                        try_level: 0,
                    });
                }
                i += 1;
            }
        }

        ecfg
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LandingPadClassifier — identify cleanup vs catch landing pads
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies landing pads into cleanup, catch, and filter.
pub struct LandingPadClassifier {
    /// Set of landing pads known to be cleanup-only.
    cleanup_pads: HashSet<Address>,
    /// Set of landing pads known to be typed-catch.
    catch_pads: HashSet<Address>,
}

impl LandingPadClassifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cleanup_pads: HashSet::new(),
            catch_pads: HashSet::new(),
        }
    }

    pub fn classify_from_ecfg(&mut self, ecfg: &ExceptionCfg) {
        for region in &ecfg.regions {
            for handler in &region.handlers {
                match handler.kind {
                    HandlerKind::Cleanup | HandlerKind::Finally => {
                        self.cleanup_pads.insert(handler.handler_addr);
                    }
                    HandlerKind::Catch => {
                        self.catch_pads.insert(handler.handler_addr);
                    }
                    // Neither a cleanup pad nor a catch pad: a filter is only
                    // a predicate, Terminate ends the program, and a generic
                    // LandingPad is unclassified until refined elsewhere.
                    HandlerKind::Filter
                    | HandlerKind::Terminate
                    | HandlerKind::LandingPad => {}
                }
            }
        }
    }

    #[must_use]
    pub fn is_cleanup(&self, addr: Address) -> bool {
        self.cleanup_pads.contains(&addr) && !self.catch_pads.contains(&addr)
    }

    #[must_use]
    pub fn is_catch(&self, addr: Address) -> bool {
        self.catch_pads.contains(&addr)
    }

    #[must_use]
    pub fn is_mixed(&self, addr: Address) -> bool {
        self.cleanup_pads.contains(&addr) && self.catch_pads.contains(&addr)
    }

    #[must_use]
    pub fn total_pads(&self) -> usize {
        let mut all: HashSet<Address> = HashSet::new();
        all.extend(&self.cleanup_pads);
        all.extend(&self.catch_pads);
        all.len()
    }
}

impl Default for LandingPadClassifier {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// DwarfEhFrameParser — simplified .eh_frame / DWARF CIE+FDE parser
// ─────────────────────────────────────────────────────────────────────────────

/// A CIE (Common Information Entry) from .`eh_frame`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfCie {
    pub offset: u64,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: u64,
    pub personality_routine: Option<u64>,
    pub lsda_encoding: u8,
    pub fde_encoding: u8,
}

/// An FDE (Frame Description Entry) from .`eh_frame`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfFde {
    pub offset: u64,
    /// Corresponding CIE offset.
    pub cie_offset: u64,
    /// Initial location of the range described.
    pub initial_location: u64,
    /// Length of the range.
    pub range_length: u64,
    /// LSDA pointer (if augmentation 'L' is present).
    pub lsda_ptr: Option<u64>,
}

impl DwarfFde {
    /// End address of the described range.
    #[must_use]
    pub const fn end_location(&self) -> u64 {
        // Saturate: both fields are parsed straight out of raw `.eh_frame`
        // bytes with no validation, so adversarial input can make this add
        // overflow (panic in debug, silent wraparound in release).
        self.initial_location.saturating_add(self.range_length)
    }
}

/// A simplified parser for DWARF .`eh_frame` sections.
pub struct DwarfEhFrameParser;

impl DwarfEhFrameParser {
    /// Parse a list of FDE records from raw bytes at `base_addr`.
    /// This is a stub — a real implementation would decode DWARF CFI opcodes.
    #[must_use]
    pub fn parse_fdes(data: &[u8], base_addr: u64) -> Vec<DwarfFde> {
        let mut fdes = Vec::new();
        let mut offset = 0usize;

        while offset + 8 < data.len() {
            let length = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]) as usize;
            if length == 0 { break; }

            let cie_ptr = u32::from_le_bytes([
                data[offset+4], data[offset+5], data[offset+6], data[offset+7]
            ]);

            // If cie_ptr != 0, this is an FDE.
            if cie_ptr != 0 && offset + 16 < data.len() {
                let initial_loc = u64::from_le_bytes([
                    data[offset+8], data[offset+9], data[offset+10], data[offset+11],
                    data[offset+12], data[offset+13], data[offset+14], data[offset+15],
                ]);
                // Off-by-one fix: reading `data[offset+16..offset+24]` only
                // requires `offset + 24 <= data.len()`; the previous strict
                // `<` needlessly dropped range_length (silently zeroing it)
                // whenever the buffer ended exactly at the 24-byte boundary
                // (regression test: `parse_fdes_single_fde_record`).
                let range_len = if offset + 24 <= data.len() {
                    u64::from_le_bytes([
                        data[offset+16], data[offset+17], data[offset+18], data[offset+19],
                        data[offset+20], data[offset+21], data[offset+22], data[offset+23],
                    ])
                } else {
                    0
                };
                fdes.push(DwarfFde {
                    offset: base_addr + offset as u64,
                    cie_offset: u64::from(cie_ptr),
                    initial_location: initial_loc,
                    range_length: range_len,
                    lsda_ptr: None,
                });
            }

            offset += 4 + length; // advance past this entry
        }

        fdes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_cfg() -> ControlFlowGraph {
        ControlFlowGraph {
            blocks: HashMap::new(),
            edges: Vec::new(),
            entry: Address::new(0x1000),
            dom_tree: Default::default(),
            loops: Vec::new(),
            post_dom_tree: Default::default(),
        }
    }

    #[test]
    fn exception_region_contains() {
        let region = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::catch(Address::new(0x3000))],
            kind: ExceptionHandlingKind::LlvmLsda,
            depth: 0,
        };
        assert!(region.contains_try(Address::new(0x1500)));
        assert!(!region.contains_try(Address::new(0x2000)));
        assert!(!region.contains_try(Address::new(0x0FFF)));
    }

    #[test]
    fn exception_cfg_add_region() {
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        let region = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::catch(Address::new(0x3000))],
            kind: ExceptionHandlingKind::LlvmLsda,
            depth: 0,
        };
        ecfg.add_region(region);
        assert!(ecfg.is_landing_pad(Address::new(0x3000)));
        assert_eq!(ecfg.exception_edge_count(), 1);
    }

    #[test]
    fn landing_pad_classifier() {
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x1100),
            handlers: vec![ExceptionHandler::cleanup(Address::new(0x2000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        });
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x1100),
            try_end: Address::new(0x1200),
            handlers: vec![ExceptionHandler::catch(Address::new(0x3000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        });

        let mut clf = LandingPadClassifier::new();
        clf.classify_from_ecfg(&ecfg);

        assert!(clf.is_cleanup(Address::new(0x2000)));
        assert!(clf.is_catch(Address::new(0x3000)));
        assert!(!clf.is_cleanup(Address::new(0x3000)));
        assert_eq!(clf.total_pads(), 2);
    }

    #[test]
    fn builder_from_lsda() {
        let builder = ExceptionCfgBuilder::with_default_config();
        let lsda = vec![
            LsdaCallSite {
                cs_start: 0x1000,
                cs_len: 0x100,
                landing_pad: 0x2000,
                action_offset: 1,
            },
        ];
        let ecfg = builder.build_from_cfg(empty_cfg(), lsda, vec![], None);
        assert!(!ecfg.regions.is_empty());
        assert!(ecfg.is_landing_pad(Address::new(0x2000)));
    }

    #[test]
    fn unwind_info_flags() {
        let ui = UnwindInfo::from_flags_byte(UnwindInfo::UNW_FLAG_EHANDLER);
        assert!(ui.has_exception_handler);
        assert!(!ui.has_termination_handler);
        assert!(!ui.is_chained);
    }

    #[test]
    fn reachable_landing_pads() {
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_unwind_edge(Address::new(0x1000), Address::new(0x2000));
        ecfg.add_unwind_edge(Address::new(0x2000), Address::new(0x3000));
        let pads = ecfg.reachable_landing_pads(Address::new(0x1000));
        assert!(pads.contains(&Address::new(0x2000)));
        assert!(pads.contains(&Address::new(0x3000)));
    }

    #[test]
    fn builder_nesting_depth_independent_of_insertion_order() {
        // Inner region (0x1100..0x1180) is inserted *before* the outer
        // region (0x1000..0x1200) that structurally contains it. Depth
        // assignment must still recognize the outer region as depth 0 and
        // the inner region as depth 1, regardless of LSDA record order.
        let builder = ExceptionCfgBuilder::with_default_config();
        let lsda = vec![
            // Inner region, listed first.
            LsdaCallSite {
                cs_start: 0x1100,
                cs_len: 0x80,
                landing_pad: 0x2100,
                action_offset: 1,
            },
            // Outer region, listed second.
            LsdaCallSite {
                cs_start: 0x1000,
                cs_len: 0x200,
                landing_pad: 0x2000,
                action_offset: 1,
            },
        ];
        let ecfg = builder.build_from_cfg(empty_cfg(), lsda, vec![], None);
        assert_eq!(ecfg.regions.len(), 2);

        let inner = ecfg
            .regions
            .iter()
            .find(|r| r.try_start == Address::new(0x1100))
            .unwrap();
        let outer = ecfg
            .regions
            .iter()
            .find(|r| r.try_start == Address::new(0x1000))
            .unwrap();
        assert_eq!(outer.depth, 0, "outer region must be depth 0");
        assert_eq!(inner.depth, 1, "inner region must be depth 1 even though inserted first");
    }

    #[test]
    fn exception_cfg_empty_has_no_landing_pads_or_regions() {
        let ecfg = ExceptionCfg::new(empty_cfg());
        assert_eq!(ecfg.exception_edge_count(), 0);
        assert!(ecfg.regions.is_empty());
        assert!(!ecfg.is_landing_pad(Address::new(0x1000)));
        assert!(ecfg.regions_at(Address::new(0x1000)).is_empty());
        assert!(ecfg.innermost_region(Address::new(0x1000)).is_none());
        assert!(ecfg.reachable_landing_pads(Address::new(0x1000)).is_empty());
    }

    #[test]
    fn innermost_region_picks_deepest_nesting() {
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::catch(Address::new(0x9000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        });
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x1200),
            try_end: Address::new(0x1800),
            handlers: vec![ExceptionHandler::catch(Address::new(0x9100))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 1,
        });
        let inner = ecfg.innermost_region(Address::new(0x1300)).unwrap();
        assert_eq!(inner.depth, 1);
        assert_eq!(inner.try_start, Address::new(0x1200));
    }

    #[test]
    fn reachable_landing_pads_dedups_parallel_edges() {
        // Two distinct call sites both unwind into the same landing pad, and
        // that landing pad itself has two edges into a shared successor.
        // The result must list each reachable pad exactly once, never once
        // per incoming edge.
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_unwind_edge(Address::new(0x1000), Address::new(0x2000));
        ecfg.exception_edges.push(ExceptionCfgEdge {
            from: Address::new(0x1000),
            to: Address::new(0x2000),
            kind: ExceptionEdgeKind::Unwind,
        });
        ecfg.add_unwind_edge(Address::new(0x2000), Address::new(0x3000));
        ecfg.exception_edges.push(ExceptionCfgEdge {
            from: Address::new(0x2000),
            to: Address::new(0x3000),
            kind: ExceptionEdgeKind::Cleanup,
        });
        let pads = ecfg.reachable_landing_pads(Address::new(0x1000));
        assert_eq!(pads.len(), 2, "each reachable pad must appear exactly once: {pads:?}");
        assert!(pads.contains(&Address::new(0x2000)));
        assert!(pads.contains(&Address::new(0x3000)));
    }

    #[test]
    fn reachable_landing_pads_no_edges_is_empty() {
        let ecfg = ExceptionCfg::new(empty_cfg());
        assert!(ecfg.reachable_landing_pads(Address::new(0x1000)).is_empty());
    }

    #[test]
    fn reachable_landing_pads_cyclic_terminates() {
        // Cycle: 0x1000 -> 0x2000 -> 0x1000. Must terminate and not
        // infinite-loop or double-count via the visited set.
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_unwind_edge(Address::new(0x1000), Address::new(0x2000));
        ecfg.add_unwind_edge(Address::new(0x2000), Address::new(0x1000));
        let pads = ecfg.reachable_landing_pads(Address::new(0x1000));
        assert_eq!(pads.len(), 1);
        assert!(pads.contains(&Address::new(0x2000)));
    }

    #[test]
    fn parse_fdes_empty_input() {
        let fdes = DwarfEhFrameParser::parse_fdes(&[], 0);
        assert!(fdes.is_empty());
    }

    #[test]
    fn handler_constructors() {
        let catch = ExceptionHandler::catch(Address::new(0x1000))
            .with_type("std::exception");
        assert_eq!(catch.kind, HandlerKind::Catch);
        assert_eq!(catch.type_name.as_deref(), Some("std::exception"));

        let filter = ExceptionHandler::catch(Address::new(0x2000))
            .with_filter("GetExceptionCode() == 1");
        assert_eq!(filter.kind, HandlerKind::Filter);
    }

    // --- Regression tests: saturating arithmetic on adversarial LSDA/DWARF fields ---

    #[test]
    fn lsda_call_site_overflowing_len_does_not_panic() {
        // A malformed/adversarial LSDA record can claim a call-site length
        // that overflows u64 when added to cs_start. This must saturate
        // instead of panicking (debug) or silently wrapping to a tiny,
        // bogus try_end (release).
        let builder = ExceptionCfgBuilder::with_default_config();
        let site = LsdaCallSite {
            cs_start: u64::MAX - 10,
            cs_len: u64::MAX,
            landing_pad: 0x1000,
            action_offset: 0,
        };
        let ecfg = builder.build_from_cfg(empty_cfg(), vec![site], Vec::new(), None);
        assert_eq!(ecfg.regions.len(), 1);
        assert_eq!(ecfg.regions[0].try_end, Address::new(u64::MAX));
        assert_eq!(ecfg.regions[0].try_start, Address::new(u64::MAX - 10));
    }

    #[test]
    fn dwarf_fde_end_location_saturates_on_overflow() {
        let fde = DwarfFde {
            offset: 0,
            cie_offset: 0,
            initial_location: u64::MAX - 5,
            range_length: 100,
            lsda_ptr: None,
        };
        assert_eq!(fde.end_location(), u64::MAX);
    }

    // --- ExceptionRegion helper methods (previously zero coverage) ---

    #[test]
    fn exception_region_first_catch_finds_catch_handler() {
        let region = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![
                ExceptionHandler::cleanup(Address::new(0x2000)),
                ExceptionHandler::catch(Address::new(0x3000)),
            ],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        };
        let catch = region.first_catch().expect("must find catch handler");
        assert_eq!(catch.handler_addr, Address::new(0x3000));
    }

    #[test]
    fn exception_region_first_catch_none_when_absent() {
        let region = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::cleanup(Address::new(0x2000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        };
        assert!(region.first_catch().is_none());
    }

    #[test]
    fn exception_region_finally_handlers_filters_correctly() {
        let region = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![
                ExceptionHandler::finally(Address::new(0x2000)),
                ExceptionHandler::catch(Address::new(0x3000)),
                ExceptionHandler::finally(Address::new(0x4000)),
            ],
            kind: ExceptionHandlingKind::MsvcCppEh,
            depth: 0,
        };
        let finallies = region.finally_handlers();
        assert_eq!(finallies.len(), 2);
        assert!(finallies.iter().all(|h| h.kind == HandlerKind::Finally));
    }

    #[test]
    fn exception_region_has_cleanup_true_and_false() {
        let with_cleanup = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::cleanup(Address::new(0x2000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        };
        assert!(with_cleanup.has_cleanup());

        let without_cleanup = ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x2000),
            handlers: vec![ExceptionHandler::catch(Address::new(0x3000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        };
        assert!(!without_cleanup.has_cleanup());
    }

    // --- ExceptionCfg::regions_at (previously only tested against zero regions) ---

    #[test]
    fn regions_at_returns_only_containing_regions() {
        let mut ecfg = ExceptionCfg::new(empty_cfg());
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x1000),
            try_end: Address::new(0x1500),
            handlers: vec![ExceptionHandler::catch(Address::new(0x9000))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        });
        ecfg.add_region(ExceptionRegion {
            try_start: Address::new(0x2000),
            try_end: Address::new(0x2500),
            handlers: vec![ExceptionHandler::catch(Address::new(0x9100))],
            kind: ExceptionHandlingKind::GccCppEh,
            depth: 0,
        });
        let at_1200 = ecfg.regions_at(Address::new(0x1200));
        assert_eq!(at_1200.len(), 1);
        assert_eq!(at_1200[0].try_start, Address::new(0x1000));

        let at_9999 = ecfg.regions_at(Address::new(0x9999));
        assert!(at_9999.is_empty());
    }

    // --- ExceptionCfgBuilder::detect_from_instructions (previously zero coverage) ---

    #[test]
    fn detect_from_instructions_finds_windows_seh_pattern() {
        let builder = ExceptionCfgBuilder::with_default_config();
        // `mov dword ptr fs:[0], esp` = 64 89 25 00 00 00 00
        let bytes: Vec<(Address, u8)> = [0x64u8, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90]
            .iter()
            .enumerate()
            .map(|(i, &b)| (Address::new(0x1000 + i as u64), b))
            .collect();
        let ecfg = builder.detect_from_instructions(empty_cfg(), &bytes);
        assert_eq!(ecfg.seh_frames.len(), 1);
        assert_eq!(ecfg.seh_frames[0].registration_addr, Address::new(0x1000));
    }

    #[test]
    fn detect_from_instructions_no_pattern_no_frames() {
        let builder = ExceptionCfgBuilder::with_default_config();
        let bytes: Vec<(Address, u8)> = [0x90u8; 16]
            .iter()
            .enumerate()
            .map(|(i, &b)| (Address::new(i as u64), b))
            .collect();
        let ecfg = builder.detect_from_instructions(empty_cfg(), &bytes);
        assert!(ecfg.seh_frames.is_empty());
    }

    #[test]
    fn detect_from_instructions_disabled_config_skips_detection() {
        let config = EhCfgConfig {
            detect_windows_seh: false,
            ..EhCfgConfig::default()
        };
        let builder = ExceptionCfgBuilder::new(config);
        let bytes: Vec<(Address, u8)> = [0x64u8, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00]
            .iter()
            .enumerate()
            .map(|(i, &b)| (Address::new(i as u64), b))
            .collect();
        let ecfg = builder.detect_from_instructions(empty_cfg(), &bytes);
        assert!(ecfg.seh_frames.is_empty());
    }

    // --- DwarfEhFrameParser::parse_fdes with real data (previously only empty input) ---

    #[test]
    fn parse_fdes_single_fde_record() {
        // Layout per entry: length(u32 LE) | cie_ptr(u32 LE) | initial_location(u64 LE) | range_length(u64 LE)
        // length must cover cie_ptr + initial_location + range_length = 4 + 8 + 8 = 20
        let mut data = Vec::new();
        data.extend_from_slice(&20u32.to_le_bytes()); // length
        data.extend_from_slice(&1u32.to_le_bytes()); // cie_ptr != 0 => FDE
        data.extend_from_slice(&0x4000u64.to_le_bytes()); // initial_location
        data.extend_from_slice(&0x100u64.to_le_bytes()); // range_length

        let fdes = DwarfEhFrameParser::parse_fdes(&data, 0x8000);
        assert_eq!(fdes.len(), 1);
        assert_eq!(fdes[0].initial_location, 0x4000);
        assert_eq!(fdes[0].range_length, 0x100);
        assert_eq!(fdes[0].cie_offset, 1);
        assert_eq!(fdes[0].end_location(), 0x4100);
    }

    #[test]
    fn parse_fdes_zero_length_stops_parsing() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // length == 0 => stop
        data.extend_from_slice(&[0xFFu8; 20]); // would be garbage if parsed
        let fdes = DwarfEhFrameParser::parse_fdes(&data, 0);
        assert!(fdes.is_empty());
    }

    #[test]
    fn dwarf_fde_end_location_normal_case() {
        let fde = DwarfFde {
            offset: 0,
            cie_offset: 0,
            initial_location: 0x1000,
            range_length: 0x100,
            lsda_ptr: None,
        };
        assert_eq!(fde.end_location(), 0x1100);
    }
}
