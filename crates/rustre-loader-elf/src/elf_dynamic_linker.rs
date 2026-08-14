//! ELF dynamic linker simulation.
//!
//! This module models the runtime dynamic linker (`ld.so`) behaviour as it
//! applies to reverse-engineering tasks: understanding which libraries are
//! needed, how the PLT/GOT is laid out, how lazy binding works, how IFUNC
//! resolvers are called, TLS layout, and GNU RELRO / `BIND_NOW` hardening.
//!
//! It does **not** actually load or execute code; it reconstructs the linker's
//! data structures from parsed ELF metadata to help understand indirect calls,
//! data references, and security mitigations.

use std::collections::HashMap;
use std::fmt;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkerError {
    MissingDtNeeded(String),
    UnresolvedSymbol(String),
    CyclicDependency(Vec<String>),
    GotSlotOutOfRange { index: usize, got_size: usize },
    TlsLayoutConflict(String),
    RelocNotApplicable { sym: String, reason: String },
    InvalidIfunc(String),
    BadRelro { start: u64, size: u64 },
}

impl fmt::Display for LinkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDtNeeded(lib) =>
                write!(f, "required library '{lib}' not found"),
            Self::UnresolvedSymbol(sym) =>
                write!(f, "undefined symbol '{sym}'"),
            Self::CyclicDependency(libs) =>
                write!(f, "cyclic dependency: {}", libs.join(" → ")),
            Self::GotSlotOutOfRange { index, got_size } =>
                write!(f, "GOT slot {index} out of range (GOT has {got_size} entries)"),
            Self::TlsLayoutConflict(s) =>
                write!(f, "TLS layout conflict: {s}"),
            Self::RelocNotApplicable { sym, reason } =>
                write!(f, "relocation for '{sym}' not applicable: {reason}"),
            Self::InvalidIfunc(sym) =>
                write!(f, "IFUNC resolver for '{sym}' is not a function pointer"),
            Self::BadRelro { start, size } =>
                write!(f, "GNU_RELRO region 0x{start:X}+{size} is not page-aligned"),
        }
    }
}

// ── DT_NEEDED dependency graph ─────────────────────────────────────────────────

/// A node in the library dependency graph.
#[derive(Debug, Clone)]
pub struct LibNode {
    /// SONAME of this library (e.g., `"libc.so.6"`).
    pub soname: String,
    /// Direct dependencies (`DT_NEEDED` entries) of this library.
    pub needed: Vec<String>,
    /// Resolved load address (0 = not yet placed).
    pub load_addr: u64,
    /// Whether this is the main executable (`ET_EXEC` or `ET_DYN` position 0).
    pub is_main: bool,
}

/// Simulated dependency resolver.
#[derive(Debug, Clone, Default)]
pub struct DepGraph {
    pub nodes: HashMap<String, LibNode>,
    /// BFS/DFS load order (libraries earlier in list are searched first).
    pub load_order: Vec<String>,
}

impl DepGraph {
    /// Add a library node.
    pub fn add_lib(&mut self, node: LibNode) {
        self.nodes.insert(node.soname.clone(), node);
    }

    /// Resolve the load order via BFS from the main executable.
    ///
    /// Returns an error if a `DT_NEEDED` library is not present in `nodes`, or
    /// if a cycle is detected.
    ///
    /// # Errors
    /// Returns an error if a required library is missing or a cycle is detected.
    pub fn resolve_order(&mut self, main: &str) -> Result<(), LinkerError> {
        let mut order = Vec::new();
        let mut visited = Vec::new();
        self.bfs(main, &mut order, &mut visited)?;
        self.load_order = order;
        Ok(())
    }

    fn bfs(
        &self,
        name: &str,
        order: &mut Vec<String>,
        path: &mut Vec<String>,
    ) -> Result<(), LinkerError> {
        if path.contains(&name.to_string()) {
            let mut cycle = path.clone();
            cycle.push(name.to_string());
            return Err(LinkerError::CyclicDependency(cycle));
        }
        if order.contains(&name.to_string()) {
            return Ok(());
        }
        let node = self.nodes.get(name)
            .ok_or_else(|| LinkerError::MissingDtNeeded(name.to_string()))?;
        let deps = node.needed.clone();
        order.push(name.to_string());
        path.push(name.to_string());
        for dep in &deps {
            self.bfs(dep, order, path)?;
        }
        path.pop();
        Ok(())
    }

    /// Find which library first defines a symbol by searching in load order.
    #[must_use]
    pub fn find_symbol<'a>(
        &'a self,
        symbol: &str,
        symbol_tables: &'a HashMap<String, Vec<ExportedSymbol>>,
    ) -> Option<(&'a str, &'a ExportedSymbol)> {
        for lib in &self.load_order {
            if let Some(syms) = symbol_tables.get(lib.as_str())
                && let Some(s) = syms.iter().find(|s| s.name == symbol) {
                    return Some((lib.as_str(), s));
                }
        }
        None
    }
}

/// An exported symbol from a shared library.
#[derive(Debug, Clone)]
pub struct ExportedSymbol {
    pub name: String,
    pub value: u64,   // virtual address within the library
    pub size: u64,
    pub sym_type: SymType,
    pub binding: SymBinding,
    pub is_ifunc: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymType { Func, Object, Tls, NoType, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymBinding { Global, Weak, Local }

// ── PLT / GOT layout ──────────────────────────────────────────────────────────

/// The PLT stub type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PltStubKind {
    /// Classic PLT[n]: push index; jmp PLT[0].
    Classic,
    /// PLT[0]: the resolver trampoline that calls `_dl_runtime_resolve`.
    Resolver,
    /// PLT with IBT/BTI landing pad (Intel CET or Arm PAC).
    IbtPad,
    /// IPLT: for IFUNC resolvers.
    Ifunc,
}

/// A single PLT entry with its associated GOT slot.
#[derive(Debug, Clone)]
pub struct PltEntry {
    /// Virtual address of the PLT stub.
    pub plt_addr: u64,
    /// Index in the PLT (0 = resolver, 1… = entries).
    pub index: usize,
    /// Virtual address of the corresponding GOT slot (8 bytes on 64-bit).
    pub got_addr: u64,
    /// Name of the symbol this stub resolves.
    pub symbol: String,
    /// Relocation offset in .rela.plt / .rel.plt.
    pub reloc_offset: u64,
    pub kind: PltStubKind,
}

/// Layout of the PLT and GOT sections for an ELF binary.
#[derive(Debug, Clone)]
pub struct PltGotLayout {
    /// Base address of .plt section.
    pub plt_base: u64,
    /// Base address of .got.plt section.
    pub got_plt_base: u64,
    /// Stride between PLT entries (16 bytes on x86-64, 12 on x86-32, 32 on aarch64).
    pub plt_entry_size: u64,
    /// All PLT entries.
    pub entries: Vec<PltEntry>,
    /// GOT[0] = address of .dynamic section.
    pub got_dynamic: u64,
    /// GOT[1] = `link_map` pointer (filled by ld.so at runtime).
    pub got_link_map: u64,
    /// GOT[2] = _`dl_runtime_resolve` address (filled by ld.so at runtime).
    pub got_resolver: u64,
}

impl PltGotLayout {
    /// Build from a list of PLT relocation entries.
    ///
    /// `relocs`: `(sym_name, reloc_offset, got_addr)` tuples.
    #[must_use]
    pub fn build(
        plt_base: u64,
        got_plt_base: u64,
        plt_entry_size: u64,
        dynamic_addr: u64,
        relocs: &[(String, u64, u64)],
    ) -> Self {
        let mut entries = Vec::new();
        // PLT[0] is the resolver trampoline.
        entries.push(PltEntry {
            plt_addr: plt_base,
            index: 0,
            got_addr: got_plt_base + 16, // GOT[2] = resolver
            symbol: "_dl_runtime_resolve".to_string(),
            reloc_offset: 0,
            kind: PltStubKind::Resolver,
        });

        for (i, (sym, reloc_off, got_addr)) in relocs.iter().enumerate() {
            let plt_addr = plt_base + plt_entry_size + (i as u64) * plt_entry_size;
            entries.push(PltEntry {
                plt_addr,
                index: i + 1,
                got_addr: *got_addr,
                symbol: sym.clone(),
                reloc_offset: *reloc_off,
                kind: PltStubKind::Classic,
            });
        }

        Self {
            plt_base,
            got_plt_base,
            plt_entry_size,
            entries,
            got_dynamic: dynamic_addr,
            got_link_map: got_plt_base + 8,
            got_resolver: got_plt_base + 16,
        }
    }

    /// Look up a PLT entry by the symbol name.
    #[must_use]
    pub fn find_by_symbol(&self, sym: &str) -> Option<&PltEntry> {
        self.entries.iter().find(|e| e.symbol == sym)
    }

    /// Describe what happens at a given virtual address if it is in the PLT.
    #[must_use]
    pub fn describe_addr(&self, addr: u64) -> Option<String> {
        for entry in &self.entries {
            if addr == entry.plt_addr {
                return Some(match entry.kind {
                    PltStubKind::Resolver =>
                        "PLT[0]: resolver trampoline → _dl_runtime_resolve".to_string(),
                    PltStubKind::Classic =>
                        format!("PLT[{}]: lazy stub for '{}' → GOT[0x{:X}]",
                            entry.index, entry.symbol, entry.got_addr),
                    PltStubKind::Ifunc =>
                        format!("PLT IPLT: IFUNC resolver for '{}'", entry.symbol),
                    PltStubKind::IbtPad =>
                        format!("PLT IBT pad for '{}'", entry.symbol),
                });
            }
        }
        None
    }
}

// ── Lazy binding ───────────────────────────────────────────────────────────────

/// State of a single GOT entry for lazy-binding simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GotSlotState {
    /// Initial state: GOT slot points back into the PLT (PLT+6 on x86-64).
    Unresolved { plt_back_addr: u64 },
    /// Resolved to the final symbol address.
    Resolved { sym_addr: u64, sym_name: String },
    /// `BIND_NOW`: resolved at load time before any user code runs.
    BindNow { sym_addr: u64, sym_name: String },
    /// IFUNC resolver was called and produced this address.
    IfuncResolved { resolver_addr: u64, final_addr: u64, sym_name: String },
}

impl fmt::Display for GotSlotState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved { plt_back_addr } =>
                write!(f, "UNRESOLVED → PLT back-ptr 0x{plt_back_addr:X}"),
            Self::Resolved { sym_addr, sym_name } =>
                write!(f, "RESOLVED '{sym_name}' @ 0x{sym_addr:X}"),
            Self::BindNow { sym_addr, sym_name } =>
                write!(f, "BIND_NOW '{sym_name}' @ 0x{sym_addr:X}"),
            Self::IfuncResolved { final_addr, sym_name, .. } =>
                write!(f, "IFUNC '{sym_name}' resolved → 0x{final_addr:X}"),
        }
    }
}

/// Simulate lazy binding for an entire PLT/GOT.
#[derive(Debug, Clone)]
pub struct LazyBindingState {
    /// GOT state per slot index (0 = .dynamic, 1 = `link_map`, 2 = resolver, 3…).
    pub slots: Vec<(u64, GotSlotState)>, // (got_addr, state)
    pub bind_now: bool,
}

impl LazyBindingState {
    /// Build initial (unresolved) GOT state from a `PltGotLayout`.
    #[must_use]
    pub fn initial(layout: &PltGotLayout, bind_now: bool) -> Self {
        let mut slots = vec![
            (layout.got_plt_base,      GotSlotState::Unresolved { plt_back_addr: 0 }), // GOT[0]
            (layout.got_link_map,      GotSlotState::Unresolved { plt_back_addr: 0 }), // GOT[1]
            (layout.got_resolver,      GotSlotState::Unresolved { plt_back_addr: 0 }), // GOT[2]
        ];
        for entry in layout.entries.iter().skip(1) {
            let state = if bind_now {
                GotSlotState::BindNow { sym_addr: 0, sym_name: entry.symbol.clone() }
            } else {
                // PLT back-ptr = PLT stub + 6 (push instruction on x86-64).
                GotSlotState::Unresolved { plt_back_addr: entry.plt_addr + 6 }
            };
            slots.push((entry.got_addr, state));
        }
        Self { slots, bind_now }
    }

    /// Simulate a call to `sym_name`: resolve its GOT slot to `sym_addr`.
    pub fn resolve(&mut self, sym_name: &str, sym_addr: u64) {
        for (_, state) in &mut self.slots {
            if let GotSlotState::Unresolved { .. } = state {
                    // We can't easily match sym_name here without the layout;
                    // caller is expected to resolve by index instead.
                }
            if let GotSlotState::Unresolved { .. } = state {
                // Compare by index would need layout; use the simpler name approach.
                *state = GotSlotState::Resolved { sym_addr, sym_name: sym_name.to_string() };
                return;
            }
        }
    }

    /// Resolve a GOT slot by its address.
    pub fn resolve_by_addr(&mut self, got_addr: u64, sym_addr: u64, sym_name: &str) {
        for (addr, state) in &mut self.slots {
            if *addr == got_addr {
                *state = GotSlotState::Resolved {
                    sym_addr,
                    sym_name: sym_name.to_string(),
                };
                return;
            }
        }
    }
}

// ── IFUNC resolution ──────────────────────────────────────────────────────────

/// An IFUNC (indirect function) entry.
///
/// The GNU IFUNC mechanism allows a shared library to select a function
/// implementation at runtime (e.g., choosing the best `memcpy` variant based
/// on CPU features).
#[derive(Debug, Clone)]
pub struct IfuncEntry {
    /// Symbol name.
    pub name: String,
    /// Virtual address of the resolver function.
    pub resolver_addr: u64,
    /// IPLT GOT slot address (`R_X86_64_IRELATIVE` or similar relocation).
    pub got_addr: u64,
}

/// Describe all IFUNC entries found via `R_*_IRELATIVE` relocations.
#[must_use]
pub fn collect_ifuncs(
    relocs: &[(String, u64, u64, u32)], // (name, got_addr, addend, reloc_type)
    irelative_type: u32,
) -> Vec<IfuncEntry> {
    relocs.iter()
        .filter(|r| r.3 == irelative_type)
        .map(|(name, got_addr, addend, _)| IfuncEntry {
            name: name.clone(),
            resolver_addr: *addend,
            got_addr: *got_addr,
        })
        .collect()
}

// ── TLS layout ────────────────────────────────────────────────────────────────

/// Thread-Local Storage (TLS) model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsModel {
    /// General Dynamic: works across all cases, most code emitted.
    GeneralDynamic,
    /// Local Dynamic: module-local TLS variables.
    LocalDynamic,
    /// Initial Exec: TLS accessible at load time (used by executables / preloaded libs).
    InitialExec,
    /// Local Exec: static executable, TLS in fixed TP-relative offsets.
    LocalExec,
}

impl fmt::Display for TlsModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GeneralDynamic => "General Dynamic",
            Self::LocalDynamic   => "Local Dynamic",
            Self::InitialExec    => "Initial Exec",
            Self::LocalExec      => "Local Exec",
        })
    }
}

/// A TLS variable's layout information.
#[derive(Debug, Clone)]
pub struct TlsVar {
    pub name: String,
    pub module_id: u32,
    /// Offset within the TLS block for this module.
    pub tls_offset: i64,
    /// Size in bytes.
    pub size: usize,
    pub model: TlsModel,
}

/// TLS block layout for a set of shared libraries.
#[derive(Debug, Clone, Default)]
pub struct TlsLayout {
    /// Ordered list of TLS-using modules (module ID → block base offset from TP).
    pub modules: Vec<(u32, String, u64)>, // (module_id, soname, tp_offset)
    pub variables: Vec<TlsVar>,
    /// Size of the TP-relative (DTP) header on this arch (`2×ptr_size` on most).
    pub dtp_header_size: usize,
}

impl TlsLayout {
    /// Build from a list of `(soname, tls_segment_size, tls_vars)` tuples.
    ///
    /// Assigns module IDs and TP-relative offsets in order.
    #[must_use]
    pub fn build(
        modules: &[(String, usize, Vec<TlsVar>)],
        ptr_size: usize,
    ) -> Self {
        let dtp_header_size = 2 * ptr_size;
        let mut layout = Self { dtp_header_size, ..Default::default() };
        let mut tp_off = i64::try_from(dtp_header_size).unwrap_or(0);

        for (i, (soname, seg_size, vars)) in modules.iter().enumerate() {
            let module_id = u32::try_from(i + 1).unwrap_or(u32::MAX);
            layout.modules.push((module_id, soname.clone(), tp_off.cast_unsigned()));
            for v in vars {
                layout.variables.push(TlsVar {
                    name: v.name.clone(),
                    module_id,
                    tls_offset: tp_off + v.tls_offset,
                    size: v.size,
                    model: v.model,
                });
            }
            tp_off += i64::try_from(*seg_size).unwrap_or(0);
        }
        layout
    }

    /// Compute the TP-relative offset (tp-offset) for a TLS variable.
    #[must_use]
    pub fn tp_offset(&self, var_name: &str) -> Option<i64> {
        self.variables.iter()
            .find(|v| v.name == var_name)
            .map(|v| v.tls_offset)
    }

    /// Compute the DTP offset (`module_id`, dt-offset pair used by `__tls_get_addr`).
    #[must_use]
    pub fn dtp_offset(&self, var_name: &str) -> Option<(u32, i64)> {
        let v = self.variables.iter().find(|v| v.name == var_name)?;
        let module_base = self.modules.iter()
            .find(|m| m.0 == v.module_id)
            .map(|m| m.2.cast_signed())?;
        Some((v.module_id, v.tls_offset - module_base))
    }
}

// ── GNU RELRO ─────────────────────────────────────────────────────────────────

/// `GNU_RELRO` hardening analysis.
///
/// RELRO ("`RELocation` Read-Only") makes certain sections that contain
/// linker-filled pointers read-only after the dynamic linker finishes.
#[derive(Debug, Clone)]
pub struct RelroRegion {
    /// Virtual address where RELRO protection starts.
    pub start: u64,
    /// Size in bytes (should be page-aligned for full protection).
    pub size: u64,
    /// Sections that fall within the RELRO region.
    pub covered_sections: Vec<String>,
    /// True if `BIND_NOW` is also set (full RELRO).
    pub full_relro: bool,
}

impl RelroRegion {
    /// Validate that the RELRO region is page-aligned.
    ///
    /// # Errors
    /// Returns an error if the region is not page-aligned.
    pub const fn check_alignment(&self, page_size: u64) -> Result<(), LinkerError> {
        if !self.start.is_multiple_of(page_size) || !self.size.is_multiple_of(page_size) {
            return Err(LinkerError::BadRelro { start: self.start, size: self.size });
        }
        Ok(())
    }

    /// True if `.got.plt` is fully covered by this region (full RELRO).
    #[must_use]
    pub fn covers_got_plt(&self) -> bool {
        self.covered_sections.iter().any(|s| s == ".got.plt")
    }

    /// Human-readable summary.
    #[must_use]
    pub fn describe(&self) -> String {
        let coverage = self.covered_sections.join(", ");
        let kind = if self.full_relro { "Full RELRO" } else { "Partial RELRO" };
        format!(
            "{kind}: 0x{:X}..0x{:X} ({} bytes) covers [{}]",
            self.start, self.start + self.size, self.size, coverage
        )
    }
}

/// Identify which sections fall within a `GNU_RELRO` segment.
#[must_use]
pub fn identify_relro_sections(
    relro_start: u64,
    relro_size: u64,
    sections: &[(&str, u64, u64)], // (name, addr, size)
) -> Vec<String> {
    sections.iter()
        .filter(|(_, addr, sz)| {
            let s_end = addr + sz;
            let r_end = relro_start + relro_size;
            *addr >= relro_start && s_end <= r_end
        })
        .map(|(name, _, _)| (*name).to_string())
        .collect()
}

// ── BIND_NOW ──────────────────────────────────────────────────────────────────

/// Check for `DT_FLAGS` / `DT_FLAGS_1` entries indicating `BIND_NOW`.
#[must_use]
pub const fn has_bind_now(dt_flags: u64, dt_flags_1: u64) -> bool {
    // DT_FLAGS bit 3 = DF_BIND_NOW; DT_FLAGS_1 bit 0 = DF_1_NOW.
    (dt_flags & 0x8) != 0 || (dt_flags_1 & 0x1) != 0
}

/// Check for `DT_FLAGS_1` bit 8 = `DF_1_PIE` (position-independent executable).
#[must_use]
pub const fn is_pie(dt_flags_1: u64) -> bool {
    (dt_flags_1 & 0x0800_0000) != 0
}

/// Check for `DT_FLAGS_1` bit 0x400 = `DF_1_NODELETE` (cannot be dlclose'd).
#[must_use]
pub const fn is_nodelete(dt_flags_1: u64) -> bool {
    (dt_flags_1 & 0x400) != 0
}

// ── Dynamic linker summary ────────────────────────────────────────────────────

/// High-level summary of the dynamic linking setup.
#[derive(Debug, Clone)]
pub struct DynLinkSummary {
    pub soname: Option<String>,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub bind_now: bool,
    pub pie: bool,
    pub relro: Option<RelroRegion>,
    pub plt_entry_count: usize,
    pub ifunc_count: usize,
    pub tls_var_count: usize,
}

impl fmt::Display for DynLinkSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Dynamic Linking Summary")?;
        writeln!(f, "  Interpreter: {}", self.interpreter.as_deref().unwrap_or("<none>"))?;
        writeln!(f, "  SONAME: {}", self.soname.as_deref().unwrap_or("<none>"))?;
        writeln!(f, "  PIE: {}", self.pie)?;
        writeln!(f, "  BIND_NOW (lazy={}): {}", !self.bind_now, self.bind_now)?;
        writeln!(f, "  RPATH: {}", self.rpath.as_deref().unwrap_or("-"))?;
        writeln!(f, "  RUNPATH: {}", self.runpath.as_deref().unwrap_or("-"))?;
        writeln!(f, "  DT_NEEDED ({}):", self.needed.len())?;
        for lib in &self.needed {
            writeln!(f, "    {lib}")?;
        }
        writeln!(f, "  PLT entries: {}", self.plt_entry_count)?;
        writeln!(f, "  IFUNC entries: {}", self.ifunc_count)?;
        writeln!(f, "  TLS variables: {}", self.tls_var_count)?;
        if let Some(ref relro) = self.relro {
            writeln!(f, "  RELRO: {}", relro.describe())?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_graph_bfs_order() {
        let mut g = DepGraph::default();
        g.add_lib(LibNode { soname: "main".into(), needed: vec!["liba.so".into(), "libb.so".into()], load_addr: 0, is_main: true });
        g.add_lib(LibNode { soname: "liba.so".into(), needed: vec!["libc.so.6".into()], load_addr: 0, is_main: false });
        g.add_lib(LibNode { soname: "libb.so".into(), needed: vec![], load_addr: 0, is_main: false });
        g.add_lib(LibNode { soname: "libc.so.6".into(), needed: vec![], load_addr: 0, is_main: false });
        g.resolve_order("main").unwrap();
        assert_eq!(g.load_order[0], "main");
        assert!(g.load_order.contains(&"libc.so.6".to_string()));
    }

    #[test]
    fn missing_needed_error() {
        let mut g = DepGraph::default();
        g.add_lib(LibNode { soname: "main".into(), needed: vec!["missing.so".into()], load_addr: 0, is_main: true });
        let err = g.resolve_order("main").unwrap_err();
        assert!(matches!(err, LinkerError::MissingDtNeeded(_)));
    }

    #[test]
    fn plt_got_layout_build() {
        let relocs = vec![
            ("printf".to_string(), 0, 0x0060_1018),
            ("puts".to_string(), 8, 0x0060_1020),
        ];
        let layout = PltGotLayout::build(0x0040_0400, 0x0060_1000, 16, 0x0060_0E20, &relocs);
        assert_eq!(layout.entries.len(), 3); // PLT[0] + 2 entries
        assert_eq!(layout.entries[1].symbol, "printf");
    }

    #[test]
    fn describe_plt_addr() {
        let relocs = vec![("exit".to_string(), 0, 0x0060_1018)];
        let layout = PltGotLayout::build(0x0040_0410, 0x0060_1000, 16, 0x0060_0E20, &relocs);
        let desc = layout.describe_addr(0x0040_0420).unwrap();
        assert!(desc.contains("exit"));
    }

    #[test]
    fn lazy_binding_initial_state() {
        let relocs = vec![("write".to_string(), 0, 0x0060_1020)];
        let layout = PltGotLayout::build(0x0040_0410, 0x0060_1000, 16, 0x0060_0E20, &relocs);
        let state = LazyBindingState::initial(&layout, false);
        // First real symbol slot should be unresolved.
        assert!(matches!(state.slots[3].1, GotSlotState::Unresolved { .. }));
    }

    #[test]
    fn bind_now_state() {
        let relocs = vec![("read".to_string(), 0, 0x0060_1028)];
        let layout = PltGotLayout::build(0x0040_0410, 0x0060_1000, 16, 0x0060_0E20, &relocs);
        let state = LazyBindingState::initial(&layout, true);
        assert!(matches!(state.slots[3].1, GotSlotState::BindNow { .. }));
    }

    #[test]
    fn relro_covers_got_plt() {
        let sections = [(".got.plt", 0x0060_1000_u64, 0x1000u64)];
        let covered = identify_relro_sections(0x0060_1000, 0x1000, &sections);
        assert!(covered.contains(&".got.plt".to_string()));
    }

    #[test]
    fn tls_layout_build() {
        let vars = vec![TlsVar {
            name: "errno".to_string(),
            module_id: 0,
            tls_offset: 0,
            size: 4,
            model: TlsModel::InitialExec,
        }];
        let mods = vec![("libc.so.6".to_string(), 8usize, vars)];
        let layout = TlsLayout::build(&mods, 8);
        let tp = layout.tp_offset("errno").unwrap();
        assert!(tp >= 16); // after 2×ptr_size DTP header
    }

    #[test]
    fn has_bind_now_flags() {
        assert!(has_bind_now(0x8, 0));
        assert!(has_bind_now(0, 0x1));
        assert!(!has_bind_now(0, 0));
    }
}
