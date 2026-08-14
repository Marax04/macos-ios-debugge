//! `CoreSight` topology discovery and component modelling.
//!
//! Models the set of `CoreSight` components found via ROM table walk, their
//! connections (funnel → ETF → TPIU etc.), and provides helpers for selecting
//! a trace-capture path from an ETM source to a sink.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::CsError;

// ─── CoreSightComponentKind ───────────────────────────────────────────────────

/// High-level kind of a `CoreSight` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentKind {
    /// Embedded Trace Macrocell.
    Etm,
    /// Embedded Trace Buffer.
    Etb,
    /// Embedded Trace FIFO (ETF in FIFO mode).
    Etf,
    /// Trace Port Interface Unit.
    Tpiu,
    /// Cross Trigger Interface.
    Cti,
    /// Trace Funnel.
    Funnel,
    /// Trace Replicator.
    Replicator,
    /// System Trace Macrocell (MIPI STP).
    Stm,
    /// Embedded Trace Router (ETR — off-chip ETF).
    Etr,
    /// Unknown component.
    Unknown,
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Etm => "ETM",
            Self::Etb => "ETB",
            Self::Etf => "ETF",
            Self::Tpiu => "TPIU",
            Self::Cti => "CTI",
            Self::Funnel => "Funnel",
            Self::Replicator => "Replicator",
            Self::Stm => "STM",
            Self::Etr => "ETR",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl ComponentKind {
    /// Return `true` if this kind is a trace source.
    #[must_use]
    pub const fn is_source(&self) -> bool {
        matches!(self, Self::Etm | Self::Stm)
    }

    /// Return `true` if this kind is a trace sink.
    #[must_use]
    pub const fn is_sink(&self) -> bool {
        matches!(self, Self::Etb | Self::Etf | Self::Tpiu | Self::Etr)
    }
}

// ─── CoreSightId ──────────────────────────────────────────────────────────────

/// `CoreSight` peripheral identification registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoreSightId {
    /// DEVTYPE register value (major:minor component type).
    pub dev_type: u8,
    /// Part number from PIDR1:PIDR0.
    pub part_num: u16,
    /// Designer (JEP106) ID from PIDR2:PIDR1.
    pub designer: u16,
    /// Revision from PIDR2.
    pub revision: u8,
}

impl CoreSightId {
    /// Create from raw register values.
    #[must_use]
    pub const fn new(dev_type: u8, part_num: u16, designer: u16, revision: u8) -> Self {
        Self {
            dev_type,
            part_num,
            designer,
            revision,
        }
    }

    /// Major component type field (bits 7:4 of DEVTYPE).
    #[must_use]
    pub const fn major_type(&self) -> u8 {
        self.dev_type >> 4
    }

    /// Minor component type field (bits 3:0 of DEVTYPE).
    #[must_use]
    pub const fn minor_type(&self) -> u8 {
        self.dev_type & 0x0F
    }

    /// Infer `ComponentKind` from DEVTYPE.
    #[must_use]
    pub const fn infer_kind(&self) -> ComponentKind {
        match (self.major_type(), self.minor_type()) {
            (0x1, 0x1 | 0x2) => ComponentKind::Etm,
            (0x2, 0x1) => ComponentKind::Funnel,
            (0x2, 0x2) => ComponentKind::Replicator,
            (0x3, 0x1) => ComponentKind::Etf,
            (0x3, 0x2) => ComponentKind::Tpiu,
            (0x3, 0x3) => ComponentKind::Etb,
            (0x4, 0x1) => ComponentKind::Cti,
            (0x6, 0x1) => ComponentKind::Stm,
            _ => ComponentKind::Unknown,
        }
    }

    /// ARM designer ID (JEP106).
    pub const ARM_DESIGNER: u16 = 0x23B;
}

impl fmt::Display for CoreSightId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DEVTYPE={:#04x} PN={:#06x} DESIG={:#06x} REV={}",
            self.dev_type, self.part_num, self.designer, self.revision
        )
    }
}

// ─── ComponentRegMap ──────────────────────────────────────────────────────────

/// Standard `CoreSight` register offsets for component identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentRegMap {
    /// Base address of the component's 4 KiB register page.
    pub base: u64,
}

impl ComponentRegMap {
    /// DEVID register offset.
    pub const DEVID: u64 = 0xFC8;
    /// DEVTYPE register offset.
    pub const DEVTYPE: u64 = 0xFCC;
    /// PIDR4 register offset.
    pub const PIDR4: u64 = 0xFD0;
    /// PIDR0 register offset.
    pub const PIDR0: u64 = 0xFE0;
    /// PIDR1 register offset.
    pub const PIDR1: u64 = 0xFE4;
    /// PIDR2 register offset.
    pub const PIDR2: u64 = 0xFE8;
    /// PIDR3 register offset.
    pub const PIDR3: u64 = 0xFEC;
    /// CIDR0 register offset (component class identification).
    pub const CIDR0: u64 = 0xFF0;
    /// CIDR1 register offset.
    pub const CIDR1: u64 = 0xFF4;
    /// CIDR2 register offset.
    pub const CIDR2: u64 = 0xFF8;
    /// CIDR3 register offset.
    pub const CIDR3: u64 = 0xFFC;

    /// Create a register map anchored at `base`.
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Absolute address of a register at `offset`.
    #[must_use]
    pub const fn abs(&self, offset: u64) -> u64 {
        self.base + offset
    }

    /// Validate CIDR magic bytes (should be `0x0D`, `0x10`, `0x05`, `0xB1`).
    #[must_use]
    pub const fn validate_cidr(cidr: [u32; 4]) -> bool {
        cidr[0] & 0xFF == 0x0D
            && cidr[1] & 0xFF == 0x10
            && cidr[2] & 0xFF == 0x05
            && cidr[3] & 0xFF == 0xB1
    }

    /// Extract DEVTYPE from a raw register word.
    #[must_use]
    pub const fn extract_devtype(reg: u32) -> u8 {
        (reg & 0xFF) as u8
    }

    /// Build a `CoreSightId` from raw register reads.
    #[must_use]
    pub const fn build_id(dev_type: u32, pidr0: u32, pidr1: u32, pidr2: u32) -> CoreSightId {
        let part_num = ((pidr1 & 0x0F) as u16) << 8 | (pidr0 & 0xFF) as u16;
        let designer = ((pidr2 & 0x0F) as u16) << 4 | ((pidr1 >> 4) & 0x0F) as u16;
        let revision = ((pidr2 >> 4) & 0x0F) as u8;
        CoreSightId::new(
            Self::extract_devtype(dev_type),
            part_num,
            designer,
            revision,
        )
    }
}

// ─── CoreSightComponent ───────────────────────────────────────────────────────

/// A discovered `CoreSight` component.
#[derive(Debug, Clone)]
pub struct CoreSightComponent {
    /// Unique numeric ID assigned during topology discovery.
    pub id: u32,
    /// Component kind.
    pub kind: ComponentKind,
    /// `CoreSight` peripheral ID registers.
    pub cs_id: CoreSightId,
    /// Base address of the component's register page.
    pub base_addr: u64,
    /// Human-readable label (e.g. "ETM0", "Funnel1").
    pub label: String,
    /// CPU affinity index (for ETM, which CPU core it traces).
    pub cpu: Option<u32>,
}

impl CoreSightComponent {
    /// Create a component.
    #[must_use]
    pub fn new(
        id: u32,
        kind: ComponentKind,
        cs_id: CoreSightId,
        base_addr: u64,
        label: impl Into<String>,
    ) -> Self {
        Self {
            id,
            kind,
            cs_id,
            base_addr,
            label: label.into(),
            cpu: None,
        }
    }

    /// Set CPU affinity.
    #[must_use] 
    pub const fn with_cpu(mut self, cpu: u32) -> Self {
        self.cpu = Some(cpu);
        self
    }

    /// Return `true` if this is a trace source.
    #[must_use]
    pub const fn is_source(&self) -> bool {
        self.kind.is_source()
    }

    /// Return `true` if this is a trace sink.
    #[must_use]
    pub const fn is_sink(&self) -> bool {
        self.kind.is_sink()
    }

    /// Register map for this component.
    #[must_use]
    pub const fn reg_map(&self) -> ComponentRegMap {
        ComponentRegMap::new(self.base_addr)
    }
}

impl fmt::Display for CoreSightComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] @ {:#018x} cpu={:?}",
            self.label, self.kind, self.base_addr, self.cpu
        )
    }
}

// ─── TopologyGraph ────────────────────────────────────────────────────────────

/// Directed graph of `CoreSight` component connections.
///
/// Edges run from source to sink, e.g. ETM → Funnel → ETF → TPIU.
#[derive(Debug, Default)]
pub struct TopologyGraph {
    /// All components by their ID.
    components: HashMap<u32, CoreSightComponent>,
    /// `source_id → set<sink_id>`.
    edges: HashMap<u32, HashSet<u32>>,
}

impl TopologyGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a component.
    pub fn add_component(&mut self, comp: CoreSightComponent) {
        self.components.insert(comp.id, comp);
    }

    /// Add a directed edge `from → to`.
    pub fn add_edge(&mut self, from: u32, to: u32) {
        self.edges.entry(from).or_default().insert(to);
    }

    /// Get a component by ID.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&CoreSightComponent> {
        self.components.get(&id)
    }

    /// Number of components.
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// All component IDs.
    #[must_use]
    pub fn ids(&self) -> Vec<u32> {
        self.components.keys().copied().collect()
    }

    /// All ETM source components.
    #[must_use]
    pub fn sources(&self) -> Vec<&CoreSightComponent> {
        self.components.values().filter(|c| c.is_source()).collect()
    }

    /// All trace sink components.
    #[must_use]
    pub fn sinks(&self) -> Vec<&CoreSightComponent> {
        self.components.values().filter(|c| c.is_sink()).collect()
    }

    /// Downstream neighbours of `id`.
    #[must_use]
    pub fn successors(&self, id: u32) -> Vec<u32> {
        self.edges
            .get(&id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// All component IDs of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: ComponentKind) -> Vec<&CoreSightComponent> {
        self.components
            .values()
            .filter(|c| c.kind == kind)
            .collect()
    }

    /// BFS path from `source` to `sink` (returns IDs in path order, inclusive).
    ///
    /// # Panics
    ///
    /// Panics if the BFS queue is empty when popped (cannot happen in practice).
    #[must_use]
    pub fn find_path(&self, source: u32, sink: u32) -> Option<Vec<u32>> {
        if source == sink {
            return Some(vec![source]);
        }
        let mut visited: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<Vec<u32>> = VecDeque::new();
        queue.push_back(vec![source]);
        visited.insert(source);

        while let Some(path) = queue.pop_front() {
            let last = *path.last().unwrap();
            if let Some(succs) = self.edges.get(&last) {
                for &next in succs {
                    if visited.contains(&next) {
                        continue;
                    }
                    let mut new_path = path.clone();
                    new_path.push(next);
                    if next == sink {
                        return Some(new_path);
                    }
                    visited.insert(next);
                    queue.push_back(new_path);
                }
            }
        }
        None
    }

    /// All paths from `source` to any sink.
    ///
    /// # Panics
    ///
    /// Panics if the BFS queue is empty when popped (cannot happen in practice).
    #[must_use]
    pub fn paths_to_any_sink(&self, source: u32) -> Vec<Vec<u32>> {
        let mut results = Vec::new();
        let mut queue: VecDeque<Vec<u32>> = VecDeque::new();
        queue.push_back(vec![source]);

        while let Some(path) = queue.pop_front() {
            let last = *path.last().unwrap();
            let succs = self.successors(last);
            if succs.is_empty() {
                results.push(path);
                continue;
            }
            for &next in &succs {
                let mut new_path = path.clone();
                new_path.push(next);
                if self.get(next).is_some_and(CoreSightComponent::is_sink) {
                    results.push(new_path);
                } else {
                    queue.push_back(new_path);
                }
            }
        }
        results
    }
}

// ─── TraceCapture ─────────────────────────────────────────────────────────────

/// High-level helper for selecting a trace-capture path.
#[derive(Debug)]
pub struct TraceCapture<'g> {
    graph: &'g TopologyGraph,
    /// Selected source component ID.
    pub source_id: Option<u32>,
    /// Selected sink component ID.
    pub sink_id: Option<u32>,
}

impl<'g> TraceCapture<'g> {
    /// Create a capture selector for `graph`.
    #[must_use]
    pub const fn new(graph: &'g TopologyGraph) -> Self {
        Self {
            graph,
            source_id: None,
            sink_id: None,
        }
    }

    /// Select the first ETM source for `cpu` (0-based).
    ///
    /// # Errors
    ///
    /// Returns `Err` if no ETM is found for the given CPU index.
    pub fn select_source_for_cpu(&mut self, cpu: u32) -> Result<(), CsError> {
        let src = self
            .graph
            .sources()
            .into_iter()
            .find(|c| c.cpu == Some(cpu))
            .ok_or_else(|| CsError::RomTable(format!("no ETM for cpu {cpu}")))?;
        self.source_id = Some(src.id);
        Ok(())
    }

    /// Select the first available sink of `kind`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no sink of the given kind is found.
    pub fn select_sink_by_kind(&mut self, kind: ComponentKind) -> Result<(), CsError> {
        let sink = self
            .graph
            .by_kind(kind)
            .into_iter()
            .next()
            .ok_or_else(|| CsError::RomTable(format!("no {kind} sink found")))?;
        self.sink_id = Some(sink.id);
        Ok(())
    }

    /// Compute the component path from selected source to selected sink.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no source or sink is selected, or no path exists.
    pub fn path(&self) -> Result<Vec<u32>, CsError> {
        let src = self
            .source_id
            .ok_or_else(|| CsError::RomTable("no source selected".to_string()))?;
        let snk = self
            .sink_id
            .ok_or_else(|| CsError::RomTable("no sink selected".to_string()))?;
        self.graph
            .find_path(src, snk)
            .ok_or_else(|| CsError::RomTable(format!("no path from {src} to {snk}")))
    }

    /// Describe the capture configuration.
    #[must_use]
    pub fn describe(&self) -> String {
        let src = self
            .source_id
            .and_then(|id| self.graph.get(id))
            .map_or("none", |c| c.label.as_str());
        let snk = self
            .sink_id
            .and_then(|id| self.graph.get(id))
            .map_or("none", |c| c.label.as_str());
        format!("{src} → {snk}")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id(kind: ComponentKind) -> CoreSightId {
        let devtype = match kind {
            ComponentKind::Etm => 0x11,
            ComponentKind::Funnel => 0x21,
            ComponentKind::Etb => 0x33,
            ComponentKind::Tpiu => 0x32,
            ComponentKind::Etf => 0x31,
            _ => 0x00,
        };
        CoreSightId::new(devtype, 0x950, CoreSightId::ARM_DESIGNER, 0)
    }

    fn make_graph() -> TopologyGraph {
        // ETM0(0) → Funnel(1) → ETF(2) → TPIU(3)
        let mut g = TopologyGraph::new();
        g.add_component(
            CoreSightComponent::new(
                0,
                ComponentKind::Etm,
                sample_id(ComponentKind::Etm),
                0x0000_2000,
                "ETM0",
            )
            .with_cpu(0),
        );
        g.add_component(CoreSightComponent::new(
            1,
            ComponentKind::Funnel,
            sample_id(ComponentKind::Funnel),
            0x0000_4000,
            "Funnel1",
        ));
        g.add_component(CoreSightComponent::new(
            2,
            ComponentKind::Etf,
            sample_id(ComponentKind::Etf),
            0x0000_5000,
            "ETF0",
        ));
        g.add_component(CoreSightComponent::new(
            3,
            ComponentKind::Tpiu,
            sample_id(ComponentKind::Tpiu),
            0x0000_6000,
            "TPIU0",
        ));
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g
    }

    // ── ComponentKind ────────────────────────────────────────────────────────

    #[test]
    fn kind_display() {
        assert_eq!(ComponentKind::Etm.to_string(), "ETM");
        assert_eq!(ComponentKind::Funnel.to_string(), "Funnel");
        assert_eq!(ComponentKind::Tpiu.to_string(), "TPIU");
    }

    #[test]
    fn kind_is_source() {
        assert!(ComponentKind::Etm.is_source());
        assert!(!ComponentKind::Etb.is_source());
    }

    #[test]
    fn kind_is_sink() {
        assert!(ComponentKind::Tpiu.is_sink());
        assert!(!ComponentKind::Etm.is_sink());
    }

    // ── CoreSightId ──────────────────────────────────────────────────────────

    #[test]
    fn cs_id_major_minor() {
        let id = CoreSightId::new(0x21, 0, 0, 0);
        assert_eq!(id.major_type(), 0x2);
        assert_eq!(id.minor_type(), 0x1);
    }

    #[test]
    fn cs_id_infer_kind_etm() {
        let id = CoreSightId::new(0x11, 0, 0, 0);
        assert_eq!(id.infer_kind(), ComponentKind::Etm);
    }

    #[test]
    fn cs_id_infer_kind_funnel() {
        let id = CoreSightId::new(0x21, 0, 0, 0);
        assert_eq!(id.infer_kind(), ComponentKind::Funnel);
    }

    #[test]
    fn cs_id_infer_kind_tpiu() {
        let id = CoreSightId::new(0x32, 0, 0, 0);
        assert_eq!(id.infer_kind(), ComponentKind::Tpiu);
    }

    #[test]
    fn cs_id_infer_kind_unknown() {
        let id = CoreSightId::new(0xFF, 0, 0, 0);
        assert_eq!(id.infer_kind(), ComponentKind::Unknown);
    }

    #[test]
    fn cs_id_display() {
        let id = CoreSightId::new(0x11, 0x950, CoreSightId::ARM_DESIGNER, 0);
        let s = id.to_string();
        assert!(s.contains("DEVTYPE"));
    }

    // ── ComponentRegMap ──────────────────────────────────────────────────────

    #[test]
    fn reg_map_abs() {
        let rm = ComponentRegMap::new(0x1000_0000);
        assert_eq!(rm.abs(ComponentRegMap::DEVTYPE), 0x1000_0FCC);
    }

    #[test]
    fn reg_map_validate_cidr_valid() {
        let cidr = [0x0Du32, 0x10, 0x05, 0xB1];
        assert!(ComponentRegMap::validate_cidr(cidr));
    }

    #[test]
    fn reg_map_validate_cidr_invalid() {
        let cidr = [0x00u32, 0x10, 0x05, 0xB1];
        assert!(!ComponentRegMap::validate_cidr(cidr));
    }

    #[test]
    fn reg_map_build_id() {
        let id = ComponentRegMap::build_id(0x11, 0x50, 0x09, 0x3B);
        assert_eq!(id.dev_type, 0x11);
        assert_eq!(id.part_num, 0x950);
    }

    // ── TopologyGraph ────────────────────────────────────────────────────────

    #[test]
    fn graph_component_count() {
        let g = make_graph();
        assert_eq!(g.component_count(), 4);
    }

    #[test]
    fn graph_sources() {
        let g = make_graph();
        assert_eq!(g.sources().len(), 1);
        assert_eq!(g.sources()[0].kind, ComponentKind::Etm);
    }

    #[test]
    fn graph_sinks() {
        let g = make_graph();
        // ETF and TPIU are both sinks
        assert_eq!(g.sinks().len(), 2);
    }

    #[test]
    fn graph_find_path() {
        let g = make_graph();
        let path = g.find_path(0, 3).unwrap();
        assert_eq!(path, vec![0, 1, 2, 3]);
    }

    #[test]
    fn graph_find_path_no_path() {
        let g = make_graph();
        // 3 → 0 has no edges
        assert!(g.find_path(3, 0).is_none());
    }

    #[test]
    fn graph_successors() {
        let g = make_graph();
        assert!(g.successors(0).contains(&1));
    }

    #[test]
    fn graph_by_kind_etm() {
        let g = make_graph();
        assert_eq!(g.by_kind(ComponentKind::Etm).len(), 1);
    }

    #[test]
    fn graph_paths_to_any_sink() {
        let g = make_graph();
        let paths = g.paths_to_any_sink(0);
        // Path ends at TPIU (sink)
        assert!(!paths.is_empty());
        let last = *paths[0].last().unwrap();
        assert!(g.get(last).unwrap().is_sink());
    }

    #[test]
    fn graph_ids_not_empty() {
        let g = make_graph();
        assert!(!g.ids().is_empty());
    }

    // ── TraceCapture ─────────────────────────────────────────────────────────

    #[test]
    fn trace_capture_select_source_cpu0() {
        let g = make_graph();
        let mut tc = TraceCapture::new(&g);
        tc.select_source_for_cpu(0).unwrap();
        assert_eq!(tc.source_id, Some(0));
    }

    #[test]
    fn trace_capture_select_source_missing_cpu() {
        let g = make_graph();
        let mut tc = TraceCapture::new(&g);
        assert!(tc.select_source_for_cpu(99).is_err());
    }

    #[test]
    fn trace_capture_select_sink_tpiu() {
        let g = make_graph();
        let mut tc = TraceCapture::new(&g);
        tc.select_sink_by_kind(ComponentKind::Tpiu).unwrap();
        assert!(tc.sink_id.is_some());
    }

    #[test]
    fn trace_capture_path() {
        let g = make_graph();
        let mut tc = TraceCapture::new(&g);
        tc.select_source_for_cpu(0).unwrap();
        tc.select_sink_by_kind(ComponentKind::Tpiu).unwrap();
        let path = tc.path().unwrap();
        assert_eq!(path.len(), 4);
    }

    #[test]
    fn trace_capture_describe() {
        let g = make_graph();
        let mut tc = TraceCapture::new(&g);
        tc.select_source_for_cpu(0).unwrap();
        tc.select_sink_by_kind(ComponentKind::Tpiu).unwrap();
        let desc = tc.describe();
        assert!(desc.contains('→'));
    }

    #[test]
    fn component_display() {
        let comp = CoreSightComponent::new(
            0,
            ComponentKind::Etm,
            sample_id(ComponentKind::Etm),
            0x2000,
            "ETM0",
        );
        let s = comp.to_string();
        assert!(s.contains("ETM0"));
    }
}
