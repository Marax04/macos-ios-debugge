//! PDF object reference graph.
//!
//! Builds a complete directed graph of PDF object references, detects circular
//! references and orphaned objects, analyzes cross-reference table integrity,
//! detects incremental update attacks, and maps object types.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ObjectType ───────────────────────────────────────────────────────────────

/// The semantic type of a PDF object, inferred from its dictionary `/Type` key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectType {
    /// `/Type /Catalog` — document root.
    Catalog,
    /// `/Type /Pages` — page tree node.
    Pages,
    /// `/Type /Page` — individual page.
    Page,
    /// `/Type /Font` — font resource.
    Font,
    /// `/Type /XObject` — external object (image, form, etc.).
    XObject,
    /// `/Type /Annot` — annotation (links, widgets, etc.).
    Annot,
    /// `/Type /Action` — action dictionary.
    Action,
    /// `/Type /JavaScript` — JavaScript action.
    JavaScript,
    /// Embedded file specification.
    EmbeddedFile,
    /// Stream without a known type.
    Stream,
    /// Plain dictionary without a `/Type`.
    Dictionary,
    /// Array object.
    Array,
    /// Integer, real, string, or name.
    Primitive,
    /// Free (deleted) object.
    Free,
    /// Unknown or unparseable.
    Unknown,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Catalog => "Catalog",
            Self::Pages => "Pages",
            Self::Page => "Page",
            Self::Font => "Font",
            Self::XObject => "XObject",
            Self::Annot => "Annot",
            Self::Action => "Action",
            Self::JavaScript => "JavaScript",
            Self::EmbeddedFile => "EmbeddedFile",
            Self::Stream => "Stream",
            Self::Dictionary => "Dictionary",
            Self::Array => "Array",
            Self::Primitive => "Primitive",
            Self::Free => "Free",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── ObjectRef ────────────────────────────────────────────────────────────────

/// An indirect object reference: `object_number generation R`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    pub obj_num: u32,
    pub generation: u16,
}

impl ObjectRef {
    /// Create a new object reference.
    #[must_use]
    pub const fn new(obj_num: u32, generation: u16) -> Self {
        Self { obj_num, generation }
    }

    /// Zero-generation reference (the common case).
    #[must_use]
    pub const fn gen0(obj_num: u32) -> Self {
        Self::new(obj_num, 0)
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} R", self.obj_num, self.generation)
    }
}

// ─── GraphNode ────────────────────────────────────────────────────────────────

/// A node in the PDF object graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// The object reference.
    pub obj_ref: ObjectRef,
    /// Inferred object type.
    pub obj_type: ObjectType,
    /// Objects this node directly references.
    pub outgoing: Vec<ObjectRef>,
    /// Objects that reference this node (back-links).
    pub incoming: Vec<ObjectRef>,
    /// Whether this object was found in the xref table.
    pub in_xref: bool,
    /// Whether this object was reached from the document catalog (reachable).
    pub reachable: bool,
    /// Byte offset in the file.
    pub file_offset: u64,
    /// Whether this object is part of a circular reference chain.
    pub in_cycle: bool,
    /// Xref generation present in xref table.
    pub xref_generation: Option<u16>,
}

impl GraphNode {
    /// Create a new graph node.
    #[must_use]
    pub fn new(obj_ref: ObjectRef, obj_type: ObjectType, file_offset: u64) -> Self {
        Self {
            obj_ref,
            obj_type,
            outgoing: vec![],
            incoming: vec![],
            in_xref: false,
            reachable: false,
            file_offset,
            in_cycle: false,
            xref_generation: None,
        }
    }

    /// Returns true if this object is orphaned (not reachable from catalog).
    #[must_use]
    pub const fn is_orphaned(&self) -> bool {
        !self.reachable && self.in_xref
    }
}

// ─── XRefEntry ────────────────────────────────────────────────────────────────

/// A single cross-reference table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XRefEntry {
    /// Object number.
    pub obj_num: u32,
    /// Generation number.
    pub generation: u16,
    /// Byte offset (for in-use entries).
    pub offset: u64,
    /// Whether the entry is in-use.
    pub in_use: bool,
    /// Whether this entry came from an incremental update section.
    pub from_incremental: bool,
}

impl XRefEntry {
    /// Create a new in-use xref entry.
    #[must_use]
    pub const fn in_use(obj_num: u32, generation: u16, offset: u64) -> Self {
        Self {
            obj_num,
            generation,
            offset,
            in_use: true,
            from_incremental: false,
        }
    }

    /// Create a free xref entry.
    #[must_use]
    pub const fn free(obj_num: u32, generation: u16) -> Self {
        Self {
            obj_num,
            generation,
            offset: 0,
            in_use: false,
            from_incremental: false,
        }
    }
}

// ─── XRefTable ────────────────────────────────────────────────────────────────

/// A complete cross-reference table (possibly spanning multiple sections).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XRefTable {
    pub entries: Vec<XRefEntry>,
    /// Number of incremental update sections found.
    pub incremental_sections: u32,
    /// Offsets of each `startxref` keyword found.
    pub startxref_offsets: Vec<u64>,
    /// Whether the xref was encoded as a cross-reference stream.
    pub has_xref_stream: bool,
}

impl XRefTable {
    /// Create a new, empty xref table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add(&mut self, entry: XRefEntry) {
        self.entries.push(entry);
    }

    /// Look up an entry by object number.
    #[must_use]
    pub fn get(&self, obj_num: u32) -> Option<&XRefEntry> {
        self.entries.iter().rev().find(|e| e.obj_num == obj_num)
    }

    /// Return all in-use entries.
    #[must_use]
    pub fn in_use_entries(&self) -> Vec<&XRefEntry> {
        self.entries.iter().filter(|e| e.in_use).collect()
    }

    /// Return the highest object number.
    #[must_use]
    pub fn max_obj_num(&self) -> u32 {
        self.entries.iter().map(|e| e.obj_num).max().unwrap_or(0)
    }

    /// Return all entries marked as coming from incremental updates.
    #[must_use]
    pub fn incremental_entries(&self) -> Vec<&XRefEntry> {
        self.entries.iter().filter(|e| e.from_incremental).collect()
    }

    /// Count duplicate entries (same obj_num appearing more than once).
    #[must_use]
    pub fn duplicate_count(&self) -> usize {
        let mut seen: HashMap<u32, usize> = HashMap::new();
        for e in &self.entries {
            *seen.entry(e.obj_num).or_insert(0) += 1;
        }
        seen.values().filter(|&&c| c > 1).count()
    }
}

// ─── IncrementalUpdate ────────────────────────────────────────────────────────

/// Metadata about a single incremental update section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalUpdate {
    /// Sequential index of this update (0 = original, 1 = first update, etc.).
    pub index: u32,
    /// Byte offset of the `xref` or xref-stream for this update.
    pub xref_offset: u64,
    /// Object numbers added/modified in this update.
    pub modified_objects: Vec<u32>,
    /// Whether this update contains suspicious modifications (e.g. modifying the catalog action).
    pub is_suspicious: bool,
    /// Reason for suspicion, if any.
    pub suspicion_reason: Option<String>,
}

impl IncrementalUpdate {
    /// Create a new incremental update record.
    #[must_use]
    pub fn new(index: u32, xref_offset: u64, modified_objects: Vec<u32>) -> Self {
        Self {
            index,
            xref_offset,
            modified_objects,
            is_suspicious: false,
            suspicion_reason: None,
        }
    }

    /// Mark this update as suspicious.
    pub fn flag_suspicious(&mut self, reason: impl Into<String>) {
        self.is_suspicious = true;
        self.suspicion_reason = Some(reason.into());
    }
}

// ─── GraphAnalysis ────────────────────────────────────────────────────────────

/// Result of full graph analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnalysis {
    /// Total number of objects in the graph.
    pub total_objects: usize,
    /// Reachable objects (from the document catalog).
    pub reachable_count: usize,
    /// Orphaned objects (in xref but not reachable).
    pub orphaned_objects: Vec<ObjectRef>,
    /// Objects involved in circular references.
    pub cyclic_objects: Vec<ObjectRef>,
    /// Objects found in the file but not in the xref table.
    pub missing_from_xref: Vec<ObjectRef>,
    /// Incremental update details.
    pub incremental_updates: Vec<IncrementalUpdate>,
    /// Detected suspicious xref anomalies.
    pub xref_anomalies: Vec<XRefAnomaly>,
    /// Count of each object type.
    pub type_counts: HashMap<String, usize>,
    /// Whether the document has JavaScript.
    pub has_javascript: bool,
    /// Whether the document has embedded files.
    pub has_embedded_files: bool,
    /// Whether the document has external launch actions.
    pub has_launch_actions: bool,
    /// Overall risk score [0, 100].
    pub risk_score: u32,
}

impl GraphAnalysis {
    /// Returns true if the document contains suspicious elements.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.risk_score >= 30 || !self.xref_anomalies.is_empty()
    }
}

// ─── XRefAnomaly ──────────────────────────────────────────────────────────────

/// An anomaly detected in the cross-reference structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefAnomaly {
    /// Short name for the anomaly type.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Associated object numbers (if applicable).
    pub objects: Vec<u32>,
    /// Severity [0, 10].
    pub severity: u32,
}

impl XRefAnomaly {
    /// Create a new xref anomaly.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        description: impl Into<String>,
        objects: Vec<u32>,
        severity: u32,
    ) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            objects,
            severity,
        }
    }
}

// ─── PdfObjectGraph ──────────────────────────────────────────────────────────

/// The full PDF object reference graph.
pub struct PdfObjectGraph {
    /// All nodes indexed by object number.
    nodes: HashMap<u32, GraphNode>,
    /// The xref table.
    pub xref: XRefTable,
    /// Root catalog object reference (if known).
    pub catalog_ref: Option<ObjectRef>,
    /// Incremental update sections.
    pub incremental_updates: Vec<IncrementalUpdate>,
}

impl PdfObjectGraph {
    /// Create a new, empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            xref: XRefTable::new(),
            catalog_ref: None,
            incremental_updates: vec![],
        }
    }

    /// Add or update a node in the graph.
    pub fn upsert_node(&mut self, node: GraphNode) {
        self.nodes.insert(node.obj_ref.obj_num, node);
    }

    /// Get a node by object number (immutable).
    #[must_use]
    pub fn get_node(&self, obj_num: u32) -> Option<&GraphNode> {
        self.nodes.get(&obj_num)
    }

    /// Get a node by object number (mutable).
    pub fn get_node_mut(&mut self, obj_num: u32) -> Option<&mut GraphNode> {
        self.nodes.get_mut(&obj_num)
    }

    /// Add a directed edge from `from` to `to`.
    pub fn add_edge(&mut self, from: ObjectRef, to: ObjectRef) {
        // Ensure both nodes exist.
        self.nodes.entry(from.obj_num).or_insert_with(|| {
            GraphNode::new(from, ObjectType::Unknown, 0)
        });
        self.nodes.entry(to.obj_num).or_insert_with(|| {
            GraphNode::new(to, ObjectType::Unknown, 0)
        });
        // Add outgoing edge on 'from'.
        let from_node = self.nodes.get_mut(&from.obj_num).unwrap();
        if !from_node.outgoing.contains(&to) {
            from_node.outgoing.push(to);
        }
        // Add incoming back-link on 'to'.
        let to_node = self.nodes.get_mut(&to.obj_num).unwrap();
        if !to_node.incoming.contains(&from) {
            to_node.incoming.push(from);
        }
    }

    /// Mark all nodes reachable from the catalog via BFS.
    pub fn mark_reachable(&mut self) {
        let root = match self.catalog_ref {
            Some(r) => r,
            None => return,
        };
        let mut queue: VecDeque<u32> = VecDeque::new();
        let mut visited: HashSet<u32> = HashSet::new();
        queue.push_back(root.obj_num);
        while let Some(num) = queue.pop_front() {
            if visited.contains(&num) {
                continue;
            }
            visited.insert(num);
            if let Some(node) = self.nodes.get_mut(&num) {
                node.reachable = true;
                let children: Vec<ObjectRef> = node.outgoing.clone();
                for child in children {
                    if !visited.contains(&child.obj_num) {
                        queue.push_back(child.obj_num);
                    }
                }
            }
        }
    }

    /// Detect cycles using DFS with a grey/black marking scheme.
    pub fn detect_cycles(&mut self) {
        let all_nums: Vec<u32> = self.nodes.keys().copied().collect();
        let mut state: HashMap<u32, u8> = HashMap::new(); // 0=white, 1=grey, 2=black
        let mut cyclic: HashSet<u32> = HashSet::new();

        fn dfs(
            num: u32,
            nodes: &HashMap<u32, GraphNode>,
            state: &mut HashMap<u32, u8>,
            cyclic: &mut HashSet<u32>,
            path: &mut Vec<u32>,
        ) {
            if *state.get(&num).unwrap_or(&0) == 2 {
                return;
            }
            if *state.get(&num).unwrap_or(&0) == 1 {
                // Found a cycle — mark all nodes on the current path from this node.
                if let Some(pos) = path.iter().position(|&n| n == num) {
                    for &n in &path[pos..] {
                        cyclic.insert(n);
                    }
                }
                return;
            }
            state.insert(num, 1);
            path.push(num);
            if let Some(node) = nodes.get(&num) {
                let children: Vec<u32> = node.outgoing.iter().map(|r| r.obj_num).collect();
                for child in children {
                    dfs(child, nodes, state, cyclic, path);
                }
            }
            path.pop();
            state.insert(num, 2);
        }

        for &num in &all_nums {
            if *state.get(&num).unwrap_or(&0) == 0 {
                let mut path = Vec::new();
                dfs(num, &self.nodes, &mut state, &mut cyclic, &mut path);
            }
        }

        for num in cyclic {
            if let Some(node) = self.nodes.get_mut(&num) {
                node.in_cycle = true;
            }
        }
    }

    /// Return all orphaned nodes.
    #[must_use]
    pub fn orphaned(&self) -> Vec<&GraphNode> {
        self.nodes.values().filter(|n| n.is_orphaned()).collect()
    }

    /// Return all cyclic nodes.
    #[must_use]
    pub fn cyclic_nodes(&self) -> Vec<&GraphNode> {
        self.nodes.values().filter(|n| n.in_cycle).collect()
    }

    /// Return the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return all nodes.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<&GraphNode> {
        self.nodes.values().collect()
    }

    /// Count nodes by type.
    #[must_use]
    pub fn type_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for node in self.nodes.values() {
            *counts.entry(node.obj_type.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Perform a full analysis pass and return a `GraphAnalysis`.
    #[must_use]
    pub fn analyze(&mut self) -> GraphAnalysis {
        self.mark_reachable();
        self.detect_cycles();

        let total_objects = self.nodes.len();
        let reachable_count = self.nodes.values().filter(|n| n.reachable).count();

        let orphaned_objects: Vec<ObjectRef> = self
            .orphaned()
            .iter()
            .map(|n| n.obj_ref)
            .collect();

        let cyclic_objects: Vec<ObjectRef> = self
            .cyclic_nodes()
            .iter()
            .map(|n| n.obj_ref)
            .collect();

        // Objects in xref but with wrong offset (heuristic: offset=0 but in-use).
        let mut missing_from_xref = Vec::new();
        for node in self.nodes.values() {
            if !node.in_xref && node.reachable {
                missing_from_xref.push(node.obj_ref);
            }
        }

        // Detect xref anomalies.
        let xref_anomalies = self.detect_xref_anomalies();

        // Detect incremental update attacks.
        let incremental_updates = self.analyze_incremental_updates();

        let type_counts = self.type_counts();

        let has_javascript = self
            .nodes
            .values()
            .any(|n| n.obj_type == ObjectType::JavaScript);
        let has_embedded_files = self
            .nodes
            .values()
            .any(|n| n.obj_type == ObjectType::EmbeddedFile);
        let has_launch_actions = self
            .nodes
            .values()
            .any(|n| n.obj_type == ObjectType::Action);

        // Compute risk score.
        let mut risk: u32 = 0;
        if has_javascript { risk += 20; }
        if has_embedded_files { risk += 15; }
        if has_launch_actions { risk += 10; }
        if !cyclic_objects.is_empty() { risk += 15; }
        if !orphaned_objects.is_empty() { risk += (orphaned_objects.len() as u32 * 2).min(10); }
        if xref_anomalies.iter().any(|a| a.severity >= 7) { risk += 20; }
        if incremental_updates.iter().any(|u| u.is_suspicious) { risk += 20; }
        let risk = risk.min(100);

        GraphAnalysis {
            total_objects,
            reachable_count,
            orphaned_objects,
            cyclic_objects,
            missing_from_xref,
            incremental_updates,
            xref_anomalies,
            type_counts,
            has_javascript,
            has_embedded_files,
            has_launch_actions,
            risk_score: risk,
        }
    }

    fn detect_xref_anomalies(&self) -> Vec<XRefAnomaly> {
        let mut anomalies = Vec::new();

        // Duplicate object numbers in xref.
        let dup_count = self.xref.duplicate_count();
        if dup_count > 0 {
            anomalies.push(XRefAnomaly::new(
                "duplicate_entries",
                format!("{dup_count} duplicate xref entries — incremental update shadowing"),
                vec![],
                7,
            ));
        }

        // Objects with offset=0 but marked in-use (invalid).
        let invalid_offsets: Vec<u32> = self
            .xref
            .entries
            .iter()
            .filter(|e| e.in_use && e.offset == 0 && e.obj_num != 0)
            .map(|e| e.obj_num)
            .collect();
        if !invalid_offsets.is_empty() {
            anomalies.push(XRefAnomaly::new(
                "zero_offset_in_use",
                format!("{} in-use entries with offset=0", invalid_offsets.len()),
                invalid_offsets,
                6,
            ));
        }

        // Very high generation numbers (potential object number recycling attack).
        let high_gen: Vec<u32> = self
            .xref
            .entries
            .iter()
            .filter(|e| e.generation > 100)
            .map(|e| e.obj_num)
            .collect();
        if !high_gen.is_empty() {
            anomalies.push(XRefAnomaly::new(
                "high_generation_numbers",
                format!("{} entries with generation > 100", high_gen.len()),
                high_gen,
                5,
            ));
        }

        // Xref entries with offset pointing past end of file (hypothetical).
        // Without the actual file size here we skip this check.

        anomalies
    }

    fn analyze_incremental_updates(&self) -> Vec<IncrementalUpdate> {
        // Return the pre-populated incremental updates, augmented with suspicion flags.
        let mut updates = self.incremental_updates.clone();
        for update in &mut updates {
            // Suspicious if update modifies the catalog (obj 1 typically).
            if update.modified_objects.contains(&1) {
                update.flag_suspicious("Catalog object modified in incremental update");
            }
            // Suspicious if update modifies an action object.
            for &obj in &update.modified_objects {
                if let Some(node) = self.nodes.get(&obj) {
                    if node.obj_type == ObjectType::Action || node.obj_type == ObjectType::JavaScript {
                        update.flag_suspicious(format!(
                            "Object {} ({}) modified in incremental update",
                            obj, node.obj_type
                        ));
                        break;
                    }
                }
            }
        }
        updates
    }
}

impl Default for PdfObjectGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PdfObjectGraphBuilder ────────────────────────────────────────────────────

/// Builds a `PdfObjectGraph` by parsing raw PDF bytes.
pub struct PdfObjectGraphBuilder;

impl PdfObjectGraphBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build a graph from a raw PDF byte buffer.
    ///
    /// This is a best-effort parser that does not require perfect PDF conformance.
    #[must_use]
    pub fn build(&self, data: &[u8]) -> PdfObjectGraph {
        let mut graph = PdfObjectGraph::new();

        // 1. Parse xref.
        graph.xref = self.parse_xref_table(data);

        // 2. Build nodes from xref.
        for entry in &graph.xref.entries {
            if entry.in_use {
                let obj_ref = ObjectRef::new(entry.obj_num, entry.generation);
                let mut node = GraphNode::new(obj_ref, ObjectType::Unknown, entry.offset);
                node.in_xref = true;
                node.xref_generation = Some(entry.generation);
                graph.nodes.insert(entry.obj_num, node);
            }
        }

        // 3. Scan file for "N G obj" headers and infer types.
        self.scan_object_types(data, &mut graph);

        // 4. Scan for indirect references to build edges.
        self.scan_references(data, &mut graph);

        // 5. Find catalog.
        graph.catalog_ref = self.find_catalog_ref(&graph);

        // 6. Parse incremental updates.
        graph.incremental_updates = self.find_incremental_updates(data, &graph.xref);

        graph
    }

    fn parse_xref_table(&self, data: &[u8]) -> XRefTable {
        let mut table = XRefTable::new();

        // Find all `startxref` occurrences.
        let needle = b"startxref";
        let mut search = 0usize;
        let mut update_index = 0u32;
        loop {
            let found = data[search..].windows(needle.len()).position(|w| w == needle);
            let rel = match found {
                Some(r) => r,
                None => break,
            };
            let abs = search + rel;
            table.startxref_offsets.push(abs as u64);

            // Parse the offset after startxref.
            let after = &data[abs + needle.len()..];
            let skip = after.iter().take_while(|&&b| matches!(b, b'\n' | b'\r' | b' ')).count();
            let num_start = abs + needle.len() + skip;
            let num_len = data[num_start..].iter().take_while(|&&b| b.is_ascii_digit()).count();
            if num_len > 0 {
                if let Ok(s) = std::str::from_utf8(&data[num_start..num_start + num_len]) {
                    if let Ok(off) = s.parse::<usize>() {
                        if off + 4 <= data.len() && &data[off..off + 4] == b"xref" {
                            let is_incremental = update_index > 0;
                            self.parse_single_xref(data, off, is_incremental, update_index, &mut table);
                            table.incremental_sections = update_index + 1;
                        } else if off < data.len() {
                            table.has_xref_stream = true;
                        }
                        update_index += 1;
                    }
                }
            }
            search = abs + needle.len();
        }

        table
    }

    fn parse_single_xref(
        &self,
        data: &[u8],
        start: usize,
        incremental: bool,
        _update_idx: u32,
        table: &mut XRefTable,
    ) {
        let mut pos = start + 4; // skip "xref"
        while pos < data.len() {
            // Skip whitespace.
            while pos < data.len() && matches!(data[pos], b'\n' | b'\r' | b' ' | b'\t') {
                pos += 1;
            }
            // Check for "trailer".
            if pos + 7 <= data.len() && &data[pos..pos + 7] == b"trailer" {
                break;
            }
            if pos >= data.len() { break; }
            // Parse subsection header.
            let line_end = data[pos..].iter().position(|&b| matches!(b, b'\n' | b'\r')).unwrap_or(data.len() - pos);
            let header = std::str::from_utf8(&data[pos..pos + line_end]).unwrap_or("");
            let parts: Vec<&str> = header.split_ascii_whitespace().collect();
            if parts.len() < 2 { break; }
            let first_obj: u32 = parts[0].parse().unwrap_or(0);
            let count: u32 = parts[1].parse().unwrap_or(0);
            pos += line_end + 1;
            // Consume optional \r.
            if pos < data.len() && data[pos] == b'\r' { pos += 1; }

            for i in 0..count {
                if pos + 20 > data.len() { break; }
                let entry = &data[pos..pos + 20];
                if let Ok(s) = std::str::from_utf8(entry) {
                    let ep: Vec<&str> = s.split_ascii_whitespace().collect();
                    if ep.len() >= 3 {
                        let offset: u64 = ep[0].parse().unwrap_or(0);
                        let generation: u16 = ep[1].parse().unwrap_or(0);
                        let in_use = ep[2] == "n";
                        let mut xref_entry = if in_use {
                            XRefEntry::in_use(first_obj + i, generation, offset)
                        } else {
                            XRefEntry::free(first_obj + i, generation)
                        };
                        xref_entry.from_incremental = incremental;
                        table.add(xref_entry);
                    }
                }
                pos += 20;
            }
        }
    }

    fn scan_object_types(&self, data: &[u8], graph: &mut PdfObjectGraph) {
        // Find "N G obj" patterns and infer type from nearby /Type key.
        let mut pos = 0usize;
        while pos + 4 < data.len() {
            let found = data[pos..].windows(4).position(|w| w == b" obj");
            let rel = match found {
                Some(r) => r,
                None => break,
            };
            let abs = pos + rel;
            // Walk back to find the object number.
            let obj_num = self.parse_obj_num_before(data, abs);
            // Look for /Type in the next 512 bytes.
            let scan_end = (abs + 4 + 512).min(data.len());
            let snippet = &data[abs + 4..scan_end];
            let obj_type = self.infer_type_from_snippet(snippet);

            if let Some(node) = graph.nodes.get_mut(&obj_num) {
                if node.obj_type == ObjectType::Unknown {
                    node.obj_type = obj_type;
                }
                if node.file_offset == 0 {
                    node.file_offset = abs as u64;
                }
            } else if obj_num > 0 {
                let obj_ref = ObjectRef::gen0(obj_num);
                let mut node = GraphNode::new(obj_ref, obj_type, abs as u64);
                node.in_xref = graph.xref.get(obj_num).is_some();
                graph.nodes.insert(obj_num, node);
            }

            pos = abs + 4;
        }
    }

    fn parse_obj_num_before(&self, data: &[u8], pos: usize) -> u32 {
        // The pattern is "N G obj" where N and G are numbers.
        // Walk backward from pos to find "N ".
        if pos == 0 { return 0; }
        let mut p = pos;
        // Skip generation number.
        while p > 0 && data[p - 1].is_ascii_digit() { p -= 1; }
        if p > 0 && data[p - 1] == b' ' { p -= 1; }
        // Now skip object number.
        let num_end = p;
        while p > 0 && data[p - 1].is_ascii_digit() { p -= 1; }
        if p == num_end { return 0; }
        std::str::from_utf8(&data[p..num_end]).ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    fn infer_type_from_snippet(&self, snippet: &[u8]) -> ObjectType {
        // Look for /Type /Xxx pattern.
        let type_needle = b"/Type";
        if let Some(tp) = snippet.windows(type_needle.len()).position(|w| w == type_needle) {
            let after = &snippet[tp + type_needle.len()..];
            let skip = after.iter().take_while(|&&b| matches!(b, b' ' | b'\n' | b'\r')).count();
            let rest = &after[skip..];
            if rest.first() == Some(&b'/') {
                let name_end = rest[1..].iter().position(|&b| matches!(b, b' ' | b'\n' | b'/' | b'>'))
                    .unwrap_or(rest.len() - 1);
                let name = std::str::from_utf8(&rest[1..1 + name_end]).unwrap_or("");
                return match name {
                    "Catalog" => ObjectType::Catalog,
                    "Pages" => ObjectType::Pages,
                    "Page" => ObjectType::Page,
                    "Font" => ObjectType::Font,
                    "XObject" => ObjectType::XObject,
                    "Annot" => ObjectType::Annot,
                    "Action" => ObjectType::Action,
                    "JavaScript" => ObjectType::JavaScript,
                    "EmbeddedFile" => ObjectType::EmbeddedFile,
                    _ => ObjectType::Dictionary,
                };
            }
        }
        // Check for stream keyword.
        if snippet.windows(6).any(|w| w == b"stream") {
            return ObjectType::Stream;
        }
        // Check for JavaScript action.
        if snippet.windows(11).any(|w| w == b"/JavaScript") {
            return ObjectType::JavaScript;
        }
        ObjectType::Unknown
    }

    fn scan_references(&self, data: &[u8], graph: &mut PdfObjectGraph) {
        // Scan for "N G R" patterns and build edges.
        // To attribute edges to a source object, we track the last "N G obj" seen.
        let mut current_obj: u32 = 0;
        let mut pos = 0usize;

        while pos + 3 < data.len() {
            // Look for " obj" to track current object context.
            if pos + 4 <= data.len() && &data[pos..pos + 4] == b" obj" {
                current_obj = self.parse_obj_num_before(data, pos);
                pos += 4;
                continue;
            }
            // Look for " R" that terminates an indirect reference.
            if data[pos] == b'R' && pos > 0 && data[pos - 1] == b' ' {
                // Try to parse "N G R" ending at pos.
                if let Some((target_num, target_gen)) = self.parse_ref_ending_at(data, pos) {
                    if current_obj > 0 && target_num > 0 {
                        let from = ObjectRef::gen0(current_obj);
                        let to = ObjectRef::new(target_num, target_gen as u16);
                        graph.add_edge(from, to);
                    }
                }
            }
            pos += 1;
        }
    }

    fn parse_ref_ending_at(&self, data: &[u8], r_pos: usize) -> Option<(u32, u32)> {
        // Pattern: digits SP digits SP R
        // r_pos is the position of 'R', r_pos-1 is ' '.
        if r_pos < 3 { return None; }
        let mut p = r_pos - 1; // ' ' before R
        // Skip the space.
        if data[p] != b' ' { return None; }
        // Parse generation number backward.
        let gen_end = p;
        let mut pg = p;
        while pg > 0 && data[pg - 1].is_ascii_digit() { pg -= 1; }
        if pg == gen_end { return None; }
        let r#gen: u32 = std::str::from_utf8(&data[pg..gen_end]).ok()?.parse().ok()?;
        p = pg;
        if p == 0 || data[p - 1] != b' ' { return None; }
        p -= 1; // space before gen
        // Parse object number backward.
        let num_end = p;
        let mut pn = p;
        while pn > 0 && data[pn - 1].is_ascii_digit() { pn -= 1; }
        if pn == num_end { return None; }
        let num: u32 = std::str::from_utf8(&data[pn..num_end]).ok()?.parse().ok()?;
        Some((num, r#gen))
    }

    fn find_catalog_ref(&self, graph: &PdfObjectGraph) -> Option<ObjectRef> {
        // Catalog is typically object 1 or the Root entry from the trailer.
        for node in graph.nodes.values() {
            if node.obj_type == ObjectType::Catalog {
                return Some(node.obj_ref);
            }
        }
        // Fall back to object 1.
        if graph.nodes.contains_key(&1) {
            return Some(ObjectRef::gen0(1));
        }
        None
    }

    fn find_incremental_updates(&self, data: &[u8], xref: &XRefTable) -> Vec<IncrementalUpdate> {
        let mut updates = Vec::new();
        for (i, &offset) in xref.startxref_offsets.iter().enumerate() {
            // For each startxref beyond the first, build an incremental update record.
            // Collect objects that appear to belong to this section by xref entry ordering.
            let modified: Vec<u32> = xref
                .entries
                .iter()
                .enumerate()
                .filter(|(j, e)| {
                    // Heuristic: assign entries roughly by section order.
                    let section = (*j as u32) / (xref.entries.len().max(1) as u32 / (xref.incremental_sections.max(1)));
                    e.in_use && section == i as u32 && e.from_incremental
                })
                .map(|(_, e)| e.obj_num)
                .collect();

            updates.push(IncrementalUpdate::new(i as u32, offset, modified));
        }
        let _ = data; // used implicitly via xref
        updates
    }
}

impl Default for PdfObjectGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_ref_display() {
        let r = ObjectRef::new(5, 0);
        assert_eq!(r.to_string(), "5 0 R");
    }

    #[test]
    fn test_graph_add_edge() {
        let mut graph = PdfObjectGraph::new();
        let a = ObjectRef::gen0(1);
        let b = ObjectRef::gen0(2);
        graph.add_edge(a, b);
        assert_eq!(graph.get_node(1).unwrap().outgoing.len(), 1);
        assert_eq!(graph.get_node(2).unwrap().incoming.len(), 1);
    }

    #[test]
    fn test_mark_reachable() {
        let mut graph = PdfObjectGraph::new();
        let a = ObjectRef::gen0(1);
        let b = ObjectRef::gen0(2);
        graph.add_edge(a, b);
        graph.catalog_ref = Some(a);
        graph.mark_reachable();
        assert!(graph.get_node(1).unwrap().reachable);
        assert!(graph.get_node(2).unwrap().reachable);
    }

    #[test]
    fn test_detect_cycles() {
        let mut graph = PdfObjectGraph::new();
        // 1 -> 2 -> 3 -> 1 (cycle)
        graph.add_edge(ObjectRef::gen0(1), ObjectRef::gen0(2));
        graph.add_edge(ObjectRef::gen0(2), ObjectRef::gen0(3));
        graph.add_edge(ObjectRef::gen0(3), ObjectRef::gen0(1));
        graph.detect_cycles();
        let cyclic = graph.cyclic_nodes();
        assert_eq!(cyclic.len(), 3);
    }

    #[test]
    fn test_no_cycles_linear() {
        let mut graph = PdfObjectGraph::new();
        graph.add_edge(ObjectRef::gen0(1), ObjectRef::gen0(2));
        graph.add_edge(ObjectRef::gen0(2), ObjectRef::gen0(3));
        graph.detect_cycles();
        assert!(graph.cyclic_nodes().is_empty());
    }

    #[test]
    fn test_orphaned_detection() {
        let mut graph = PdfObjectGraph::new();
        let node1 = GraphNode {
            obj_ref: ObjectRef::gen0(1),
            obj_type: ObjectType::Catalog,
            outgoing: vec![],
            incoming: vec![],
            in_xref: true,
            reachable: true,
            file_offset: 0,
            in_cycle: false,
            xref_generation: Some(0),
        };
        let node2 = GraphNode {
            obj_ref: ObjectRef::gen0(99),
            obj_type: ObjectType::Unknown,
            outgoing: vec![],
            incoming: vec![],
            in_xref: true,
            reachable: false,
            file_offset: 0,
            in_cycle: false,
            xref_generation: Some(0),
        };
        graph.upsert_node(node1);
        graph.upsert_node(node2);
        let orphaned = graph.orphaned();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].obj_ref.obj_num, 99);
    }

    #[test]
    fn test_xref_table_duplicate_count() {
        let mut table = XRefTable::new();
        table.add(XRefEntry::in_use(5, 0, 100));
        table.add(XRefEntry::in_use(5, 1, 200));
        assert_eq!(table.duplicate_count(), 1);
    }

    #[test]
    fn test_builder_minimal_pdf() {
        let data = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nxref\n0 2\n0000000000 65535 f \r\n0000000009 00000 n \r\ntrailer\n<<>>\nstartxref\n20\n%%EOF\n";
        let builder = PdfObjectGraphBuilder::new();
        let mut graph = builder.build(data);
        let analysis = graph.analyze();
        assert!(analysis.total_objects >= 1);
    }

    #[test]
    fn test_object_type_display() {
        assert_eq!(ObjectType::Catalog.to_string(), "Catalog");
        assert_eq!(ObjectType::JavaScript.to_string(), "JavaScript");
    }
}
