//! .NET assembly merger.
//!
//! Provides `AssemblyMerger` which analyses conflict scenarios between a set
//! of .NET assemblies and produces a `MergeReport` describing how conflicts
//! should be resolved, dependency ordering, and a list of types to merge or
//! skip.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// ConflictType / ConflictResolution
// ---------------------------------------------------------------------------

/// The kind of naming or signature conflict encountered during a merge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConflictType {
    /// Two assemblies define a type with the same fully-qualified name.
    TypeNameCollision,
    /// Two assemblies define a method with the same signature in a shared type.
    MethodSignatureCollision,
    /// Two assemblies embed a resource with the same name.
    ResourceNameCollision,
}

impl ConflictType {
    /// Returns a short description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::TypeNameCollision => "type name collision",
            Self::MethodSignatureCollision => "method signature collision",
            Self::ResourceNameCollision => "resource name collision",
        }
    }
}

/// How a detected conflict should be handled.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConflictResolution {
    /// Rename the conflicting entity from the secondary assembly.
    Rename,
    /// Override (replace) the primary's entity with the secondary's version.
    Override,
    /// Skip the conflicting entity from the secondary assembly.
    Skip,
    /// Abort the merge with an error.
    Error,
}

impl ConflictResolution {
    /// Returns `true` if this resolution prevents merging.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Error)
    }
}

// ---------------------------------------------------------------------------
// MergeConflict
// ---------------------------------------------------------------------------

/// A single conflict detected between two assemblies being merged.
#[derive(Debug, Clone)]
pub struct MergeConflict {
    /// What kind of conflict this is.
    pub conflict_type: ConflictType,
    /// Human-readable description (includes the conflicting names).
    pub description: String,
    /// Suggested resolution.
    pub resolution: ConflictResolution,
    /// The name of the primary assembly involved.
    pub primary_assembly: String,
    /// The name of the secondary (merged-in) assembly involved.
    pub secondary_assembly: String,
}

impl MergeConflict {
    /// Create a new `MergeConflict`.
    pub fn new(
        conflict_type: ConflictType,
        description: impl Into<String>,
        resolution: ConflictResolution,
        primary: impl Into<String>,
        secondary: impl Into<String>,
    ) -> Self {
        Self {
            conflict_type,
            description: description.into(),
            resolution,
            primary_assembly: primary.into(),
            secondary_assembly: secondary.into(),
        }
    }

    /// Returns `true` if the conflict is fatal (will abort the merge).
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.resolution.is_fatal()
    }
}

// ---------------------------------------------------------------------------
// AssemblyInfo
// ---------------------------------------------------------------------------

/// Metadata about a single .NET assembly relevant to merging.
#[derive(Debug, Clone)]
pub struct AssemblyInfo {
    /// Simple assembly name (no extension).
    pub name: String,
    /// All type names defined in this assembly (fully qualified).
    pub types: Vec<String>,
    /// Types exported by this assembly.
    pub exported_types: Vec<String>,
    /// Embedded resource names.
    pub resources: Vec<String>,
    /// Assembly references (names of assemblies this one depends on).
    pub references: Vec<String>,
}

impl AssemblyInfo {
    /// Create a new `AssemblyInfo`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            types: Vec::new(),
            exported_types: Vec::new(),
            resources: Vec::new(),
            references: Vec::new(),
        }
    }

    /// Returns `true` if this assembly defines the given type name.
    #[must_use]
    pub fn defines_type(&self, type_name: &str) -> bool {
        self.types.iter().any(|t| t == type_name)
    }

    /// Returns `true` if this assembly has a resource with the given name.
    #[must_use]
    pub fn has_resource(&self, name: &str) -> bool {
        self.resources.iter().any(|r| r == name)
    }
}

// ---------------------------------------------------------------------------
// MergeConfig
// ---------------------------------------------------------------------------

/// Configuration for an assembly merge operation.
#[derive(Debug, Clone)]
pub struct MergeConfig {
    /// Name of the output (merged) assembly.
    pub output_name: String,
    /// Name of the primary (main) assembly.
    pub main_assembly: String,
    /// Names of secondary assemblies to merge in.
    pub merge_assemblies: Vec<String>,
    /// If `true`, make all merged types `internal` (hide from external consumers).
    pub internalize: bool,
    /// Default resolution to apply when a conflict is detected.
    pub default_resolution: ConflictResolution,
}

impl MergeConfig {
    /// Create a new `MergeConfig`.
    pub fn new(output_name: impl Into<String>, main_assembly: impl Into<String>) -> Self {
        Self {
            output_name: output_name.into(),
            main_assembly: main_assembly.into(),
            merge_assemblies: Vec::new(),
            internalize: false,
            default_resolution: ConflictResolution::Skip,
        }
    }

    /// Add a secondary assembly to merge.
    pub fn add_merge(mut self, assembly: impl Into<String>) -> Self {
        self.merge_assemblies.push(assembly.into());
        self
    }

    /// Enable internalisation of merged types.
    #[must_use]
    pub const fn with_internalize(mut self) -> Self {
        self.internalize = true;
        self
    }
}

// ---------------------------------------------------------------------------
// MergeReport
// ---------------------------------------------------------------------------

/// Summary of a merge analysis.
#[derive(Debug, Clone, Default)]
pub struct MergeReport {
    /// Number of conflicts detected.
    pub conflicts: u32,
    /// Number of conflicts resolved.
    pub resolutions: u32,
    /// Number of types that will be merged.
    pub merged_types: u32,
    /// Number of types that will be skipped due to conflicts.
    pub skipped_types: u32,
    /// Number of renamed types.
    pub renamed_types: u32,
    /// Topologically-sorted merge order (assembly names).
    pub merge_order: Vec<String>,
    /// Whether the merge can proceed without fatal errors.
    pub can_proceed: bool,
}

impl MergeReport {
    /// Returns `true` if there are no fatal conflicts.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.can_proceed
    }

    /// Returns a one-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "conflicts={} resolved={} merged_types={} skipped={} renamed={}",
            self.conflicts,
            self.resolutions,
            self.merged_types,
            self.skipped_types,
            self.renamed_types
        )
    }
}

// ---------------------------------------------------------------------------
// AssemblyMerger
// ---------------------------------------------------------------------------

/// Analyses and plans a .NET assembly merge operation.
///
/// The actual byte-level merging is left to a downstream step; this module
/// handles conflict detection, resolution planning, and dependency ordering.
pub struct AssemblyMerger {
    /// All assemblies known to the merger.
    assemblies: HashMap<String, AssemblyInfo>,
    /// The merge configuration.
    config: MergeConfig,
}

impl AssemblyMerger {
    /// Create a new `AssemblyMerger`.
    #[must_use]
    pub fn new(config: MergeConfig) -> Self {
        Self {
            assemblies: HashMap::new(),
            config,
        }
    }

    /// Register an assembly's metadata.
    pub fn register_assembly(&mut self, info: AssemblyInfo) {
        self.assemblies.insert(info.name.clone(), info);
    }

    /// Returns the number of registered assemblies.
    #[must_use]
    pub fn assembly_count(&self) -> usize {
        self.assemblies.len()
    }

    // -- conflict detection -------------------------------------------------

    /// Detect all conflicts between the primary assembly and each secondary.
    #[must_use]
    pub fn detect_conflicts(&self) -> Vec<MergeConflict> {
        let mut conflicts = Vec::new();
        let primary_name = &self.config.main_assembly;
        let Some(primary) = self.assemblies.get(primary_name) else { return conflicts };
        for secondary_name in &self.config.merge_assemblies {
            let Some(secondary) = self.assemblies.get(secondary_name) else { continue };
            for type_name in &secondary.types {
                if primary.defines_type(type_name) {
                    conflicts.push(MergeConflict::new(
                        ConflictType::TypeNameCollision,
                        format!(
                            "Type '{type_name}' exists in both '{primary_name}' and '{secondary_name}'"
                        ),
                        self.config.default_resolution.clone(),
                        primary_name.clone(),
                        secondary_name.clone(),
                    ));
                }
            }

            // Resource name collisions
            for res in &secondary.resources {
                if primary.has_resource(res) {
                    conflicts.push(MergeConflict::new(
                        ConflictType::ResourceNameCollision,
                        format!(
                            "Resource '{res}' exists in both '{primary_name}' and '{secondary_name}'"
                        ),
                        self.config.default_resolution.clone(),
                        primary_name.clone(),
                        secondary_name.clone(),
                    ));
                }
            }

            // Also check collisions between secondaries
            for other_secondary_name in &self.config.merge_assemblies {
                if other_secondary_name == secondary_name {
                    continue;
                }
                let Some(other) = self.assemblies.get(other_secondary_name) else { continue };
                for type_name in &secondary.types {
                    if other.defines_type(type_name) {
                        let desc = format!(
                            "Type '{type_name}' exists in both '{secondary_name}' and '{other_secondary_name}'"
                        );
                        // Avoid duplicate entries
                        if !conflicts.iter().any(|c| c.description == desc) {
                            conflicts.push(MergeConflict::new(
                                ConflictType::TypeNameCollision,
                                desc,
                                self.config.default_resolution.clone(),
                                secondary_name.clone(),
                                other_secondary_name.clone(),
                            ));
                        }
                    }
                }
            }
        }
        conflicts
    }

    /// Resolve a list of conflicts, optionally overriding the default resolution
    /// for specific conflict types.
    ///
    /// Returns pairs of `(conflict, chosen_resolution)`.
    #[must_use]
    pub fn resolve_conflicts(
        &self,
        conflicts: &[MergeConflict],
        override_map: &HashMap<ConflictType, ConflictResolution>,
    ) -> Vec<(MergeConflict, ConflictResolution)> {
        conflicts
            .iter()
            .map(|c| {
                let resolution = override_map
                    .get(&c.conflict_type)
                    .cloned()
                    .unwrap_or_else(|| c.resolution.clone());
                (c.clone(), resolution)
            })
            .collect()
    }

    // -- dependency ordering -----------------------------------------------

    /// Compute a topological merge order based on assembly references.
    ///
    /// The primary assembly is always last; secondary assemblies are sorted so
    /// that if A references B, B is merged first.
    ///
    /// Returns `Err(cycle)` if a dependency cycle is detected.
    pub fn compute_merge_order(&self) -> Result<Vec<String>, String> {
        // Build a subgraph of just the assemblies involved in this merge
        let all_names: HashSet<String> = {
            let mut s: HashSet<String> = self.config.merge_assemblies.iter().cloned().collect();
            s.insert(self.config.main_assembly.clone());
            s
        };

        // Build adjacency: "depends on" edges
        let mut in_degree: HashMap<String, usize> = all_names.iter().map(|n| (n.clone(), 0)).collect();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for name in &all_names {
            if let Some(info) = self.assemblies.get(name) {
                for dep in &info.references {
                    if all_names.contains(dep) {
                        // `name` depends on `dep` so `dep` must come first
                        dependents.entry(dep.clone()).or_default().push(name.clone());
                        *in_degree.entry(name.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Kahn's algorithm
        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(n, _)| n.clone())
            .collect();

        // Ensure deterministic ordering
        queue.make_contiguous().sort();

        let mut order: Vec<String> = Vec::new();
        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            if let Some(nexts) = dependents.get(&node) {
                let mut nexts_sorted: Vec<&String> = nexts.iter().collect();
                nexts_sorted.sort();
                for next in nexts_sorted {
                    let next = next.clone();
                    let deg = in_degree.get_mut(&next).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(next);
                    }
                }
            }
        }

        if order.len() != all_names.len() {
            return Err("dependency cycle detected among assemblies".to_owned());
        }

        // The primary assembly must be last
        order.retain(|n| n != &self.config.main_assembly);
        order.push(self.config.main_assembly.clone());
        Ok(order)
    }

    // -- full merge analysis -----------------------------------------------

    /// Run the full merge analysis and produce a `MergeReport`.
    #[must_use]
    pub fn analyse(&self) -> MergeReport {
        let conflicts = self.detect_conflicts();
        let override_map: HashMap<ConflictType, ConflictResolution> = HashMap::new();
        let resolutions = self.resolve_conflicts(&conflicts, &override_map);

        let can_proceed = !resolutions.iter().any(|(_, r)| r.is_fatal());

        let mut merged_types = 0u32;
        let mut skipped_types = 0u32;
        let mut renamed_types = 0u32;

        for (conflict, resolution) in &resolutions {
            if conflict.conflict_type == ConflictType::TypeNameCollision {
                match resolution {
                    ConflictResolution::Skip => skipped_types += 1,
                    ConflictResolution::Rename => renamed_types += 1,
                    ConflictResolution::Override => merged_types += 1,
                    ConflictResolution::Error => {}
                }
            }
        }

        // Count merged types (secondary types without conflict)
        for secondary_name in &self.config.merge_assemblies {
            if let Some(sec) = self.assemblies.get(secondary_name) {
                let conflicting: HashSet<String> = conflicts
                    .iter()
                    .filter(|c| {
                        c.conflict_type == ConflictType::TypeNameCollision
                            && c.secondary_assembly == *secondary_name
                    })
                    .filter_map(|c| c.description.split('\'').nth(1).map(std::borrow::ToOwned::to_owned))
                    .collect();
                for t in &sec.types {
                    if !conflicting.contains(t) {
                        merged_types += 1;
                    }
                }
            }
        }

        let merge_order = self.compute_merge_order().unwrap_or_default();

        MergeReport {
            conflicts: conflicts.len() as u32,
            resolutions: resolutions.len() as u32,
            merged_types,
            skipped_types,
            renamed_types,
            merge_order,
            can_proceed,
        }
    }

    /// Generate a suggested output name for a renamed conflicting type.
    ///
    /// Convention: `<SecondaryAssemblyName>_<TypeName>`.
    #[must_use]
    pub fn suggested_rename(secondary_name: &str, type_name: &str) -> String {
        let prefix = secondary_name
            .split('.')
            .next_back()
            .unwrap_or(secondary_name);
        format!("{prefix}_{type_name}")
    }

    /// Returns all type names that can be safely merged (no conflicts).
    #[must_use]
    pub fn safe_merge_types(&self) -> Vec<String> {
        let conflicts = self.detect_conflicts();
        let conflicting: HashSet<String> = conflicts
            .iter()
            .filter(|c| c.conflict_type == ConflictType::TypeNameCollision)
            .filter_map(|c| {
                // Extract type name from description: "Type 'X' exists in both ..."
                c.description
                    .split('\'')
                    .nth(1)
                    .map(std::borrow::ToOwned::to_owned)
            })
            .collect();

        let mut safe = Vec::new();
        for name in &self.config.merge_assemblies {
            if let Some(info) = self.assemblies.get(name) {
                for t in &info.types {
                    if !conflicting.contains(t) {
                        safe.push(t.clone());
                    }
                }
            }
        }
        safe.sort();
        safe
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_primary() -> AssemblyInfo {
        let mut a = AssemblyInfo::new("Primary");
        a.types = vec!["Ns.TypeA".to_owned(), "Ns.TypeB".to_owned()];
        a.resources = vec!["logo.png".to_owned()];
        a.references = vec![];
        a
    }

    fn make_secondary(name: &str, types: Vec<&str>, refs: Vec<&str>) -> AssemblyInfo {
        let mut a = AssemblyInfo::new(name);
        a.types = types.into_iter().map(std::borrow::ToOwned::to_owned).collect();
        a.references = refs.into_iter().map(std::borrow::ToOwned::to_owned).collect();
        a
    }

    fn config() -> MergeConfig {
        MergeConfig::new("Output", "Primary")
            .add_merge("Secondary1")
            .add_merge("Secondary2")
    }

    #[test]
    fn test_no_conflicts() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeC"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec!["Ns.TypeD"], vec![]));
        let conflicts = merger.detect_conflicts();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_type_collision_detected() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeA"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec!["Ns.TypeX"], vec![]));
        let conflicts = merger.detect_conflicts();
        assert!(conflicts.iter().any(|c| c.conflict_type == ConflictType::TypeNameCollision));
    }

    #[test]
    fn test_resource_collision_detected() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        let mut sec = make_secondary("Secondary1", vec![], vec![]);
        sec.resources = vec!["logo.png".to_owned()];
        merger.register_assembly(sec);
        merger.register_assembly(make_secondary("Secondary2", vec![], vec![]));
        let conflicts = merger.detect_conflicts();
        assert!(conflicts.iter().any(|c| c.conflict_type == ConflictType::ResourceNameCollision));
    }

    #[test]
    fn test_resolve_with_override_map() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeA"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec![], vec![]));
        let conflicts = merger.detect_conflicts();
        let mut override_map = HashMap::new();
        override_map.insert(ConflictType::TypeNameCollision, ConflictResolution::Rename);
        let resolved = merger.resolve_conflicts(&conflicts, &override_map);
        assert!(resolved.iter().all(|(_, r)| *r == ConflictResolution::Rename));
    }

    #[test]
    fn test_merge_order_no_deps() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec![], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec![], vec![]));
        let order = merger.compute_merge_order().unwrap();
        assert_eq!(order.last().unwrap(), "Primary");
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn test_merge_order_with_deps() {
        let cfg = MergeConfig::new("Out", "Main")
            .add_merge("Lib1")
            .add_merge("Lib2");
        let mut merger = AssemblyMerger::new(cfg);
        merger.register_assembly(make_primary()); // named "Primary" - not in this config
        let mut main = AssemblyInfo::new("Main");
        main.references = vec!["Lib1".to_owned()];
        merger.register_assembly(main);
        let mut lib1 = AssemblyInfo::new("Lib1");
        lib1.references = vec!["Lib2".to_owned()];
        merger.register_assembly(lib1);
        merger.register_assembly(make_secondary("Lib2", vec![], vec![]));
        let order = merger.compute_merge_order().unwrap();
        // Lib2 -> Lib1 -> Main
        let lib2_pos = order.iter().position(|s| s == "Lib2").unwrap();
        let lib1_pos = order.iter().position(|s| s == "Lib1").unwrap();
        let main_pos = order.iter().position(|s| s == "Main").unwrap();
        assert!(lib2_pos < lib1_pos);
        assert!(lib1_pos < main_pos);
    }

    #[test]
    fn test_analyse_can_proceed() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeC"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec!["Ns.TypeD"], vec![]));
        let report = merger.analyse();
        assert!(report.can_proceed);
    }

    #[test]
    fn test_analyse_counts_merged_types() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeC", "Ns.TypeD"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec!["Ns.TypeE"], vec![]));
        let report = merger.analyse();
        assert!(report.merged_types >= 3);
    }

    #[test]
    fn test_safe_merge_types_excludes_conflicts() {
        let mut merger = AssemblyMerger::new(config());
        merger.register_assembly(make_primary());
        merger.register_assembly(make_secondary("Secondary1", vec!["Ns.TypeA", "Ns.TypeC"], vec![]));
        merger.register_assembly(make_secondary("Secondary2", vec!["Ns.TypeD"], vec![]));
        let safe = merger.safe_merge_types();
        assert!(safe.contains(&"Ns.TypeC".to_owned()));
        assert!(safe.contains(&"Ns.TypeD".to_owned()));
        assert!(!safe.contains(&"Ns.TypeA".to_owned()));
    }

    #[test]
    fn test_suggested_rename() {
        let name = AssemblyMerger::suggested_rename("My.Company.Utils", "Logger");
        assert_eq!(name, "Utils_Logger");
    }

    #[test]
    fn test_assembly_info_defines_type() {
        let mut a = AssemblyInfo::new("A");
        a.types = vec!["Foo.Bar".to_owned()];
        assert!(a.defines_type("Foo.Bar"));
        assert!(!a.defines_type("Foo.Baz"));
    }

    #[test]
    fn test_assembly_info_has_resource() {
        let mut a = AssemblyInfo::new("A");
        a.resources = vec!["icon.ico".to_owned()];
        assert!(a.has_resource("icon.ico"));
        assert!(!a.has_resource("splash.png"));
    }

    #[test]
    fn test_conflict_type_description() {
        assert!(!ConflictType::TypeNameCollision.description().is_empty());
        assert!(!ConflictType::ResourceNameCollision.description().is_empty());
    }

    #[test]
    fn test_conflict_resolution_is_fatal() {
        assert!(ConflictResolution::Error.is_fatal());
        assert!(!ConflictResolution::Skip.is_fatal());
        assert!(!ConflictResolution::Rename.is_fatal());
        assert!(!ConflictResolution::Override.is_fatal());
    }

    #[test]
    fn test_merge_report_summary_contains_fields() {
        let report = MergeReport {
            conflicts: 2,
            resolutions: 2,
            merged_types: 10,
            skipped_types: 1,
            renamed_types: 1,
            merge_order: vec!["A".to_owned(), "B".to_owned()],
            can_proceed: true,
        };
        let s = report.summary();
        assert!(s.contains("conflicts=2"));
        assert!(s.contains("merged_types=10"));
    }
}