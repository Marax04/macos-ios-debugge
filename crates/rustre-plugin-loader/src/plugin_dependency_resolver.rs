// rustre-plugin-loader/src/plugin_dependency_resolver.rs
//
// Dependency resolution for RustRE plugins.  Builds a directed acyclic graph
// of plugin dependencies and produces a topologically-sorted load order.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::plugin_version_checker::{SemanticVersion, VersionSpec};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur during dependency resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A dependency named in a plugin's manifest was never registered.
    Missing { plugin: String, dep: String },
    /// The dependency graph contains a cycle.
    Cycle(Vec<String>),
    /// A required version range is not satisfied by the available version.
    VersionMismatch {
        plugin: String,
        dep: String,
        required: String,
        found: String,
    },
    /// An optional dependency was requested but the feature is disabled.
    OptionalUnavailable { plugin: String, dep: String },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { plugin, dep } => {
                write!(f, "plugin '{plugin}' requires missing dependency '{dep}'")
            }
            Self::Cycle(path) => write!(f, "dependency cycle: {}", path.join(" -> ")),
            Self::VersionMismatch {
                plugin,
                dep,
                required,
                found,
            } => write!(
                f,
                "plugin '{plugin}' requires '{dep} {required}' but found '{found}'"
            ),
            Self::OptionalUnavailable { plugin, dep } => {
                write!(
                    f,
                    "optional dependency '{dep}' for plugin '{plugin}' is not available"
                )
            }
        }
    }
}

impl std::error::Error for ResolveError {}

// ── Dependency ────────────────────────────────────────────────────────────────

/// A single dependency declaration inside a plugin's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Name of the plugin this entry depends on.
    pub name: String,
    /// Semver-style version requirement, e.g. `">=0.2.0"` or `"^1.0"`.
    pub version_req: String,
    /// When `true` the dependency is loaded opportunistically; a missing
    /// dependency does not cause resolution to fail.
    pub optional: bool,
    /// Feature flags that must be enabled in the dependency.
    pub required_features: Vec<String>,
}

impl Dependency {
    /// Construct a required dependency with an exact version requirement.
    #[must_use]
    pub fn required(name: impl Into<String>, version_req: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version_req: version_req.into(),
            optional: false,
            required_features: Vec::new(),
        }
    }

    /// Construct an optional dependency.
    #[must_use]
    pub fn optional(name: impl Into<String>, version_req: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version_req: version_req.into(),
            optional: true,
            required_features: Vec::new(),
        }
    }

    /// Add a required feature flag.
    #[must_use]
    pub fn with_feature(mut self, feat: impl Into<String>) -> Self {
        self.required_features.push(feat.into());
        self
    }
}

impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opt_tag = if self.optional { " (optional)" } else { "" };
        write!(f, "{} {}{opt_tag}", self.name, self.version_req)
    }
}

// ── DepGraph ──────────────────────────────────────────────────────────────────

/// Directed graph of plugin identifiers and their declared dependencies.
///
/// Nodes are plugin names; edges run from a plugin to each of its
/// dependencies (the things it needs to be loaded *before* itself).
#[derive(Debug, Default)]
pub struct DepGraph {
    /// Adjacency list: plugin name → list of dependency names it declares.
    edges: HashMap<String, Vec<Dependency>>,
    /// Known plugin versions registered with the graph.
    versions: HashMap<String, String>,
    /// Feature flags advertised by each plugin.
    features: HashMap<String, HashSet<String>>,
}

impl DepGraph {
    /// Create an empty dependency graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin with its version string.
    ///
    /// Subsequent calls with the same name update the version and reset the
    /// dependency list.
    pub fn register_plugin(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) {
        let name = name.into();
        self.versions.insert(name.clone(), version.into());
        self.edges.entry(name).or_default();
    }

    /// Advertise that plugin `name` provides a set of feature flags.
    pub fn set_features(
        &mut self,
        name: impl Into<String>,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) {
        let set: HashSet<String> = features.into_iter().map(Into::into).collect();
        self.features.insert(name.into(), set);
    }

    /// Add a dependency edge from `plugin` → `dep`.
    ///
    /// Both `plugin` and `dep` must have been registered first via
    /// [`register_plugin`]; however this method will insert missing nodes so
    /// that the graph can be built incrementally.
    pub fn add_dependency(&mut self, plugin: impl Into<String>, dep: Dependency) {
        self.edges.entry(plugin.into()).or_default().push(dep);
    }

    /// Return the direct dependencies of `plugin`.
    #[must_use]
    pub fn dependencies_of(&self, plugin: &str) -> &[Dependency] {
        self.edges
            .get(plugin)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return the registered version of `plugin`, or `None` if unknown.
    #[must_use]
    pub fn version_of(&self, plugin: &str) -> Option<&str> {
        self.versions.get(plugin).map(String::as_str)
    }

    /// Whether the graph contains a registration for `plugin`.
    #[must_use]
    pub fn contains(&self, plugin: &str) -> bool {
        self.edges.contains_key(plugin)
    }

    /// Return all registered plugin names.
    #[must_use]
    pub fn plugin_names(&self) -> Vec<&str> {
        self.edges.keys().map(String::as_str).collect()
    }

    /// Total number of nodes (registered plugins).
    #[must_use]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Return all transitive dependencies of `start`, including `start` itself.
    #[must_use]
    pub fn transitive_deps(&self, start: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(start.to_string());

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            for dep in self.dependencies_of(&current) {
                if !visited.contains(&dep.name) {
                    queue.push_back(dep.name.clone());
                }
            }
        }
        visited.into_iter().collect()
    }
}

// ── Version matching ──────────────────────────────────────────────────────────

/// Check whether `found` satisfies `requirement`.
///
/// Delegates to [`VersionSpec`] and [`SemanticVersion`] from
/// [`crate::plugin_version_checker`] so that all version parsing and
/// comparison logic lives in one place.
fn version_satisfies(requirement: &str, found: &str) -> bool {
    let Some(spec) = VersionSpec::parse(requirement) else {
        return false;
    };
    let Some(candidate) = SemanticVersion::parse(found) else {
        return false;
    };
    spec.matches(&candidate)
}

// ── PluginDependencyResolver ──────────────────────────────────────────────────

/// Resolves plugin load order and validates all version constraints.
///
/// # Usage
///
/// ```
/// use rustre_plugin_loader::plugin_dependency_resolver::{
///     DepGraph, Dependency, PluginDependencyResolver,
/// };
///
/// let mut graph = DepGraph::new();
/// graph.register_plugin("core", "1.0.0");
/// graph.register_plugin("pe-loader", "0.2.0");
/// graph.add_dependency("pe-loader", Dependency::required("core", ">=1.0.0"));
///
/// let resolver = PluginDependencyResolver::new(graph);
/// let order = resolver.resolve_order().expect("should resolve");
/// assert!(order.iter().position(|n| n == "core")
///     < order.iter().position(|n| n == "pe-loader"));
/// ```
#[derive(Debug)]
pub struct PluginDependencyResolver {
    graph: DepGraph,
    /// When `true`, optional dependencies that are unavailable are silently
    /// skipped; when `false` they produce an `OptionalUnavailable` error.
    pub strict_optional: bool,
}

impl PluginDependencyResolver {
    /// Create a new resolver from a pre-built [`DepGraph`].
    #[must_use]
    pub fn new(graph: DepGraph) -> Self {
        Self {
            graph,
            strict_optional: false,
        }
    }

    /// Create a resolver and immediately validate + sort the given plugins.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] if any constraint is violated.
    pub fn from_plugins<I, S>(plugins: I) -> Result<(Self, Vec<String>), ResolveError>
    where
        I: IntoIterator<Item = (S, S, Vec<Dependency>)>,
        S: Into<String>,
    {
        let mut graph = DepGraph::new();
        for (name, version, deps) in plugins {
            let n = name.into();
            let v = version.into();
            graph.register_plugin(n.clone(), v);
            for dep in deps {
                graph.add_dependency(n.clone(), dep);
            }
        }
        let resolver = Self::new(graph);
        let order = resolver.resolve_order()?;
        Ok((resolver, order))
    }

    /// Return a reference to the underlying graph.
    #[must_use]
    pub const fn graph(&self) -> &DepGraph {
        &self.graph
    }

    /// Validate all dependency edges and return a topologically-sorted load
    /// order (dependencies appear before the plugins that need them).
    ///
    /// # Errors
    ///
    /// - [`ResolveError::Missing`] when a required dependency is not registered.
    /// - [`ResolveError::VersionMismatch`] when the registered version does not
    ///   satisfy the declared requirement.
    /// - [`ResolveError::Cycle`] when the graph contains a dependency cycle.
    /// - [`ResolveError::OptionalUnavailable`] when `strict_optional` is set
    ///   and an optional dependency is absent.
    pub fn resolve_order(&self) -> Result<Vec<String>, ResolveError> {
        // Phase 1: validate all declared constraints.
        self.validate_constraints()?;

        // Phase 2: topological sort (Kahn's algorithm).
        // in_degree[P] counts the number of *prerequisites* of P that have not
        // yet been emitted.  A node with in_degree == 0 is ready to be placed
        // in the output (all its dependencies have already been emitted).
        let names = self.graph.plugin_names();
        let mut in_degree: HashMap<&str, usize> = names.iter().map(|n| (*n, 0)).collect();

        for plugin in &names {
            for dep in self.graph.dependencies_of(plugin) {
                if !dep.optional || self.graph.contains(&dep.name) {
                    // `plugin` has one more unsatisfied prerequisite.
                    if let Some(cnt) = in_degree.get_mut(*plugin) {
                        *cnt += 1;
                    }
                }
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(n, _)| (*n).to_string())
            .collect();

        let mut order: Vec<String> = Vec::with_capacity(names.len());

        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            // All plugins that depend on `node` lose one in-edge.
            for plugin in &names {
                let deps = self.graph.dependencies_of(plugin);
                for dep in deps {
                    if dep.name == node {
                        if let Some(cnt) = in_degree.get_mut(plugin) {
                            *cnt = cnt.saturating_sub(1);
                            if *cnt == 0 {
                                queue.push_back((*plugin).to_string());
                            }
                        }
                    }
                }
            }
        }

        if order.len() < names.len() {
            // Cycle detected — find it.
            let visited: HashSet<&str> = order.iter().map(String::as_str).collect();
            let cycle_start = names
                .iter()
                .find(|n| !visited.contains(*n))
                .map(|s| (*s).to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let path = self.trace_cycle(&cycle_start);
            return Err(ResolveError::Cycle(path));
        }

        Ok(order)
    }

    /// Validate version constraints and presence of all required deps without
    /// computing load order.
    ///
    /// # Errors
    ///
    /// See [`resolve_order`](Self::resolve_order) for a list of possible errors.
    pub fn validate_constraints(&self) -> Result<(), ResolveError> {
        for plugin in self.graph.plugin_names() {
            for dep in self.graph.dependencies_of(plugin) {
                let available = self.graph.contains(&dep.name);

                if !available {
                    if dep.optional {
                        if self.strict_optional {
                            return Err(ResolveError::OptionalUnavailable {
                                plugin: plugin.to_string(),
                                dep: dep.name.clone(),
                            });
                        }
                        // Skip optional, unavailable dep.
                        continue;
                    }
                    return Err(ResolveError::Missing {
                        plugin: plugin.to_string(),
                        dep: dep.name.clone(),
                    });
                }

                // Version check.  A plugin registered via `add_dependency`
                // without a matching `register_plugin` call has no version
                // entry; treat that as a missing-version mismatch rather than
                // silently accepting it.
                match self.graph.version_of(&dep.name) {
                    Some(found_ver) => {
                        if !version_satisfies(&dep.version_req, found_ver) {
                            return Err(ResolveError::VersionMismatch {
                                plugin: plugin.to_string(),
                                dep: dep.name.clone(),
                                required: dep.version_req.clone(),
                                found: found_ver.to_string(),
                            });
                        }
                    }
                    None => {
                        // The dependency node exists in `edges` (so `contains`
                        // returned true above) but was never registered with a
                        // version via `register_plugin`.  Treat this as a
                        // version mismatch with an unknown found-version so the
                        // caller sees an explicit error rather than a silent
                        // pass-through.
                        return Err(ResolveError::VersionMismatch {
                            plugin: plugin.to_string(),
                            dep: dep.name.clone(),
                            required: dep.version_req.clone(),
                            found: "<unknown>".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Return a list of plugins that directly depend on `target`.
    #[must_use]
    pub fn dependents_of(&self, target: &str) -> Vec<String> {
        self.graph
            .plugin_names()
            .into_iter()
            .filter(|p| {
                self.graph
                    .dependencies_of(p)
                    .iter()
                    .any(|d| d.name == target)
            })
            .map(ToOwned::to_owned)
            .collect()
    }

    /// Return the subset of `candidates` that are ready to load given the
    /// already-loaded set.
    #[must_use]
    pub fn ready_to_load<'a>(
        &self,
        candidates: &[&'a str],
        loaded: &HashSet<String>,
    ) -> Vec<&'a str> {
        candidates
            .iter()
            .copied()
            .filter(|c| {
                self.graph.dependencies_of(c).iter().all(|dep| {
                    dep.optional || loaded.contains(&dep.name)
                })
            })
            .collect()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn trace_cycle(&self, start: &str) -> Vec<String> {
        let mut path: Vec<String> = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut current = start.to_string();

        loop {
            if visited.contains(&current) {
                path.push(current.clone());
                // Trim to the cycle portion.
                if let Some(pos) = path.iter().position(|n| n == &current) {
                    return path[pos..].to_vec();
                }
                return path;
            }
            visited.insert(current.clone());
            path.push(current.clone());

            let next = self
                .graph
                .dependencies_of(&current)
                .first()
                .map(|d| d.name.clone());

            match next {
                Some(n) => current = n,
                None => break,
            }
        }
        path
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph() -> DepGraph {
        let mut g = DepGraph::new();
        g.register_plugin("core", "1.0.0");
        g.register_plugin("arch-x86", "0.3.0");
        g.register_plugin("pe-loader", "0.2.0");
        g.add_dependency("arch-x86", Dependency::required("core", ">=1.0.0"));
        g.add_dependency("pe-loader", Dependency::required("core", ">=1.0.0"));
        g.add_dependency("pe-loader", Dependency::required("arch-x86", ">=0.2.0"));
        g
    }

    #[test]
    fn test_resolve_basic_order() {
        let resolver = PluginDependencyResolver::new(simple_graph());
        let order = resolver.resolve_order().unwrap();
        let pos = |name: &str| order.iter().position(|n| n == name).unwrap();
        assert!(pos("core") < pos("arch-x86"));
        assert!(pos("arch-x86") < pos("pe-loader"));
    }

    #[test]
    fn test_missing_dependency() {
        let mut g = DepGraph::new();
        g.register_plugin("plugin-a", "1.0.0");
        g.add_dependency("plugin-a", Dependency::required("missing-lib", ">=1.0.0"));
        let resolver = PluginDependencyResolver::new(g);
        let err = resolver.resolve_order().unwrap_err();
        assert!(matches!(err, ResolveError::Missing { .. }));
    }

    #[test]
    fn test_version_mismatch() {
        let mut g = DepGraph::new();
        g.register_plugin("core", "0.9.0");
        g.register_plugin("plugin-b", "1.0.0");
        g.add_dependency("plugin-b", Dependency::required("core", ">=1.0.0"));
        let resolver = PluginDependencyResolver::new(g);
        let err = resolver.resolve_order().unwrap_err();
        assert!(matches!(err, ResolveError::VersionMismatch { .. }));
    }

    #[test]
    fn test_optional_missing_non_strict() {
        let mut g = DepGraph::new();
        g.register_plugin("plugin-c", "1.0.0");
        g.add_dependency("plugin-c", Dependency::optional("optional-dep", ">=1.0.0"));
        let resolver = PluginDependencyResolver::new(g);
        // Should succeed without error in non-strict mode.
        assert!(resolver.resolve_order().is_ok());
    }

    #[test]
    fn test_optional_missing_strict() {
        let mut g = DepGraph::new();
        g.register_plugin("plugin-d", "1.0.0");
        g.add_dependency("plugin-d", Dependency::optional("optional-dep", ">=1.0.0"));
        let mut resolver = PluginDependencyResolver::new(g);
        resolver.strict_optional = true;
        let err = resolver.resolve_order().unwrap_err();
        assert!(matches!(err, ResolveError::OptionalUnavailable { .. }));
    }

    #[test]
    fn test_cycle_detection() {
        let mut g = DepGraph::new();
        g.register_plugin("a", "1.0.0");
        g.register_plugin("b", "1.0.0");
        g.add_dependency("a", Dependency::required("b", ">=1.0.0"));
        g.add_dependency("b", Dependency::required("a", ">=1.0.0"));
        let resolver = PluginDependencyResolver::new(g);
        let err = resolver.resolve_order().unwrap_err();
        assert!(matches!(err, ResolveError::Cycle(_)));
    }

    #[test]
    fn test_dependents_of() {
        let resolver = PluginDependencyResolver::new(simple_graph());
        let mut deps = resolver.dependents_of("core");
        deps.sort();
        assert!(deps.contains(&"arch-x86".to_string()));
        assert!(deps.contains(&"pe-loader".to_string()));
    }

    #[test]
    fn test_ready_to_load() {
        let resolver = PluginDependencyResolver::new(simple_graph());
        let mut loaded: HashSet<String> = HashSet::new();
        loaded.insert("core".to_string());
        loaded.insert("arch-x86".to_string());
        let candidates: Vec<&str> = vec!["pe-loader"];
        let ready = resolver.ready_to_load(&candidates, &loaded);
        assert_eq!(ready, vec!["pe-loader"]);
    }

    #[test]
    fn test_transitive_deps() {
        let g = simple_graph();
        let mut trans = g.transitive_deps("pe-loader");
        trans.sort();
        assert!(trans.contains(&"core".to_string()));
        assert!(trans.contains(&"arch-x86".to_string()));
        assert!(trans.contains(&"pe-loader".to_string()));
    }

    #[test]
    fn test_from_plugins_helper() {
        let plugins: Vec<(&str, &str, Vec<Dependency>)> = vec![
            ("core", "1.0.0", vec![]),
            ("myplug", "0.1.0", vec![Dependency::required("core", ">=1.0.0")]),
        ];
        let (_resolver, order) = PluginDependencyResolver::from_plugins(plugins).unwrap();
        let core_pos = order.iter().position(|n| n == "core").unwrap();
        let plug_pos = order.iter().position(|n| n == "myplug").unwrap();
        assert!(core_pos < plug_pos);
    }

    #[test]
    fn test_version_satisfies_caret() {
        assert!(version_satisfies("^1.0.0", "1.2.3"));
        assert!(!version_satisfies("^2.0.0", "1.9.9"));
    }

    #[test]
    fn test_version_satisfies_tilde() {
        assert!(version_satisfies("~1.2.0", "1.2.5"));
        assert!(!version_satisfies("~1.2.0", "1.3.0"));
    }

    #[test]
    fn test_empty_graph() {
        let resolver = PluginDependencyResolver::new(DepGraph::new());
        let order = resolver.resolve_order().unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_dep_display() {
        let d = Dependency::required("core", ">=1.0.0");
        assert!(d.to_string().contains("core"));
        let opt = Dependency::optional("extras", ">=0.1.0");
        assert!(opt.to_string().contains("optional"));
    }

    #[test]
    fn test_graph_contains() {
        let mut g = DepGraph::new();
        g.register_plugin("alpha", "1.0.0");
        assert!(g.contains("alpha"));
        assert!(!g.contains("beta"));
    }

    #[test]
    fn test_graph_version_of() {
        let mut g = DepGraph::new();
        g.register_plugin("core", "2.1.0");
        assert_eq!(g.version_of("core"), Some("2.1.0"));
        assert_eq!(g.version_of("unknown"), None);
    }
}
