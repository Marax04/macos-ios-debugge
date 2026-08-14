//! Tool registry: dynamic tool registration, discovery, capability advertisement,
//! versioning, and deprecation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Semantic version
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Semantic version (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    #[must_use]
    pub const fn v1() -> Self {
        Self::new(1, 0, 0)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl std::str::FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(format!("invalid version: {s}"));
        }
        let major = parts[0].parse::<u32>().map_err(|e| e.to_string())?;
        let minor = parts[1].parse::<u32>().map_err(|e| e.to_string())?;
        let patch = parts[2].parse::<u32>().map_err(|e| e.to_string())?;
        Ok(Self { major, minor, patch })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tool category
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Category/tag for grouping tools.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    Disassembly,
    Decompilation,
    Analysis,
    Search,
    Hashing,
    Memory,
    Imports,
    Exports,
    Strings,
    Sections,
    CrossReferences,
    Patching,
    Scripting,
    ThreatIntelligence,
    Network,
    Custom(String),
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Disassembly => "disassembly",
            Self::Decompilation => "decompilation",
            Self::Analysis => "analysis",
            Self::Search => "search",
            Self::Hashing => "hashing",
            Self::Memory => "memory",
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::Strings => "strings",
            Self::Sections => "sections",
            Self::CrossReferences => "cross-references",
            Self::Patching => "patching",
            Self::Scripting => "scripting",
            Self::ThreatIntelligence => "threat-intelligence",
            Self::Network => "network",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolDescriptor
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Human-readable descriptor for a registered tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub long_description: Option<String>,
    pub category: ToolCategory,
    pub tags: Vec<String>,
    pub author: Option<String>,
    pub deprecated: bool,
    pub deprecation_message: Option<String>,
    pub replacement: Option<String>,
    pub parameters: Value,
    pub return_type: Option<String>,
    pub examples: Vec<ToolExample>,
    pub enabled: bool,
}

impl ToolDescriptor {
    /// Create a new descriptor.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: ToolCategory,
    ) -> Self {
        Self {
            name: name.into(),
            version: Version::v1(),
            description: description.into(),
            long_description: None,
            category,
            tags: Vec::new(),
            author: None,
            deprecated: false,
            deprecation_message: None,
            replacement: None,
            parameters: Value::Object(serde_json::Map::new()),
            return_type: None,
            examples: Vec::new(),
            enabled: true,
        }
    }

    /// Mark this tool as deprecated.
    #[must_use]
    pub fn deprecate(mut self, message: impl Into<String>, replacement: Option<String>) -> Self {
        self.deprecated = true;
        self.deprecation_message = Some(message.into());
        self.replacement = replacement;
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Set the parameter schema JSON.
    #[must_use]
    pub fn with_parameters(mut self, params: Value) -> Self {
        self.parameters = params;
        self
    }

    /// Add an example.
    #[must_use]
    pub fn with_example(mut self, ex: ToolExample) -> Self {
        self.examples.push(ex);
        self
    }

    /// Set the version.
    #[must_use]
    pub const fn with_version(mut self, v: Version) -> Self {
        self.version = v;
        self
    }

    /// Set the author.
    #[must_use]
    pub fn by(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Returns `true` if this tool is available (enabled and not deprecated).
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.enabled && !self.deprecated
    }
}

/// A usage example for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    pub description: String,
    pub params: Value,
    pub expected_result: Option<Value>,
}

impl ToolExample {
    #[must_use]
    pub fn new(description: impl Into<String>, params: Value) -> Self {
        Self { description: description.into(), params, expected_result: None }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CapabilitySet
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A set of advertised capabilities grouped by category.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilitySet {
    pub categories: HashMap<String, Vec<String>>, // category â†’ [tool_names]
    pub total_tools: usize,
    pub enabled_tools: usize,
    pub version: String,
}

impl CapabilitySet {
    /// Build a capability set from a registry.
    #[must_use]
    pub fn from_registry(registry: &ToolRegistry) -> Self {
        let mut categories: HashMap<String, Vec<String>> = HashMap::new();
        let mut total = 0;
        let mut enabled = 0;

        for desc in registry.all_descriptors() {
            total += 1;
            if desc.enabled { enabled += 1; }
            categories
                .entry(desc.category.to_string())
                .or_default()
                .push(desc.name.clone());
        }

        Self {
            categories,
            total_tools: total,
            enabled_tools: enabled,
            version: "1.0.0".to_string(),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// RegistryEvent
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Events emitted by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEvent {
    ToolRegistered { name: String, version: Version },
    ToolDeregistered { name: String },
    ToolEnabled { name: String },
    ToolDisabled { name: String },
    ToolDeprecated { name: String, replacement: Option<String> },
    ToolUpdated { name: String, old_version: Version, new_version: Version },
}

/// Observer callback.
pub type RegistryObserver = Box<dyn Fn(&RegistryEvent) + Send + Sync>;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolRegistry
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Dynamic tool registry with versioning, deprecation, and capability advertisement.
pub struct ToolRegistry {
    descriptors: HashMap<String, ToolDescriptor>,
    observers: Vec<RegistryObserver>,
    tags_index: HashMap<String, Vec<String>>, // tag â†’ [tool_names]
    category_index: HashMap<String, Vec<String>>,
}

impl ToolRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            observers: Vec::new(),
            tags_index: HashMap::new(),
            category_index: HashMap::new(),
        }
    }

    /// Register a new tool.
    ///
    /// Returns `true` if the tool was newly added, `false` if it replaced an existing entry.
    pub fn register(&mut self, descriptor: ToolDescriptor) -> bool {
        let was_new = !self.descriptors.contains_key(&descriptor.name);

        let version = descriptor.version.clone();
        let name = descriptor.name.clone();
        let category = descriptor.category.to_string();
        let tags = descriptor.tags.clone();

        // Re-registering an existing name is an UPDATE, so its previous index
        // entries must go first.
        //
        // Before 2026-07-29 the pushes below were unconditional: registering
        // the same tool twice left its name in `tags_index` twice, and
        // `by_tag` — which reads that index — returned the descriptor twice.
        // (`by_category` filters `descriptors.values()` directly, so it never
        // saw the duplication; only the tag path was affected.) Dropping the
        // old entries also keeps the indices correct when an update CHANGES a
        // tool's category or tags, which the previous code could not do.
        let previous = self
            .descriptors
            .get(&name)
            .map(|d| (d.category.to_string(), d.tags.clone()));
        if let Some((old_category, old_tags)) = previous {
            if let Some(v) = self.category_index.get_mut(&old_category) {
                v.retain(|n| n != &name);
            }
            for t in &old_tags {
                if let Some(v) = self.tags_index.get_mut(t) {
                    v.retain(|n| n != &name);
                }
            }
        }

        // Update category index
        self.category_index
            .entry(category)
            .or_default()
            .push(name.clone());

        // Update tag index
        for tag in &tags {
            self.tags_index
                .entry(tag.clone())
                .or_default()
                .push(name.clone());
        }

        let old_version = self.descriptors.get(&name).map(|d| d.version.clone());

        self.descriptors.insert(name.clone(), descriptor);

        if was_new {
            self.emit(&RegistryEvent::ToolRegistered { name, version });
        } else if let Some(ov) = old_version {
            self.emit(&RegistryEvent::ToolUpdated {
                name,
                old_version: ov,
                new_version: version,
            });
        }

        was_new
    }

    /// Deregister a tool.
    pub fn deregister(&mut self, name: &str) -> bool {
        if let Some(desc) = self.descriptors.remove(name) {
            // Remove from indices
            let cat = desc.category.to_string();
            if let Some(v) = self.category_index.get_mut(&cat) {
                v.retain(|n| n != name);
            }
            for tag in &desc.tags {
                if let Some(v) = self.tags_index.get_mut(tag) {
                    v.retain(|n| n != name);
                }
            }
            self.emit(&RegistryEvent::ToolDeregistered { name: name.to_string() });
            true
        } else {
            false
        }
    }

    /// Enable a tool.
    pub fn enable(&mut self, name: &str) -> bool {
        if let Some(d) = self.descriptors.get_mut(name) {
            d.enabled = true;
            self.emit(&RegistryEvent::ToolEnabled { name: name.to_string() });
            true
        } else {
            false
        }
    }

    /// Disable a tool.
    pub fn disable(&mut self, name: &str) -> bool {
        if let Some(d) = self.descriptors.get_mut(name) {
            d.enabled = false;
            self.emit(&RegistryEvent::ToolDisabled { name: name.to_string() });
            true
        } else {
            false
        }
    }

    /// Deprecate a tool.
    pub fn deprecate(&mut self, name: &str, message: &str, replacement: Option<String>) -> bool {
        if let Some(d) = self.descriptors.get_mut(name) {
            d.deprecated = true;
            d.deprecation_message = Some(message.to_string());
            d.replacement.clone_from(&replacement);
            self.emit(&RegistryEvent::ToolDeprecated { name: name.to_string(), replacement });
            true
        } else {
            false
        }
    }

    /// Look up a tool descriptor by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ToolDescriptor> {
        self.descriptors.get(name)
    }

    /// Returns `true` if the tool is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.descriptors.contains_key(name)
    }

    /// All registered tool descriptors.
    #[must_use]
    pub fn all_descriptors(&self) -> Vec<&ToolDescriptor> {
        self.descriptors.values().collect()
    }

    /// All enabled, non-deprecated tools.
    #[must_use]
    pub fn available_tools(&self) -> Vec<&ToolDescriptor> {
        self.descriptors.values().filter(|d| d.is_available()).collect()
    }

    /// All deprecated tools.
    #[must_use]
    pub fn deprecated_tools(&self) -> Vec<&ToolDescriptor> {
        self.descriptors.values().filter(|d| d.deprecated).collect()
    }

    /// Find tools by category.
    #[must_use]
    pub fn by_category(&self, category: &str) -> Vec<&ToolDescriptor> {
        self.descriptors
            .values()
            .filter(|d| d.category.to_string() == category)
            .collect()
    }

    /// Find tools by tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&ToolDescriptor> {
        self.tags_index
            .get(tag)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| self.descriptors.get(n.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Search tools by partial name or description match.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&ToolDescriptor> {
        let q = query.to_lowercase();
        self.descriptors
            .values()
            .filter(|d| {
                d.name.to_lowercase().contains(&q)
                    || d.description.to_lowercase().contains(&q)
                    || d.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Total number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Returns `true` if no tools are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Build a capability advertisement.
    #[must_use]
    pub fn advertise_capabilities(&self) -> CapabilitySet {
        CapabilitySet::from_registry(self)
    }

    /// Add an observer that is called for each registry event.
    pub fn add_observer(&mut self, observer: RegistryObserver) {
        self.observers.push(observer);
    }

    fn emit(&self, event: &RegistryEvent) {
        for observer in &self.observers {
            observer(event);
        }
    }

    /// Export all tool descriptors as a JSON array.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let tools: Vec<Value> = self
            .descriptors
            .values()
            .map(|d| serde_json::to_value(d).unwrap_or(Value::Null))
            .collect();
        Value::Array(tools)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Built-in registry population
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Populate a registry with the standard built-in RE tool descriptors.
pub fn register_builtin_tools(registry: &mut ToolRegistry) {
    let tools = vec![
        ToolDescriptor::new("disassemble_at", "Disassemble instructions at a virtual address", ToolCategory::Disassembly)
            .tag("disasm").tag("x86"),
        ToolDescriptor::new("get_function", "Retrieve function information by name or address", ToolCategory::Analysis)
            .tag("function").tag("analysis"),
        ToolDescriptor::new("list_functions", "List all functions in the binary", ToolCategory::Analysis)
            .tag("function").tag("list"),
        ToolDescriptor::new("search_string", "Search for strings in the binary", ToolCategory::Strings)
            .tag("strings").tag("search"),
        ToolDescriptor::new("get_imports", "List imported symbols", ToolCategory::Imports)
            .tag("imports").tag("iat"),
        ToolDescriptor::new("get_exports", "List exported symbols", ToolCategory::Exports)
            .tag("exports").tag("eat"),
        ToolDescriptor::new("compute_hash", "Compute hash of binary data", ToolCategory::Hashing)
            .tag("hash").tag("md5").tag("sha256"),
        ToolDescriptor::new("get_section", "Get binary section information", ToolCategory::Sections)
            .tag("section").tag("pe").tag("elf"),
    ];

    for tool in tools {
        registry.register(tool);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn populated() -> ToolRegistry {
        let mut r = ToolRegistry::new();
        register_builtin_tools(&mut r);
        r
    }

    #[test]
    fn test_register_and_get() {
        let mut r = ToolRegistry::new();
        let d = ToolDescriptor::new("my_tool", "A test tool", ToolCategory::Analysis);
        r.register(d);
        assert!(r.contains("my_tool"));
        let got = r.get("my_tool").unwrap();
        assert_eq!(got.name, "my_tool");
    }

    #[test]
    fn test_deregister() {
        let mut r = ToolRegistry::new();
        r.register(ToolDescriptor::new("t", "t", ToolCategory::Analysis));
        assert!(r.deregister("t"));
        assert!(!r.contains("t"));
        assert!(!r.deregister("t")); // second deregister is false
    }

    #[test]
    fn test_enable_disable() {
        let mut r = ToolRegistry::new();
        r.register(ToolDescriptor::new("t", "t", ToolCategory::Analysis));
        assert!(r.disable("t"));
        assert!(!r.get("t").unwrap().enabled);
        assert!(r.enable("t"));
        assert!(r.get("t").unwrap().enabled);
    }

    #[test]
    fn test_deprecate() {
        let mut r = ToolRegistry::new();
        r.register(ToolDescriptor::new("old_tool", "old", ToolCategory::Analysis));
        r.deprecate("old_tool", "Use new_tool instead", Some("new_tool".to_string()));
        assert!(r.get("old_tool").unwrap().deprecated);
        assert_eq!(r.get("old_tool").unwrap().replacement.as_deref(), Some("new_tool"));
    }

    #[test]
    fn test_available_tools() {
        let mut r = populated();
        let before = r.available_tools().len();
        r.disable("disassemble_at");
        let after = r.available_tools().len();
        assert_eq!(before - 1, after);
    }

    #[test]
    fn test_deprecated_tools() {
        let mut r = populated();
        assert!(r.deprecated_tools().is_empty());
        r.deprecate("get_section", "old", None);
        assert_eq!(r.deprecated_tools().len(), 1);
    }

    #[test]
    fn test_by_category() {
        let r = populated();
        let analysis = r.by_category("analysis");
        assert!(!analysis.is_empty());
        for t in &analysis {
            assert_eq!(t.category.to_string(), "analysis");
        }
    }

    #[test]
    fn test_by_tag() {
        let r = populated();
        let with_hash = r.by_tag("hash");
        assert!(with_hash.iter().any(|t| t.name == "compute_hash"));
    }

    #[test]
    fn test_search() {
        let r = populated();
        let results = r.search("function");
        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.name.contains("function")));
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut r = ToolRegistry::new();
        assert!(r.is_empty());
        r.register(ToolDescriptor::new("t", "t", ToolCategory::Analysis));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_advertise_capabilities() {
        let r = populated();
        let caps = r.advertise_capabilities();
        assert!(caps.total_tools > 0);
        assert!(caps.enabled_tools <= caps.total_tools);
        assert!(!caps.categories.is_empty());
    }

    #[test]
    fn test_to_json() {
        let r = populated();
        let j = r.to_json();
        assert!(j.is_array());
        assert!(!j.as_array().unwrap().is_empty());
    }

    #[test]
    fn test_observer_called_on_register() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let mut r = ToolRegistry::new();
        r.add_observer(Box::new(move |_| { c.fetch_add(1, Ordering::SeqCst); }));
        r.register(ToolDescriptor::new("t", "t", ToolCategory::Analysis));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);
        let v3 = Version::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn test_version_display() {
        assert_eq!(Version::new(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn test_version_from_str() {
        let v: Version = "2.1.0".parse().unwrap();
        assert_eq!(v, Version::new(2, 1, 0));
    }

    #[test]
    fn test_tool_is_available() {
        let d = ToolDescriptor::new("t", "t", ToolCategory::Analysis);
        assert!(d.is_available());
        let dep = d.deprecate("old", None);
        assert!(!dep.is_available());
    }

    #[test]
    fn test_register_builtin_count() {
        let mut r = ToolRegistry::new();
        register_builtin_tools(&mut r);
        assert!(r.len() >= 8);
    }
}

