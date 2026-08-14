//! Symbol versioning: parse GNU version scripts, assign version nodes to
//! symbols, and resolve which version a given symbol belongs to.

use std::collections::HashMap;
use std::fmt;
use std::str::Lines;

// ── VersionError ──────────────────────────────────────────────────────────────

/// Errors raised while parsing or resolving a linker version script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    /// A version script line could not be parsed.
    ParseError {
        /// 1-based line number in the version script.
        line: usize,
        /// Human-readable description of the failure.
        msg: String,
    },
    /// The same version node name was declared twice.
    DuplicateNode(String),
    /// A node referenced a dependency that was never declared.
    UnknownNode(String),
    /// The version-node dependency graph contains a cycle at this node.
    CyclicDependency(String),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError { line, msg } => write!(f, "line {line}: {msg}"),
            Self::DuplicateNode(n) => write!(f, "duplicate version node: {n}"),
            Self::UnknownNode(n) => write!(f, "unknown version node: {n}"),
            Self::CyclicDependency(n) => write!(f, "cyclic dependency at: {n}"),
        }
    }
}

impl std::error::Error for VersionError {}

// ── VersionBinding ────────────────────────────────────────────────────────────

/// Whether a symbol is exported as global or kept local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionBinding {
    /// The symbol is exported globally under this version.
    Global,
    /// The symbol is kept local (hidden) by this version.
    Local,
    /// The symbol is exported weakly under this version.
    Weak,
}

impl fmt::Display for VersionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SymbolVersion ─────────────────────────────────────────────────────────────

/// A version node as found in a linker version script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolVersion {
    /// Version node name, e.g. `"MYLIB_1.2"`.
    pub name: String,
    /// Symbols explicitly listed as global in this node.
    pub globals: Vec<String>,
    /// Symbols explicitly listed as local in this node.
    pub locals: Vec<String>,
    /// Optional parent node (the version this one depends on).
    pub dependencies: Vec<String>,
}

impl SymbolVersion {
    /// Create an empty version node with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            globals: Vec::new(),
            locals: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Returns `true` if `symbol` appears in the global list (exact or wildcard `*`).
    #[must_use]
    pub fn matches_global(&self, symbol: &str) -> bool {
        self.globals.iter().any(|g| g == "*" || g == symbol)
    }

    /// Returns `true` if `symbol` appears in the local list (exact or wildcard `*`).
    #[must_use]
    pub fn matches_local(&self, symbol: &str) -> bool {
        self.locals.iter().any(|l| l == "*" || l == symbol)
    }
}

impl fmt::Display for SymbolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (globals={}, locals={})", self.name, self.globals.len(), self.locals.len())
    }
}

// ── VersionScript parser ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseSection {
    None,
    Global,
    Local,
}

/// Parse a GNU-style version script text into a list of [`SymbolVersion`] nodes.
///
/// Supports:
/// - Named version nodes with `global:` and `local:` sections
/// - Anonymous `{ ... }` nodes (treated as node name `""`)
/// - Dependency chains: `MYLIB_2.0 { ... } MYLIB_1.0;`
/// - `*` wildcards
/// - Line comments (`#`)
///
/// # Errors
///
/// Returns [`VersionError`] if the script contains syntax errors such as
/// unclosed braces, malformed sections, or unexpected tokens.
pub fn parse_version_script(text: &str) -> Result<Vec<SymbolVersion>, VersionError> {
    let mut nodes: Vec<SymbolVersion> = Vec::new();
    let lines_iter: Lines<'_> = text.lines();

    // State machine.
    let mut current: Option<SymbolVersion> = None;
    let mut section = ParseSection::None;
    // Pending dependency: the word that appeared after `};` on the same line
    // becomes the dependency of the next node.  We store it here.
    let mut pending_dep: Option<String> = None;

    for raw_line in lines_iter {
        // Strip comments.
        let line = raw_line.find('#').map_or(raw_line, |idx| &raw_line[..idx]);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Tokenise the line simply by splitting on whitespace and punctuation.
        let tokens: Vec<&str> = tokenize_line(line);
        process_tokens(&tokens, &mut nodes, &mut current, &mut section, &mut pending_dep);
    }

    // Close any unclosed node.
    if let Some(node) = current.take() {
        nodes.push(node);
    }

    Ok(nodes)
}

/// Process tokens for a single (already comment-stripped) line of a version
/// script, mutating the in-progress parse state.
fn process_tokens(
    tokens: &[&str],
    nodes: &mut Vec<SymbolVersion>,
    current: &mut Option<SymbolVersion>,
    section: &mut ParseSection,
    pending_dep: &mut Option<String>,
) {
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        match tok {
            "}" | "};" => {
                let mut inline_dep: Option<String> = None;
                if i + 1 < tokens.len() {
                    let dep_candidate = tokens[i + 1];
                    let next_next = tokens.get(i + 2).copied();
                    if dep_candidate != ";" && dep_candidate != "}" && dep_candidate != "};"
                        && dep_candidate != "{" && !dep_candidate.is_empty()
                        && next_next != Some("{")
                    {
                        let dep_clean = dep_candidate.trim_end_matches(';');
                        if !dep_clean.is_empty() {
                            inline_dep = Some(dep_clean.to_owned());
                        }
                    }
                }
                if let Some(mut node) = current.take() {
                    if let Some(dep) = pending_dep.take() {
                        node.dependencies.push(dep);
                    }
                    if let Some(dep) = inline_dep.take() {
                        node.dependencies.push(dep);
                        i += 1;
                    }
                    nodes.push(node);
                } else if let Some(dep) = inline_dep.take() {
                    *pending_dep = Some(dep);
                    i += 1;
                }
                *section = ParseSection::None;
                i += 1;
            }
            // Bare `{` opens a node body and defaults to the global section,
            // same as an explicit `global:` / `global` token.
            "{" | "global:" | "global" => {
                *section = ParseSection::Global;
                i += 1;
            }
            "local:" | "local" => {
                *section = ParseSection::Local;
                i += 1;
            }
            ";" | ":" => {
                i += 1;
            }
            name if current.is_none() && (i + 1 < tokens.len() && tokens[i + 1] == "{") => {
                let mut node = SymbolVersion::new(name);
                if let Some(dep) = pending_dep.take() {
                    node.dependencies.push(dep);
                }
                *current = Some(node);
                *section = ParseSection::Global;
                i += 2;
            }
            sym_name => {
                let sym_clean = sym_name.trim_end_matches(';');
                if sym_clean.is_empty() {
                    i += 1;
                    continue;
                }
                if current.is_none() {
                    let mut node = SymbolVersion::new("");
                    if let Some(dep) = pending_dep.take() {
                        node.dependencies.push(dep);
                    }
                    *current = Some(node);
                }
                if let Some(node) = current.as_mut() {
                    match *section {
                        ParseSection::Global | ParseSection::None => {
                            node.globals.push(sym_clean.to_owned());
                        }
                        ParseSection::Local => {
                            node.locals.push(sym_clean.to_owned());
                        }
                    }
                }
                i += 1;
            }
        }
    }
}

/// Very simple tokenizer: split on whitespace but keep `{`, `}`, `};`, `:`, `;`
/// as separate tokens.
fn tokenize_line(line: &str) -> Vec<&str> {
    let mut result: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;

    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    macro_rules! flush {
        ($idx:expr) => {
            if let Some(s) = start.take() {
                let tok = line[s..$idx].trim();
                if !tok.is_empty() {
                    result.push(tok);
                }
            }
        };
    }

    while i < len {
        let c = bytes[i] as char;
        match c {
            '{' | '}' | ';' => {
                flush!(i);
                // Check for `};`
                if c == '}' && i + 1 < len && bytes[i + 1] == b';' {
                    result.push("};");
                    i += 2;
                } else if c == ';' {
                    result.push(";");
                    i += 1;
                } else {
                    result.push(if c == '{' { "{" } else { "}" });
                    i += 1;
                }
            }
            ':' => {
                // Emit `global:` / `local:` merged with previous word, then `:`
                if let Some(s) = start.take() {
                    let word = line[s..i].trim();
                    if !word.is_empty() {
                        // Emit the word portion followed by a separate ":" token
                        result.push(&line[s..i]);
                    }
                }
                result.push(":");
                i += 1;
            }
            ' ' | '\t' => {
                flush!(i);
                i += 1;
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
                i += 1;
            }
        }
    }
    flush!(len);
    result
}

// ── SymbolVersioning ─────────────────────────────────────────────────────────

/// Manages version nodes and maps symbol names to their version/binding.
#[derive(Debug, Default, Clone)]
pub struct SymbolVersioning {
    /// Version nodes in definition order.
    nodes: Vec<SymbolVersion>,
    /// Index: symbol name → (node index, binding).
    index: HashMap<String, (usize, VersionBinding)>,
    /// Wildcard globals at node index (`node_idx`, `is_local`).
    has_global_wildcard: Vec<bool>,
    has_local_wildcard: Vec<bool>,
}

impl SymbolVersioning {
    /// Create an empty versioning table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a version script text.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError`] if the script is malformed; see [`parse_version_script`].
    pub fn load_script(&mut self, text: &str) -> Result<(), VersionError> {
        let nodes = parse_version_script(text)?;
        for node in nodes {
            self.add_node(node)?;
        }
        Ok(())
    }

    /// Add a single version node.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::DuplicateNode`] if a node with the same name
    /// already exists, or other validation errors.
    pub fn add_node(&mut self, node: SymbolVersion) -> Result<usize, VersionError> {
        let idx = self.nodes.len();
        let global_wildcard = node.globals.iter().any(|g| g == "*");
        let local_wildcard = node.locals.iter().any(|l| l == "*");

        // Index explicit symbols.
        for sym in &node.globals {
            if sym != "*" {
                self.index.insert(sym.clone(), (idx, VersionBinding::Global));
            }
        }
        for sym in &node.locals {
            if sym != "*" {
                self.index.insert(sym.clone(), (idx, VersionBinding::Local));
            }
        }

        self.nodes.push(node);
        self.has_global_wildcard.push(global_wildcard);
        self.has_local_wildcard.push(local_wildcard);
        Ok(idx)
    }

    /// Resolve the version and binding for `symbol_name`.
    ///
    /// Returns `(node_name, binding)` or `None` if the symbol is not versioned.
    #[must_use]
    pub fn resolve(&self, symbol_name: &str) -> Option<(&str, VersionBinding)> {
        // Exact match first.
        if let Some(&(idx, binding)) = self.index.get(symbol_name) {
            return Some((&self.nodes[idx].name, binding));
        }
        // Wildcard: scan nodes in reverse (later nodes take precedence).
        for idx in (0..self.nodes.len()).rev() {
            if self.has_local_wildcard[idx] {
                return Some((&self.nodes[idx].name, VersionBinding::Local));
            }
            if self.has_global_wildcard[idx] {
                return Some((&self.nodes[idx].name, VersionBinding::Global));
            }
        }
        None
    }

    /// All version node names.
    #[must_use]
    pub fn node_names(&self) -> Vec<&str> {
        self.nodes.iter().map(|n| n.name.as_str()).collect()
    }

    /// Get a node by name.
    #[must_use]
    pub fn get_node(&self, name: &str) -> Option<&SymbolVersion> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Number of nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total symbols indexed (not counting wildcards).
    #[must_use]
    pub fn indexed_symbol_count(&self) -> usize {
        self.index.len()
    }

    /// Build a dependency-ordered list of node names (topological sort).
    /// Earlier dependencies come first.
    #[must_use]
    pub fn dependency_order(&self) -> Vec<&str> {
        let mut visited: Vec<bool> = vec![false; self.nodes.len()];
        let mut order: Vec<usize> = Vec::new();

        // Build name → index map.
        let name_to_idx: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.name.as_str(), i))
            .collect();

        for i in 0..self.nodes.len() {
            if !visited[i] {
                self.topo_visit(i, &name_to_idx, &mut visited, &mut order);
            }
        }

        order.iter().map(|&i| self.nodes[i].name.as_str()).collect()
    }

    fn topo_visit(
        &self,
        idx: usize,
        name_to_idx: &HashMap<&str, usize>,
        visited: &mut Vec<bool>,
        order: &mut Vec<usize>,
    ) {
        if visited[idx] {
            return;
        }
        visited[idx] = true;
        for dep in &self.nodes[idx].dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.as_str()) {
                self.topo_visit(dep_idx, name_to_idx, visited, order);
            }
        }
        order.push(idx);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_SCRIPT: &str = r"
MYLIB_2.0 {
    global:
        foo;
        bar;
    local:
        *;
} MYLIB_1.0;

MYLIB_1.0 {
    global:
        baz;
};
";

    #[test]
    fn parse_simple_script() {
        let nodes = parse_version_script(SIMPLE_SCRIPT).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "MYLIB_2.0");
        assert!(nodes[0].globals.contains(&"foo".to_owned()));
        assert!(nodes[0].globals.contains(&"bar".to_owned()));
        assert!(nodes[0].locals.contains(&"*".to_owned()));
    }

    #[test]
    fn parse_dependency_chain() {
        let nodes = parse_version_script(SIMPLE_SCRIPT).unwrap();
        // MYLIB_2.0 depends on MYLIB_1.0
        assert!(nodes[0].dependencies.contains(&"MYLIB_1.0".to_owned()));
    }

    #[test]
    fn resolve_explicit_global() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        let (ver, binding) = sv.resolve("foo").unwrap();
        assert_eq!(ver, "MYLIB_2.0");
        assert_eq!(binding, VersionBinding::Global);
    }

    #[test]
    fn resolve_older_version() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        let (ver, binding) = sv.resolve("baz").unwrap();
        assert_eq!(ver, "MYLIB_1.0");
        assert_eq!(binding, VersionBinding::Global);
    }

    #[test]
    fn wildcard_local_catch_all() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        // "unknown_sym" is not explicitly listed, caught by local `*`
        let (_, binding) = sv.resolve("unknown_sym").unwrap();
        assert_eq!(binding, VersionBinding::Local);
    }

    #[test]
    fn anonymous_node() {
        let script = "{ global: open; close; local: *; };";
        let nodes = parse_version_script(script).unwrap();
        assert_eq!(nodes[0].globals.len(), 2);
        assert!(nodes[0].globals.contains(&"open".to_owned()));
    }

    #[test]
    fn get_node_by_name() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        let node = sv.get_node("MYLIB_1.0").unwrap();
        assert!(node.globals.contains(&"baz".to_owned()));
    }

    #[test]
    fn node_count() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        assert_eq!(sv.node_count(), 2);
    }

    #[test]
    fn dependency_order_puts_dependencies_first() {
        let mut sv = SymbolVersioning::new();
        sv.load_script(SIMPLE_SCRIPT).unwrap();
        let order = sv.dependency_order();
        let pos_1_0 = order.iter().position(|&n| n == "MYLIB_1.0").unwrap();
        let pos_2_0 = order.iter().position(|&n| n == "MYLIB_2.0").unwrap();
        assert!(pos_1_0 < pos_2_0);
    }

    #[test]
    fn comments_stripped() {
        let script = "# This is a comment\nVER_1 { global: sym; # inline comment\n };";
        let nodes = parse_version_script(script).unwrap();
        assert_eq!(nodes[0].globals, vec!["sym"]);
    }

    #[test]
    fn empty_script_returns_empty() {
        let nodes = parse_version_script("").unwrap();
        assert!(nodes.is_empty());
    }

    #[test]
    fn symbol_version_matches_global() {
        let mut sv = SymbolVersion::new("V1");
        sv.globals.push("open".into());
        sv.globals.push("*".into());
        assert!(sv.matches_global("open"));
        assert!(sv.matches_global("anything_else"));
    }

    #[test]
    fn symbol_version_matches_local() {
        let mut sv = SymbolVersion::new("V1");
        sv.locals.push("internal_fn".into());
        assert!(sv.matches_local("internal_fn"));
        assert!(!sv.matches_local("public_fn"));
    }
}
