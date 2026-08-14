//! `ObjC` selector database for dyld shared cache.
//! Load all selectors from shared cache, reverse lookup (IMP → SEL),
//! identify overrides relative to superclass.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SelectorDbError {
    #[error("shared cache not loaded")]
    CacheNotLoaded,
    #[error("class '{0}' not found")]
    ClassNotFound(String),
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
}

pub type SelectorDbResult<T> = Result<T, SelectorDbError>;

// ── Selector entry ────────────────────────────────────────────────────────────

/// A single `ObjC` selector with its string name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Selector {
    /// Unique selector index (position in the shared cache selector table).
    pub index: u32,
    /// The selector string, e.g. "initWithFrame:".
    pub name: String,
    /// Virtual address of the selector string in the shared cache.
    pub address: u64,
}

impl Selector {
    #[must_use] 
    pub fn is_init(&self) -> bool {
        self.name.starts_with("init")
    }

    #[must_use] 
    pub fn is_dealloc(&self) -> bool {
        self.name == "dealloc"
    }

    #[must_use] 
    pub fn is_property_accessor(&self) -> bool {
        // Common getter/setter patterns
        let n = &self.name;
        !n.contains(':') || n.starts_with("set") && n.ends_with(':')
    }

    #[must_use] 
    pub fn argument_count(&self) -> usize {
        self.name.bytes().filter(|&b| b == b':').count()
    }
}

// ── Method implementation entry ───────────────────────────────────────────────

/// A concrete method implementation in an `ObjC` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodImpl {
    pub class_name: String,
    pub selector: Selector,
    /// Virtual address of the method implementation (IMP).
    pub imp: u64,
    pub is_class_method: bool,
    pub is_category: bool,
    pub category_name: Option<String>,
}

impl MethodImpl {
    #[must_use] 
    pub fn full_name(&self) -> String {
        let prefix = if self.is_class_method { '+' } else { '-' };
        format!("{}[{} {}]", prefix, self.class_name, self.selector.name)
    }
}

// ── Class entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClassEntry {
    pub name: String,
    pub superclass_name: Option<String>,
    pub metaclass_address: u64,
    pub class_address: u64,
    pub instance_methods: Vec<MethodImpl>,
    pub class_methods: Vec<MethodImpl>,
    pub protocols: Vec<String>,
    pub ivars: Vec<String>,
}

impl ObjcClassEntry {
    pub fn all_methods(&self) -> impl Iterator<Item = &MethodImpl> {
        self.instance_methods.iter().chain(self.class_methods.iter())
    }

    #[must_use] 
    pub fn selector_names(&self) -> HashSet<&str> {
        self.all_methods().map(|m| m.selector.name.as_str()).collect()
    }
}

// ── Override info ─────────────────────────────────────────────────────────────

/// Describes a method override relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideInfo {
    pub selector_name: String,
    pub subclass: String,
    pub superclass: String,
    pub subclass_imp: u64,
    pub superclass_imp: Option<u64>,
    pub override_kind: OverrideKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverrideKind {
    /// Standard override with super call.
    WithSuperCall,
    /// Override without calling super.
    WithoutSuperCall,
    /// Category override (may replace original).
    CategoryOverride,
    /// Protocol requirement satisfied.
    ProtocolRequirement,
    /// Unknown.
    Unknown,
}

impl OverrideKind {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithSuperCall => "override + super",
            Self::WithoutSuperCall => "override (no super)",
            Self::CategoryOverride => "category override",
            Self::ProtocolRequirement => "protocol requirement",
            Self::Unknown => "unknown",
        }
    }
}

// ── Selector database ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjcSelectorDatabase {
    /// All selectors by name.
    pub selectors_by_name: HashMap<String, Selector>,
    /// All selectors by address.
    pub selectors_by_address: HashMap<u64, Selector>,
    /// All method implementations, keyed by IMP address.
    pub methods_by_imp: HashMap<u64, Vec<MethodImpl>>,
    /// All class entries, keyed by class name.
    pub classes: HashMap<String, ObjcClassEntry>,
    /// Superclass mapping: class name → superclass name.
    pub superclass_map: HashMap<String, String>,
    /// Total selector count.
    pub selector_count: usize,
}

impl ObjcSelectorDatabase {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a selector to the database.
    pub fn add_selector(&mut self, sel: Selector) {
        self.selectors_by_address.insert(sel.address, sel.clone());
        self.selectors_by_name.insert(sel.name.clone(), sel);
        self.selector_count += 1;
    }

    /// Add a method implementation to the database.
    pub fn add_method(&mut self, method: MethodImpl) {
        self.methods_by_imp.entry(method.imp).or_default().push(method);
    }

    /// Add a class entry.
    pub fn add_class(&mut self, entry: ObjcClassEntry) {
        if let Some(ref sup) = entry.superclass_name {
            self.superclass_map.insert(entry.name.clone(), sup.clone());
        }
        for m in entry.all_methods() {
            self.methods_by_imp.entry(m.imp).or_default().push(m.clone());
            self.add_selector(m.selector.clone());
        }
        self.classes.insert(entry.name.clone(), entry);
    }

    // ── Lookup API ─────────────────────────────────────────────────────────

    /// Reverse lookup: IMP address → all `MethodImpl` that live at that address.
    #[must_use] 
    pub fn imp_to_methods(&self, imp: u64) -> Vec<&MethodImpl> {
        self.methods_by_imp
            .get(&imp)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Reverse lookup: IMP → selector name (first match).
    #[must_use] 
    pub fn imp_to_selector(&self, imp: u64) -> Option<&str> {
        self.methods_by_imp
            .get(&imp)?
            .first()
            .map(|m| m.selector.name.as_str())
    }

    /// All IMPs that implement a given selector name.
    #[must_use] 
    pub fn selector_to_imps(&self, sel_name: &str) -> Vec<u64> {
        self.methods_by_imp
            .values()
            .flat_map(|v| v.iter())
            .filter(|m| m.selector.name == sel_name)
            .map(|m| m.imp)
            .collect()
    }

    /// Find all classes that implement a given selector.
    #[must_use] 
    pub fn classes_with_selector(&self, sel_name: &str) -> Vec<&str> {
        self.classes
            .values()
            .filter(|c| c.selector_names().contains(sel_name))
            .map(|c| c.name.as_str())
            .collect()
    }

    /// Return the selector object by name.
    #[must_use] 
    pub fn selector_by_name(&self, name: &str) -> Option<&Selector> {
        self.selectors_by_name.get(name)
    }

    /// Return the selector object by address.
    #[must_use] 
    pub fn selector_by_address(&self, addr: u64) -> Option<&Selector> {
        self.selectors_by_address.get(&addr)
    }

    // ── Override detection ─────────────────────────────────────────────────

    /// Find all method overrides in a class relative to its superclass chain.
    #[must_use] 
    pub fn find_overrides(&self, class_name: &str) -> Vec<OverrideInfo> {
        let cls = match self.classes.get(class_name) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let mut overrides = Vec::new();

        // Walk the superclass chain
        let super_selectors: HashSet<&str> = self
            .superclass_chain(class_name)
            .into_iter()
            .skip(1) // skip self
            .flat_map(|sup_name| {
                self.classes
                    .get(sup_name)
                    .map(|c| c.selector_names())
                    .unwrap_or_default()
            })
            .collect();

        for method in cls.all_methods() {
            let sel = method.selector.name.as_str();
            if super_selectors.contains(sel) {
                // Find the superclass that first declares this selector
                let (sup_name, sup_imp) = self.find_superclass_method(class_name, sel);
                let override_kind = if method.is_category {
                    OverrideKind::CategoryOverride
                } else {
                    OverrideKind::Unknown
                };
                overrides.push(OverrideInfo {
                    selector_name: sel.to_owned(),
                    subclass: class_name.to_owned(),
                    superclass: sup_name.unwrap_or_default(),
                    subclass_imp: method.imp,
                    superclass_imp: sup_imp,
                    override_kind,
                });
            }
        }

        overrides
    }

    /// Return the full superclass chain for a class (including self).
    #[must_use] 
    pub fn superclass_chain<'a>(&'a self, class_name: &'a str) -> Vec<&'a str> {
        let mut chain = vec![class_name];
        let mut current = class_name;
        let mut seen = HashSet::new();
        seen.insert(class_name);

        while let Some(sup) = self.superclass_map.get(current) {
            if seen.contains(sup.as_str()) {
                break; // cycle guard
            }
            chain.push(sup.as_str());
            seen.insert(sup.as_str());
            current = sup.as_str();
        }
        chain
    }

    fn find_superclass_method(
        &self,
        class_name: &str,
        sel_name: &str,
    ) -> (Option<String>, Option<u64>) {
        for sup_name in self.superclass_chain(class_name).into_iter().skip(1) {
            if let Some(sup_cls) = self.classes.get(sup_name)
                && let Some(m) = sup_cls.all_methods().find(|m| m.selector.name == sel_name) {
                    return (Some(sup_name.to_owned()), Some(m.imp));
                }
        }
        (None, None)
    }

    // ── Statistics ─────────────────────────────────────────────────────────

    #[must_use] 
    pub fn total_methods(&self) -> usize {
        self.classes.values().map(|c| c.instance_methods.len() + c.class_methods.len()).sum()
    }

    #[must_use] 
    pub fn most_overridden_selectors(&self, top_n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for cls in self.classes.values() {
            for m in cls.all_methods() {
                *counts.entry(&m.selector.name).or_default() += 1;
            }
        }
        let mut sorted: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(top_n);
        sorted
    }

    /// Find all selectors that match a pattern (substring search).
    #[must_use] 
    pub fn search_selectors(&self, pattern: &str) -> Vec<&Selector> {
        self.selectors_by_name
            .values()
            .filter(|s| s.name.contains(pattern))
            .collect()
    }

    /// All class methods (+ prefix) implementing a selector name.
    #[must_use] 
    pub fn class_methods_for_selector(&self, sel_name: &str) -> Vec<&MethodImpl> {
        self.classes
            .values()
            .flat_map(|c| c.class_methods.iter())
            .filter(|m| m.selector.name == sel_name)
            .collect()
    }

    /// All instance methods (- prefix) implementing a selector name.
    #[must_use] 
    pub fn instance_methods_for_selector(&self, sel_name: &str) -> Vec<&MethodImpl> {
        self.classes
            .values()
            .flat_map(|c| c.instance_methods.iter())
            .filter(|m| m.selector.name == sel_name)
            .collect()
    }
}

// ── Shared cache ObjC loader ──────────────────────────────────────────────────

/// Load `ObjC` selectors from a raw dyld shared cache binary.
///
/// This reads the `ObjC` optimization structures in the shared cache
/// (`__TEXT,__objc_selrefs` and `__objc_opt_ro` header).
#[must_use] 
pub fn load_selectors_from_cache(cache_data: &[u8], base_address: u64) -> ObjcSelectorDatabase {
    let mut db = ObjcSelectorDatabase::new();

    // The ObjC optimizer stores a header at a known offset within the shared cache.
    // In practice, the `__objc_opt_ro` struct is pointed to by the cache header.
    // For this simplified implementation, we scan the cache for selector reference
    // patterns (pointers to strings in __TEXT,__cstring that look like ObjC selectors).

    // Scan for null-terminated selector strings
    // A rough heuristic: look for contiguous valid ASCII identifier strings
    let mut i = 0usize;
    let mut idx = 0u32;
    while i + 4 < cache_data.len() {
        // Check if this looks like the start of a readable selector string
        if is_valid_selector_start(cache_data[i]) {
            let end = cache_data[i..]
                .iter()
                .take(256)
                .position(|&b| b == 0)
                .unwrap_or(0);
            if end > 0 && end < 128 {
                let s = std::str::from_utf8(&cache_data[i..i + end]).unwrap_or("");
                if is_valid_selector(s) {
                    let addr = base_address + i as u64;
                    db.add_selector(Selector {
                        index: idx,
                        name: s.to_owned(),
                        address: addr,
                    });
                    idx += 1;
                    i += end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    db
}

const fn is_valid_selector_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_valid_selector(s: &str) -> bool {
    if s.is_empty() || s.len() > 127 {
        return false;
    }
    // ObjC selectors: alphanumeric + ':' + '_'
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        // Reject simple numbers or single chars that are not useful
        && !s.chars().all(|c| c.is_ascii_digit())
}

// ── Protocol conformance ──────────────────────────────────────────────────────

/// Describes a protocol and the methods it requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcProtocol {
    pub name: String,
    pub required_instance_methods: Vec<String>,
    pub required_class_methods: Vec<String>,
    pub optional_instance_methods: Vec<String>,
    pub adopted_protocols: Vec<String>,
}

impl ObjcProtocol {
    pub fn all_required(&self) -> impl Iterator<Item = &str> {
        self.required_instance_methods
            .iter()
            .chain(self.required_class_methods.iter())
            .map(std::string::String::as_str)
    }
}

/// Check which protocol methods a class implements.
#[must_use] 
pub fn check_protocol_conformance(
    class: &ObjcClassEntry,
    protocol: &ObjcProtocol,
) -> ProtocolConformanceReport {
    let class_selectors: HashSet<&str> = class.selector_names();
    let mut implemented = Vec::new();
    let mut missing = Vec::new();

    for sel in protocol.all_required() {
        if class_selectors.contains(sel) {
            implemented.push(sel.to_owned());
        } else {
            missing.push(sel.to_owned());
        }
    }

    ProtocolConformanceReport {
        class_name: class.name.clone(),
        protocol_name: protocol.name.clone(),
        fully_conforms: missing.is_empty(),
        implemented,
        missing,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConformanceReport {
    pub class_name: String,
    pub protocol_name: String,
    pub fully_conforms: bool,
    pub implemented: Vec<String>,
    pub missing: Vec<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sel(name: &str, addr: u64) -> Selector {
        Selector { index: 0, name: name.to_owned(), address: addr }
    }

    fn make_method(class: &str, sel_name: &str, imp: u64) -> MethodImpl {
        MethodImpl {
            class_name: class.to_owned(),
            selector: make_sel(sel_name, 0),
            imp,
            is_class_method: false,
            is_category: false,
            category_name: None,
        }
    }

    fn make_class(name: &str, super_name: Option<&str>, methods: Vec<MethodImpl>) -> ObjcClassEntry {
        ObjcClassEntry {
            name: name.to_owned(),
            superclass_name: super_name.map(str::to_owned),
            metaclass_address: 0,
            class_address: 0,
            instance_methods: methods,
            class_methods: Vec::new(),
            protocols: Vec::new(),
            ivars: Vec::new(),
        }
    }

    #[test]
    fn test_selector_argument_count() {
        let sel = make_sel("initWithFrame:bounds:", 0);
        assert_eq!(sel.argument_count(), 2);

        let sel0 = make_sel("init", 0);
        assert_eq!(sel0.argument_count(), 0);
    }

    #[test]
    fn test_add_and_lookup_selector() {
        let mut db = ObjcSelectorDatabase::new();
        let sel = make_sel("viewDidLoad", 0x1000);
        db.add_selector(sel);
        assert_eq!(db.selector_by_name("viewDidLoad").unwrap().address, 0x1000);
        assert_eq!(db.selector_by_address(0x1000).unwrap().name, "viewDidLoad");
    }

    #[test]
    fn test_imp_to_selector() {
        let mut db = ObjcSelectorDatabase::new();
        let m = make_method("MyVC", "viewDidLoad", 0xDEAD_BEEF);
        let cls = make_class("MyVC", Some("UIViewController"), vec![m]);
        db.add_class(cls);
        assert_eq!(db.imp_to_selector(0xDEAD_BEEF), Some("viewDidLoad"));
    }

    #[test]
    fn test_classes_with_selector() {
        let mut db = ObjcSelectorDatabase::new();
        let m1 = make_method("A", "foo", 0x100);
        let m2 = make_method("B", "foo", 0x200);
        db.add_class(make_class("A", None, vec![m1]));
        db.add_class(make_class("B", None, vec![m2]));
        let classes = db.classes_with_selector("foo");
        assert_eq!(classes.len(), 2);
    }

    #[test]
    fn test_superclass_chain() {
        let mut db = ObjcSelectorDatabase::new();
        db.add_class(make_class("NSObject", None, Vec::new()));
        db.add_class(make_class("UIView", Some("NSObject"), Vec::new()));
        db.add_class(make_class("UIButton", Some("UIView"), Vec::new()));
        let chain = db.superclass_chain("UIButton");
        assert_eq!(chain, vec!["UIButton", "UIView", "NSObject"]);
    }

    #[test]
    fn test_find_overrides() {
        let mut db = ObjcSelectorDatabase::new();
        let base_method = make_method("NSObject", "init", 0x100);
        let override_method = make_method("MyClass", "init", 0x200);
        db.add_class(make_class("NSObject", None, vec![base_method]));
        db.add_class(make_class("MyClass", Some("NSObject"), vec![override_method]));

        let overrides = db.find_overrides("MyClass");
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].selector_name, "init");
        assert_eq!(overrides[0].superclass, "NSObject");
    }

    #[test]
    fn test_search_selectors() {
        let mut db = ObjcSelectorDatabase::new();
        db.add_selector(make_sel("viewDidLoad", 0x1000));
        db.add_selector(make_sel("viewWillAppear:", 0x2000));
        db.add_selector(make_sel("dealloc", 0x3000));
        let results = db.search_selectors("view");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_valid_selector() {
        assert!(is_valid_selector("init"));
        assert!(is_valid_selector("initWithFrame:"));
        assert!(is_valid_selector("setTitle:forState:"));
        assert!(!is_valid_selector(""));
        assert!(!is_valid_selector("123"));
        assert!(!is_valid_selector("has space"));
    }

    #[test]
    fn test_protocol_conformance() {
        let proto = ObjcProtocol {
            name: "UITableViewDataSource".to_owned(),
            required_instance_methods: vec![
                "tableView:numberOfRowsInSection:".to_owned(),
                "tableView:cellForRowAtIndexPath:".to_owned(),
            ],
            required_class_methods: Vec::new(),
            optional_instance_methods: Vec::new(),
            adopted_protocols: Vec::new(),
        };

        let cls = make_class("MyVC", None, vec![
            make_method("MyVC", "tableView:numberOfRowsInSection:", 0x100),
        ]);

        let report = check_protocol_conformance(&cls, &proto);
        assert!(!report.fully_conforms);
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.implemented.len(), 1);
    }
}
