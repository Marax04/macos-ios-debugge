use std::collections::{HashMap, BTreeMap};
use serde::{Serialize, Deserialize};

// ── Symbol type hierarchy ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Data,
    Object,
    Section,
    File,
    ThreadLocal,
    Absolute,
    CommonBlock,
    IndirectFunction,
    Label,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    GnuUnique,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolVisibility {
    Default,
    Hidden,
    Protected,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSource {
    Static,      // from static symbol table
    Dynamic,     // from dynamic symbol table / exports
    Import,      // imported from external module
    Debug,       // from debug info (PDB, DWARF)
    Synthesized, // created by the loader (e.g., for plt stubs)
    Demangled,   // original was mangled, this is the demangled form
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub binding: SymbolBinding,
    pub visibility: SymbolVisibility,
    pub source: SymbolSource,
    pub section_idx: Option<usize>,
    pub section_name: Option<String>,
    pub module: Option<String>,  // for imported symbols
    pub ordinal: Option<u32>,    // for PE exports/imports
    pub is_thumb: bool,          // ARM Thumb mode
    pub forwarder: Option<String>, // PE forwarder rva
    pub aux_data: Vec<u8>,       // raw aux sym data
}

pub type SymbolId = u64;

impl Symbol {
    #[must_use] 
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.name)
    }

    #[must_use] 
    pub fn is_function(&self) -> bool { self.kind == SymbolKind::Function }
    #[must_use] 
    pub const fn is_data(&self) -> bool { matches!(self.kind, SymbolKind::Data | SymbolKind::Object) }
    #[must_use] 
    pub fn is_imported(&self) -> bool { self.source == SymbolSource::Import }
    #[must_use] 
    pub fn is_exported(&self) -> bool { self.source == SymbolSource::Dynamic }
    #[must_use] 
    pub const fn effective_address(&self) -> u64 {
        if self.is_thumb { self.address & !1 } else { self.address }
    }
}

// ── Symbol table ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    by_address: BTreeMap<u64, Vec<SymbolId>>,
    by_name: HashMap<String, Vec<SymbolId>>,
    by_demangled: HashMap<String, Vec<SymbolId>>,
    imports: Vec<SymbolId>,
    exports: Vec<SymbolId>,
    functions: Vec<SymbolId>,
    next_id: SymbolId,
}

impl SymbolTable {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, mut sym: Symbol) -> SymbolId {
        let id = self.next_id;
        self.next_id += 1;
        sym.id = id;

        self.by_address.entry(sym.effective_address()).or_default().push(id);
        self.by_name.entry(sym.name.clone()).or_default().push(id);
        if let Some(d) = &sym.demangled_name {
            self.by_demangled.entry(d.clone()).or_default().push(id);
        }
        if sym.source == SymbolSource::Import { self.imports.push(id); }
        if sym.source == SymbolSource::Dynamic { self.exports.push(id); }
        if sym.kind == SymbolKind::Function { self.functions.push(id); }

        self.symbols.push(sym);
        id
    }

    #[must_use] 
    pub fn get(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.id == id)
    }

    #[must_use] 
    pub fn by_address(&self, addr: u64) -> Vec<&Symbol> {
        self.by_address.get(&addr)
            .map(|ids| ids.iter().filter_map(|&id| self.get(id)).collect())
            .unwrap_or_default()
    }

    #[must_use] 
    pub fn nearest_before(&self, addr: u64) -> Option<&Symbol> {
        self.by_address.range(..=addr)
            .next_back()
            .and_then(|(_, ids)| ids.first().and_then(|&id| self.get(id)))
    }

    #[must_use] 
    pub fn by_name(&self, name: &str) -> Vec<&Symbol> {
        let mut results: Vec<&Symbol> = self.by_name.get(name)
            .map(|ids| ids.iter().filter_map(|&id| self.get(id)).collect())
            .unwrap_or_default();
        if results.is_empty() {
            results = self.by_demangled.get(name)
                .map(|ids| ids.iter().filter_map(|&id| self.get(id)).collect())
                .unwrap_or_default();
        }
        results
    }

    #[must_use] 
    pub fn find_by_name_prefix(&self, prefix: &str) -> Vec<&Symbol> {
        self.symbols.iter()
            .filter(|s| s.name.starts_with(prefix) ||
                s.demangled_name.as_deref().is_some_and(|d| d.starts_with(prefix)))
            .collect()
    }

    #[must_use] 
    pub fn find_by_name_substr(&self, substr: &str) -> Vec<&Symbol> {
        self.symbols.iter()
            .filter(|s| s.name.contains(substr) ||
                s.demangled_name.as_deref().is_some_and(|d| d.contains(substr)))
            .collect()
    }

    #[must_use] 
    pub fn imports(&self) -> Vec<&Symbol> {
        self.imports.iter().filter_map(|&id| self.get(id)).collect()
    }

    #[must_use] 
    pub fn exports(&self) -> Vec<&Symbol> {
        self.exports.iter().filter_map(|&id| self.get(id)).collect()
    }

    #[must_use] 
    pub fn functions(&self) -> Vec<&Symbol> {
        self.functions.iter().filter_map(|&id| self.get(id)).collect()
    }

    #[must_use] 
    pub fn all(&self) -> &[Symbol] { &self.symbols }

    #[must_use] 
    pub const fn len(&self) -> usize { self.symbols.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.symbols.is_empty() }

    #[must_use] 
    pub fn address_range(&self) -> Option<(u64, u64)> {
        let min = self.by_address.keys().next().copied()?;
        let max = self.by_address.keys().next_back().copied()?;
        Some((min, max))
    }

    #[must_use] 
    pub fn symbols_in_range(&self, start: u64, end: u64) -> Vec<&Symbol> {
        self.by_address.range(start..end)
            .flat_map(|(_, ids)| ids.iter().filter_map(|&id| self.get(id)))
            .collect()
    }

    pub fn merge(&mut self, other: Self) {
        for sym in other.symbols {
            self.add(sym);
        }
    }

    /// Remove duplicate symbols, keeping the highest-priority source.
    ///
    /// # Panics
    /// Panics if the symbol table is internally inconsistent (ID present in
    /// `seen` but not found by `get`).  This cannot happen under normal use.
    pub fn remove_duplicates(&mut self) {
        // Keep only one symbol per (address, name) pair, preferring debug > dynamic > static
        let mut seen: HashMap<(u64, String), SymbolId> = HashMap::with_capacity(self.symbols.len());
        let mut to_keep: std::collections::HashSet<SymbolId> = std::collections::HashSet::with_capacity(self.symbols.len());
        for sym in &self.symbols {
            let key = (sym.effective_address(), sym.name.clone());
            if let Some(&existing_id) = seen.get(&key) {
                let existing = self.get(existing_id).unwrap();
                let prefer_new = source_priority(&sym.source) > source_priority(&existing.source);
                if prefer_new {
                    to_keep.remove(&existing_id);
                    to_keep.insert(sym.id);
                    seen.insert(key, sym.id);
                }
            } else {
                seen.insert(key, sym.id);
                to_keep.insert(sym.id);
            }
        }
        self.symbols.retain(|s| to_keep.contains(&s.id));
        self.rebuild_indices();
    }

    fn rebuild_indices(&mut self) {
        self.by_address.clear();
        self.by_name.clear();
        self.by_demangled.clear();
        self.imports.clear();
        self.exports.clear();
        self.functions.clear();
        for sym in &self.symbols {
            self.by_address.entry(sym.effective_address()).or_default().push(sym.id);
            self.by_name.entry(sym.name.clone()).or_default().push(sym.id);
            if let Some(d) = &sym.demangled_name {
                self.by_demangled.entry(d.clone()).or_default().push(sym.id);
            }
            if sym.source == SymbolSource::Import { self.imports.push(sym.id); }
            if sym.source == SymbolSource::Dynamic { self.exports.push(sym.id); }
            if sym.kind == SymbolKind::Function { self.functions.push(sym.id); }
        }
    }

    #[must_use] 
    pub fn stats(&self) -> SymbolTableStats {
        let by_kind: HashMap<String, usize> = {
            let mut m: HashMap<String, usize> = HashMap::with_capacity(12);
            for sym in &self.symbols {
                let kind_str = match sym.kind {
                    SymbolKind::Function => "Function",
                    SymbolKind::Data => "Data",
                    SymbolKind::Object => "Object",
                    SymbolKind::Section => "Section",
                    SymbolKind::File => "File",
                    SymbolKind::ThreadLocal => "ThreadLocal",
                    SymbolKind::Absolute => "Absolute",
                    SymbolKind::CommonBlock => "CommonBlock",
                    SymbolKind::IndirectFunction => "IndirectFunction",
                    SymbolKind::Label => "Label",
                    SymbolKind::Unknown => "Unknown",
                };
                *m.entry(kind_str.to_owned()).or_insert(0) += 1;
            }
            m
        };
        SymbolTableStats {
            total: self.symbols.len(),
            functions: self.functions.len(),
            imports: self.imports.len(),
            exports: self.exports.len(),
            by_kind,
        }
    }
}

const fn source_priority(src: &SymbolSource) -> u8 {
    match src {
        SymbolSource::Debug => 4,
        SymbolSource::Demangled => 3,
        SymbolSource::Dynamic => 2,
        SymbolSource::Static | SymbolSource::Import => 1,
        SymbolSource::Synthesized => 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolTableStats {
    pub total: usize,
    pub functions: usize,
    pub imports: usize,
    pub exports: usize,
    pub by_kind: HashMap<String, usize>,
}

// ── Import table ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportTable {
    pub modules: Vec<ImportModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportModule {
    pub name: String,
    pub imports: Vec<ImportEntry>,
    pub bound_address: Option<u64>,
    pub timestamp: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_rva: u64,
    pub iat_address: u64,
    pub resolved_address: Option<u64>,
    pub is_delay_loaded: bool,
}

impl ImportEntry {
    #[must_use] 
    pub fn display_name(&self) -> String {
        self.name.as_deref().map_or_else(|| self.ordinal.map_or_else(|| "?".to_string(), |ord| format!("Ordinal#{ord}")), str::to_owned)
    }
}

impl ImportTable {
    #[must_use] 
    pub fn find_module(&self, name: &str) -> Option<&ImportModule> {
        let name_low = name.to_lowercase();
        self.modules.iter().find(|m| m.name.to_lowercase() == name_low)
    }

    #[must_use] 
    pub fn find_import(&self, module: &str, func: &str) -> Option<&ImportEntry> {
        self.find_module(module)?
            .imports.iter()
            .find(|i| i.name.as_deref() == Some(func))
    }

    pub fn all_imports(&self) -> impl Iterator<Item = (&str, &ImportEntry)> {
        self.modules.iter()
            .flat_map(|m| m.imports.iter().map(move |e| (m.name.as_str(), e)))
    }

    #[must_use] 
    pub fn suspicious_imports(&self) -> Vec<(String, String)> {
        static SUSPICIOUS: &[(&str, &str)] = &[
            ("kernel32.dll", "CreateRemoteThread"),
            ("kernel32.dll", "WriteProcessMemory"),
            ("kernel32.dll", "VirtualAllocEx"),
            ("kernel32.dll", "OpenProcess"),
            ("ntdll.dll", "NtCreateThreadEx"),
            ("ntdll.dll", "NtWriteVirtualMemory"),
            ("kernel32.dll", "URLDownloadToFile"),
            ("kernel32.dll", "WinExec"),
            ("advapi32.dll", "CryptEncrypt"),
            ("wininet.dll", "InternetOpenUrl"),
            ("shell32.dll", "ShellExecuteA"),
            ("kernel32.dll", "LoadLibraryA"),
        ];
        let mut found = Vec::new();
        for (module, func) in SUSPICIOUS {
            if self.find_import(module, func).is_some() {
                found.push((module.to_string(), func.to_string()));
            }
        }
        found
    }
}

// ── Export table ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportTable {
    pub module_name: String,
    pub base_ordinal: u32,
    pub exports: Vec<ExportEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub address: u64,
    pub is_forwarder: bool,
    pub forwarder_string: Option<String>,
}

impl ExportEntry {
    #[must_use] 
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("Ordinal#{}", self.ordinal))
    }
}

impl ExportTable {
    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Option<&ExportEntry> {
        self.exports.iter().find(|e| e.name.as_deref() == Some(name))
    }

    #[must_use] 
    pub fn find_by_ordinal(&self, ordinal: u32) -> Option<&ExportEntry> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }
}

// ── C++ name demangling (lightweight, no external dep) ───────────────────────

#[must_use] 
pub fn demangle_msvc(mangled: &str) -> Option<String> {
    if !mangled.starts_with('?') { return None; }
    // Very basic heuristic — real implementation would use msvc-demangler crate
    let without_prefix = &mangled[1..];
    let parts: Vec<&str> = without_prefix.split('@').collect();
    if parts.len() >= 2 {
        let func_name = parts[0];
        let class_name = if parts.len() >= 3 { Some(parts[1]) } else { None };
        Some(class_name.map_or_else(|| func_name.to_string(), |cls| format!("{cls}::{func_name}")))
    } else {
        None
    }
}

#[must_use] 
pub fn demangle_itanium(mangled: &str) -> Option<String> {
    if !mangled.starts_with("_Z") { return None; }
    // Simplified: strip _Z prefix and try to read the length-prefixed name
    let rest = &mangled[2..];
    let mut result = String::new();
    let mut i = 0;
    while i < rest.len() {
        let c = rest.as_bytes()[i];
        if c.is_ascii_digit() {
            let len_start = i;
            while i < rest.len() && rest.as_bytes()[i].is_ascii_digit() { i += 1; }
            let len: usize = rest[len_start..i].parse().ok()?;
            if i + len <= rest.len() {
                if !result.is_empty() { result.push_str("::"); }
                result.push_str(&rest[i..i + len]);
                i += len;
            } else { break; }
        } else {
            break;
        }
    }
    if result.is_empty() { None } else { Some(result) }
}

#[must_use] 
pub fn demangle(name: &str) -> Option<String> {
    if name.starts_with('?') { return demangle_msvc(name); }
    if name.starts_with("_Z") || name.starts_with("__Z") { return demangle_itanium(name); }
    None
}
