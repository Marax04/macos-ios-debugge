// rustre-plugin-native/src/native_symbol_resolver.rs
//
// Symbol resolution helpers for native plugin shared libraries.

use crate::native_abi_bridge::{CallConv, FunctionPtr};
use libloading::Library;
use std::collections::HashMap;

// ── SymbolKind ───────────────────────────────────────────────────────────────

/// What kind of symbol a resolver entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// An exported function pointer.
    Function,
    /// An exported data symbol (variable).
    Data,
    /// A weak symbol whose absence is not an error.
    Weak,
}

impl SymbolKind {
    /// Human-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Data => "data",
            Self::Weak => "weak",
        }
    }
}

// ── ExportedSymbol ───────────────────────────────────────────────────────────

/// A symbol that the resolver looked up successfully (or attempted to).
#[derive(Debug, Clone)]
pub struct ExportedSymbol {
    /// Symbol name, exactly as it appears in the shared library's export table.
    pub name: String,
    /// What sort of symbol this is.
    pub kind: SymbolKind,
    /// Resolved address; `null` when lookup failed and `kind == Weak`.
    pub ptr: FunctionPtr,
}

impl ExportedSymbol {
    /// Whether the symbol was successfully located.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.ptr.is_resolved()
    }
}

// ── NativeSymbolResolver ─────────────────────────────────────────────────────

/// Resolves symbol names against a loaded `libloading::Library` and caches
/// the resulting `FunctionPtr` values.
///
/// The cache lives as long as the resolver. The underlying library must
/// outlive any pointer the resolver hands out (the caller is responsible for
/// keeping the `Library` alive — typically inside a `NativePluginLoader`).
pub struct NativeSymbolResolver {
    cache: HashMap<String, ExportedSymbol>,
    default_conv: CallConv,
}

impl Default for NativeSymbolResolver {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
            default_conv: CallConv::C,
        }
    }
}

impl std::fmt::Debug for NativeSymbolResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSymbolResolver")
            .field("cached", &self.cache.len())
            .field("default_conv", &self.default_conv)
            .finish()
    }
}

impl NativeSymbolResolver {
    /// Create an empty resolver that records all subsequent lookups with the
    /// `extern "C"` calling convention by default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the default calling convention recorded with each lookup.
    #[must_use]
    pub const fn with_default_conv(mut self, conv: CallConv) -> Self {
        self.default_conv = conv;
        self
    }

    /// Look up a required function symbol.
    ///
    /// # Errors
    ///
    /// Returns the underlying `libloading` error when the symbol is missing.
    pub fn resolve_function(
        &mut self,
        lib: &Library,
        name: &str,
    ) -> Result<FunctionPtr, libloading::Error> {
        if let Some(sym) = self.cache.get(name) {
            return Ok(sym.ptr);
        }
        // SAFETY: looking up an arbitrary symbol cannot violate memory
        // safety on its own; the caller is responsible for casting the
        // pointer to the correct signature before invocation.
        let raw: libloading::Symbol<'_, unsafe extern "C" fn()> =
            unsafe { lib.get(name.as_bytes()) }?;
        let addr = (*raw) as usize;
        let ptr = FunctionPtr::from_raw(addr, self.default_conv);
        self.cache.insert(
            name.to_string(),
            ExportedSymbol {
                name: name.to_string(),
                kind: SymbolKind::Function,
                ptr,
            },
        );
        Ok(ptr)
    }

    /// Look up an optional (weak) function symbol.  Never errors — a missing
    /// symbol is recorded with `FunctionPtr::null()`.
    pub fn resolve_weak(&mut self, lib: &Library, name: &str) -> ExportedSymbol {
        if let Some(sym) = self.cache.get(name) {
            return sym.clone();
        }
        let ptr = (unsafe { lib.get::<unsafe extern "C" fn()>(name.as_bytes()) })
            .map_or(FunctionPtr::null(), |s| {
                FunctionPtr::from_raw((*s) as usize, self.default_conv)
            });
        let sym = ExportedSymbol {
            name: name.to_string(),
            kind: SymbolKind::Weak,
            ptr,
        };
        self.cache.insert(name.to_string(), sym.clone());
        sym
    }

    /// Return a cached lookup, or `None` if the resolver has never tried to
    /// look up `name`.
    #[must_use]
    pub fn cached(&self, name: &str) -> Option<&ExportedSymbol> {
        self.cache.get(name)
    }

    /// Number of cached entries.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Drop all cached entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Iterate over every cached entry.
    pub fn iter(&self) -> impl Iterator<Item = &ExportedSymbol> {
        self.cache.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_kind_str() {
        assert_eq!(SymbolKind::Function.as_str(), "function");
        assert_eq!(SymbolKind::Data.as_str(), "data");
        assert_eq!(SymbolKind::Weak.as_str(), "weak");
    }

    #[test]
    fn resolver_starts_empty() {
        let r = NativeSymbolResolver::new();
        assert_eq!(r.cache_len(), 0);
        assert!(r.cached("anything").is_none());
    }

    #[test]
    fn resolver_clear() {
        let mut r = NativeSymbolResolver::new();
        r.cache.insert(
            "x".to_string(),
            ExportedSymbol {
                name: "x".to_string(),
                kind: SymbolKind::Function,
                ptr: FunctionPtr::from_raw(0x1000, CallConv::C),
            },
        );
        assert_eq!(r.cache_len(), 1);
        r.clear();
        assert_eq!(r.cache_len(), 0);
    }

    #[test]
    fn exported_symbol_resolved() {
        let s = ExportedSymbol {
            name: "f".to_string(),
            kind: SymbolKind::Function,
            ptr: FunctionPtr::from_raw(0x42, CallConv::C),
        };
        assert!(s.is_resolved());
    }

    #[test]
    fn exported_symbol_unresolved_weak() {
        let s = ExportedSymbol {
            name: "f".to_string(),
            kind: SymbolKind::Weak,
            ptr: FunctionPtr::null(),
        };
        assert!(!s.is_resolved());
    }
}
