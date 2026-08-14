// Swift demangler — thin wrapper around the canonical implementation in
// `rustre-demangle::swift_demangler`.
//
// All core types (`SwiftNode`, `SwiftDemError`, `SwiftDemangler`,
// `swift_demangle`) are re-exported from the canonical crate.
// IPA-specific helpers (`demangle`, `demangle_batch`, `is_swift_symbol`,
// `demangle_with_stats`, `DemangleStats`, `group_by_module`,
// `extract_type_names`) are thin adapters that delegate to the canonical
// implementation and are kept here because they are IPA-domain conveniences.

pub use rustre_demangle::swift_demangler::{
    SwiftDemError, SwiftDemangler, SwiftNode, swift_demangle,
};

// ── IPA-specific helpers ──────────────────────────────────────────────────────

/// Attempt to demangle a Swift symbol.  Returns `None` if the input doesn't
/// look like a Swift mangled symbol.
#[must_use] 
pub fn demangle(sym: &str) -> Option<String> {
    if !SwiftDemangler::detect(sym) {
        return None;
    }
    let mut d = SwiftDemangler::new(sym);
    d.demangle().ok().map(|n| n.render())
}

/// Demangle a batch of symbols; non-Swift symbols produce `None`.
#[must_use] 
pub fn demangle_batch(syms: &[String]) -> Vec<(String, Option<String>)> {
    syms.iter()
        .map(|s| (s.clone(), demangle(s)))
        .collect()
}

/// Check whether `sym` looks like a Swift mangled symbol.
#[must_use] 
pub fn is_swift_symbol(sym: &str) -> bool {
    SwiftDemangler::detect(sym)
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DemangleStats {
    pub total: u32,
    pub demangled: u32,
    pub failed: u32,
}

impl DemangleStats {
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.demangled) / f64::from(self.total)
        }
    }
}

#[must_use] 
pub fn demangle_with_stats(syms: &[String]) -> (Vec<(String, Option<String>)>, DemangleStats) {
    let mut stats = DemangleStats {
        total: u32::try_from(syms.len()).unwrap_or(u32::MAX),
        ..Default::default()
    };
    let results = syms
        .iter()
        .map(|s| {
            let d = demangle(s);
            if d.is_some() {
                stats.demangled += 1;
            } else {
                stats.failed += 1;
            }
            (s.clone(), d)
        })
        .collect();
    (results, stats)
}

// ── Module grouping / type extraction ────────────────────────────────────────

/// Given a list of raw symbol strings, filter those that are Swift symbols
/// and return demangled names grouped by module.
#[must_use] 
pub fn group_by_module(syms: &[String]) -> std::collections::HashMap<String, Vec<String>> {
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for sym in syms {
        if let Some(demangled) = demangle(sym) {
            let module = demangled.split('.').next().unwrap_or("_").to_string();
            map.entry(module).or_default().push(demangled);
        }
    }
    map
}

/// Extract class/struct/enum names mentioned in Swift symbols.
#[must_use] 
pub fn extract_type_names(syms: &[String]) -> Vec<String> {
    let mut names = std::collections::HashSet::new();
    for sym in syms {
        if let Some(d) = demangle(sym) {
            for part in d.split('.') {
                let part = part.trim();
                if part.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                    let base = part.split('<').next().unwrap_or(part);
                    names.insert(base.to_string());
                }
            }
        }
    }
    let mut v: Vec<String> = names.into_iter().collect();
    v.sort();
    v
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_swift() {
        assert!(demangle("__objc_msgSend").is_none());
        assert!(demangle("malloc").is_none());
    }

    #[test]
    fn test_is_swift_symbol() {
        assert!(is_swift_symbol("$sSomeSymbol"));
        assert!(is_swift_symbol("_$sSomeSymbol"));
        assert!(!is_swift_symbol("_NSString"));
    }

    #[test]
    fn test_demangle_batch() {
        let syms = vec![
            "_NSString".to_string(),
            "$s4main3fooyyF".to_string(),
        ];
        let results = demangle_batch(&syms);
        assert!(results[0].1.is_none());
        assert!(results[1].1.is_some());
    }

    #[test]
    fn test_stats() {
        let syms = vec!["$s4main3fooyyF".to_string(), "malloc".to_string()];
        let (_, stats) = demangle_with_stats(&syms);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.demangled, 1);
        assert_eq!(stats.failed, 1);
        assert!((stats.success_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_group_by_module() {
        let syms = vec!["$s4main3fooyyF".to_string()];
        let groups = group_by_module(&syms);
        assert!(groups.contains_key("main") || !groups.is_empty());
    }
}
