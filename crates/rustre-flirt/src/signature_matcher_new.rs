// signature_matcher_new.rs — Extended FLIRT matching with multi-lib support

// AHashMap prevents hash-collision DoS when keys are attacker-controlled library names.
use ahash::AHashMap;
use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::pat_parser::{matches_pat_entry, PatByte, PatEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtMatchNew {
    pub offset: u64,
    pub function_name: String,
    pub library_name: String,
    pub confidence: f64,
    pub alt_names: Vec<(u32, String)>,
}

pub struct FlirtMatcherNew {
    patterns: Vec<PatEntry>,
    library_name: String,
    ac: AhoCorasick,
    ac_map: Vec<usize>,
}

impl FlirtMatcherNew {
    /// # Errors
    /// Returns an error if the Aho-Corasick automaton fails to build.
    pub fn from_pat_entries(entries: Vec<PatEntry>, library_name: String) -> Result<Self> {
        let mut ac_patterns: Vec<Vec<u8>> = Vec::new();
        let mut ac_map: Vec<usize> = Vec::new();

        for (idx, entry) in entries.iter().enumerate() {
            let fixed: Vec<u8> = entry
                .initial_bytes
                .iter()
                .take(8)
                .take_while(|b| matches!(b, PatByte::Exact(_)))
                .map(|b| if let PatByte::Exact(v) = b { *v } else { 0 })
                .collect();

            if fixed.len() >= 4 {
                ac_patterns.push(fixed);
                ac_map.push(idx);
            }
        }

        let ac = if ac_patterns.is_empty() {
            AhoCorasick::new(std::iter::empty::<&[u8]>())?
        } else {
            AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build(&ac_patterns)?
        };

        Ok(Self { patterns: entries, library_name, ac, ac_map })
    }

    #[must_use] 
    pub fn scan(&self, data: &[u8]) -> Vec<FlirtMatchNew> {
        let mut results: Vec<FlirtMatchNew> = Vec::new();
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for mat in self.ac.find_iter(data) {
            let entry_idx = self.ac_map[mat.pattern().as_usize()];
            let offset = mat.start();
            if seen.contains(&(offset as u64)) { continue; }
            let entry = &self.patterns[entry_idx];
            if matches_pat_entry(entry, &data[offset..]) {
                seen.insert(offset as u64);
                results.push(FlirtMatchNew {
                    offset: offset as u64,
                    function_name: entry.primary_name.clone(),
                    library_name: self.library_name.clone(),
                    confidence: 0.95,
                    alt_names: entry.public_names.iter().map(|n| (n.offset, n.name.clone())).collect(),
                });
            }
        }

        results.sort_by_key(|m| m.offset);
        results
    }
}

pub struct MultiLibMatcherNew {
    matchers: Vec<FlirtMatcherNew>,
}

impl Default for MultiLibMatcherNew {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiLibMatcherNew {
    #[must_use] 
    pub const fn new() -> Self { Self { matchers: Vec::new() } }

    /// # Errors
    /// Returns an error if the Aho-Corasick automaton fails to build.
    pub fn add_library(&mut self, entries: Vec<PatEntry>, lib: String) -> Result<()> {
        self.matchers.push(FlirtMatcherNew::from_pat_entries(entries, lib)?);
        Ok(())
    }

    #[must_use] 
    pub fn scan_all(&self, data: &[u8]) -> Vec<FlirtMatchNew> {
        use rayon::prelude::*;
        let mut all: Vec<FlirtMatchNew> = self.matchers.par_iter()
            .flat_map(|m| m.scan(data))
            .collect();
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        all.retain(|m| seen.insert(m.offset));
        all.sort_by_key(|m| m.offset);
        all
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchStats {
    pub total: usize,
    pub by_library: AHashMap<String, usize>,
    pub coverage_pct: f64,
    pub avg_confidence: f64,
}

#[must_use] 
pub fn compute_match_stats(matches: &[FlirtMatchNew], total_funcs: usize) -> MatchStats {
    let mut by_library: AHashMap<String, usize> = AHashMap::new();
    for m in matches { *by_library.entry(m.library_name.clone()).or_insert(0) += 1; }
    let avg_conf = if matches.is_empty() { 0.0 }
        else { matches.iter().map(|m| m.confidence).sum::<f64>() / f64::from(u32::try_from(matches.len()).unwrap_or(u32::MAX)) };
    let coverage_pct = if total_funcs > 0 { f64::from(u32::try_from(matches.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total_funcs).unwrap_or(u32::MAX)) * 100.0 } else { 0.0 };
    MatchStats { total: matches.len(), by_library, coverage_pct, avg_confidence: avg_conf }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multi_lib_empty() {
        let m = MultiLibMatcherNew::new();
        assert_eq!(m.matchers.len(), 0);
        assert!(m.scan_all(&[0u8; 32]).is_empty());
    }
}
