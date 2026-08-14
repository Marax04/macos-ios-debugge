//! FLIRT match applicator — rename identified functions, mark library code,
//! update call-site comments in an in-memory function database.

use std::collections::HashSet;
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names and addresses sourced from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use std::fmt;

use crate::casts::usize_to_f64;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Unique address (RVA or VA) of a function.
pub type FuncAddr = u64;

/// Human-readable name for a function.
pub type FuncName = String;

/// Confidence level for a FLIRT identification (0..=100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Confidence(pub u8);

impl Confidence {
    pub const HIGH: Self = Self(90);
    pub const MEDIUM: Self = Self(70);
    pub const LOW: Self = Self(40);

    #[must_use] 
    pub fn new(v: u8) -> Self { Self(v.min(100)) }
    #[must_use] 
    pub const fn value(self) -> u8 { self.0 }
    #[must_use] 
    pub const fn is_high(self) -> bool { self.0 >= 85 }
    #[must_use] 
    pub const fn is_acceptable(self) -> bool { self.0 >= 50 }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

/// A resolved FLIRT match that has been validated and is ready to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedMatch {
    /// Address of the matched function.
    pub address: FuncAddr,
    /// Primary name from the signature.
    pub primary_name: FuncName,
    /// Optional alternative names (e.g., from public-name tail entries).
    pub alt_names: Vec<FuncName>,
    /// Library the function belongs to.
    pub library: String,
    /// Confidence score for this match.
    pub confidence: Confidence,
    /// Byte-offset of the reference module within the .sig file.
    pub module_offset: u32,
    /// CRC16 of the bytes immediately after the prefix.
    pub crc16: u16,
    /// Whether the CRC was actually verified.
    pub crc_verified: bool,
    /// Public names at various offsets within this function (tail entries).
    pub tail_names: Vec<(u16, FuncName)>,
    /// Referenced names from the signature (calls to other library fns).
    pub ref_names: Vec<(u16, FuncName)>,
}

/// Current state of a function in the in-memory database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FunctionState {
    /// No name assigned yet; auto-generated (e.g. `sub_XXXX`).
    Unknown,
    /// Named by user or debug info.
    UserNamed(FuncName),
    /// Named by a FLIRT match.
    FlirtNamed {
        name: FuncName,
        library: String,
        confidence: u8,
    },
    /// Conflicting FLIRT matches; kept for manual resolution.
    Conflict(Vec<FuncName>),
}

impl FunctionState {
    #[must_use] 
    pub const fn name(&self) -> Option<&str> {
        match self {
            Self::UserNamed(n) => Some(n.as_str()),
            Self::FlirtNamed { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }
    #[must_use] 
    pub const fn is_library(&self) -> bool {
        matches!(self, Self::FlirtNamed { .. })
    }
}

/// A single function entry in the function database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub address: FuncAddr,
    pub size: u32,
    pub state: FunctionState,
    /// Markdown-style comment attached at the function start.
    pub comment: Option<String>,
    /// Call-site comments keyed by call offset within function body.
    pub call_comments: HashMap<u16, String>,
    /// Whether this function is marked as library/runtime code.
    pub is_library: bool,
    /// Ordinal index within its module (if known).
    pub module_ordinal: Option<u32>,
}

impl FunctionEntry {
    #[must_use] 
    pub fn new(address: FuncAddr, size: u32) -> Self {
        Self {
            address,
            size,
            state: FunctionState::Unknown,
            comment: None,
            call_comments: HashMap::new(),
            is_library: false,
            module_ordinal: None,
        }
    }

    #[must_use] 
    pub fn display_name(&self) -> String {
        match &self.state {
            FunctionState::UserNamed(n) | FunctionState::FlirtNamed { name: n, .. } => n.clone(),
            FunctionState::Conflict(names) => format!("??_{}", names.first().map_or("conflict", std::string::String::as_str)),
            FunctionState::Unknown => format!("sub_{:08X}", self.address),
        }
    }
}

// ---------------------------------------------------------------------------
// Application result
// ---------------------------------------------------------------------------

/// Outcome of applying a single resolved match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApplyOutcome {
    /// Function was newly named.
    Applied {
        address: FuncAddr,
        old_name: Option<FuncName>,
        new_name: FuncName,
        confidence: Confidence,
    },
    /// Function was already named with identical name; no-op.
    AlreadyNamed {
        address: FuncAddr,
        name: FuncName,
    },
    /// Function was already named differently by user.
    UserNamePreserved {
        address: FuncAddr,
        existing: FuncName,
        proposed: FuncName,
    },
    /// A lower-confidence match was rejected in favour of an existing one.
    LowerConfidenceRejected {
        address: FuncAddr,
        existing_confidence: u8,
        proposed_confidence: u8,
    },
    /// Conflict added — multiple matches with equal confidence.
    Conflict {
        address: FuncAddr,
        names: Vec<FuncName>,
    },
    /// Address not found in function database.
    AddressNotFound(FuncAddr),
}

impl ApplyOutcome {
    #[must_use] 
    pub const fn address(&self) -> FuncAddr {
        match self {
            Self::Applied { address, .. }
            | Self::AlreadyNamed { address, .. }
            | Self::UserNamePreserved { address, .. }
            | Self::LowerConfidenceRejected { address, .. }
            | Self::Conflict { address, .. }
            | Self::AddressNotFound(address) => *address,
        }
    }
    #[must_use] 
    pub const fn was_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

// ---------------------------------------------------------------------------
// Application configuration
// ---------------------------------------------------------------------------

/// Boolean option flags for [`ApplyConfig`], packed into a `u8` to avoid the
/// `struct_excessive_bools` lint.  Access via the named getter/setter methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyFlags(u8);

impl ApplyFlags {
    const ALLOW_OVERWRITE_FLIRT: u8 = 0x01;
    const PROTECT_USER_NAMES: u8    = 0x02;
    const ATTACH_ENTRY_COMMENT: u8  = 0x04;
    const ANNOTATE_CALL_SITES: u8   = 0x08;
    const MARK_AS_LIBRARY: u8       = 0x10;
    const PROPAGATE_REF_NAMES: u8   = 0x20;

    /// All flags enabled (the default).
    pub const ALL: Self = Self(0x3F);

    const fn get(self, bit: u8) -> bool { self.0 & bit != 0 }
    const fn set(&mut self, bit: u8, v: bool) { if v { self.0 |= bit; } else { self.0 &= !bit; } }

    /// Overwrite existing FLIRT-assigned names when a higher-confidence match is found.
    #[must_use] pub const fn allow_overwrite_flirt(self) -> bool { self.get(Self::ALLOW_OVERWRITE_FLIRT) }
    /// Never overwrite user-assigned names.
    #[must_use] pub const fn protect_user_names(self) -> bool { self.get(Self::PROTECT_USER_NAMES) }
    /// Attach a comment describing the match at the function entry.
    #[must_use] pub const fn attach_entry_comment(self) -> bool { self.get(Self::ATTACH_ENTRY_COMMENT) }
    /// Annotate call sites inside the matched function with callee names.
    #[must_use] pub const fn annotate_call_sites(self) -> bool { self.get(Self::ANNOTATE_CALL_SITES) }
    /// Mark matched functions as library code.
    #[must_use] pub const fn mark_as_library(self) -> bool { self.get(Self::MARK_AS_LIBRARY) }
    /// Propagate `ref_names` by renaming referenced functions if unknown.
    #[must_use] pub const fn propagate_ref_names(self) -> bool { self.get(Self::PROPAGATE_REF_NAMES) }

    /// Set the `allow_overwrite_flirt` flag.
    pub const fn set_allow_overwrite_flirt(&mut self, v: bool) { self.set(Self::ALLOW_OVERWRITE_FLIRT, v); }
    /// Set the `protect_user_names` flag.
    pub const fn set_protect_user_names(&mut self, v: bool) { self.set(Self::PROTECT_USER_NAMES, v); }
    /// Set the `attach_entry_comment` flag.
    pub const fn set_attach_entry_comment(&mut self, v: bool) { self.set(Self::ATTACH_ENTRY_COMMENT, v); }
    /// Set the `annotate_call_sites` flag.
    pub const fn set_annotate_call_sites(&mut self, v: bool) { self.set(Self::ANNOTATE_CALL_SITES, v); }
    /// Set the `mark_as_library` flag.
    pub const fn set_mark_as_library(&mut self, v: bool) { self.set(Self::MARK_AS_LIBRARY, v); }
    /// Set the `propagate_ref_names` flag.
    pub const fn set_propagate_ref_names(&mut self, v: bool) { self.set(Self::PROPAGATE_REF_NAMES, v); }
}

impl Default for ApplyFlags {
    fn default() -> Self { Self::ALL }
}

/// Configuration for the FLIRT applicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyConfig {
    /// Minimum confidence threshold — matches below this are discarded.
    pub min_confidence: u8,
    /// Packed boolean option flags — see [`ApplyFlags`] getters/setters.
    pub flags: ApplyFlags,
    /// Comment template; use {name}, {library}, and {confidence} as placeholders.
    pub comment_template: String,
}

// Placeholder keys used in comment templates (avoids `literal_string_with_formatting_args` lint).
const TMPL_NAME: &str       = "{name}";
const TMPL_LIBRARY: &str    = "{library}";
const TMPL_CONFIDENCE: &str = "{confidence}";

impl Default for ApplyConfig {
    fn default() -> Self {
        Self {
            min_confidence: 50,
            flags: ApplyFlags::ALL,
            comment_template: "FLIRT: {name} [{library}] ({confidence})".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Function database
// ---------------------------------------------------------------------------

/// In-memory database of all functions in the target binary.
#[derive(Debug, Default)]
pub struct FunctionDatabase {
    entries: HashMap<FuncAddr, FunctionEntry>,
    /// Secondary index: name → address.
    name_index: HashMap<String, FuncAddr>,
}

impl FunctionDatabase {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, entry: FunctionEntry) {
        if let Some(name) = entry.state.name() {
            self.name_index.insert(name.to_owned(), entry.address);
        }
        self.entries.insert(entry.address, entry);
    }

    #[must_use] 
    pub fn get(&self, addr: FuncAddr) -> Option<&FunctionEntry> {
        self.entries.get(&addr)
    }

    pub fn get_mut(&mut self, addr: FuncAddr) -> Option<&mut FunctionEntry> {
        self.entries.get_mut(&addr)
    }

    #[must_use] 
    pub fn by_name(&self, name: &str) -> Option<&FunctionEntry> {
        self.name_index.get(name).and_then(|a| self.entries.get(a))
    }

    #[must_use] 
    pub fn len(&self) -> usize { self.entries.len() }
    #[must_use] 
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn library_functions(&self) -> impl Iterator<Item = &FunctionEntry> {
        self.entries.values().filter(|e| e.is_library)
    }

    pub fn named_functions(&self) -> impl Iterator<Item = &FunctionEntry> {
        self.entries.values().filter(|e| e.state.name().is_some())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FuncAddr, &FunctionEntry)> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&FuncAddr, &mut FunctionEntry)> {
        self.entries.iter_mut()
    }

    /// Rebuild the name→address secondary index.
    pub fn rebuild_index(&mut self) {
        self.name_index.clear();
        for (addr, entry) in &self.entries {
            if let Some(name) = entry.state.name() {
                self.name_index.insert(name.to_owned(), *addr);
            }
        }
    }

    /// Return percentage of functions that have been identified.
    #[must_use] 
    pub fn coverage_percent(&self) -> f64 {
        if self.entries.is_empty() { return 0.0; }
        let named = self.entries.values().filter(|e| e.is_library).count();
        usize_to_f64(named) / usize_to_f64(self.entries.len()) * 100.0
    }
}

// ---------------------------------------------------------------------------
// FLIRT Applicator
// ---------------------------------------------------------------------------

/// Statistics collected during an application pass.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ApplyStats {
    pub total_matches: usize,
    pub applied: usize,
    pub already_named: usize,
    pub user_preserved: usize,
    pub lower_confidence_rejected: usize,
    pub conflicts: usize,
    pub not_found: usize,
    pub tail_names_applied: usize,
    pub ref_names_propagated: usize,
}

impl ApplyStats {
    pub const fn merge(&mut self, other: &Self) {
        self.total_matches += other.total_matches;
        self.applied += other.applied;
        self.already_named += other.already_named;
        self.user_preserved += other.user_preserved;
        self.lower_confidence_rejected += other.lower_confidence_rejected;
        self.conflicts += other.conflicts;
        self.not_found += other.not_found;
        self.tail_names_applied += other.tail_names_applied;
        self.ref_names_propagated += other.ref_names_propagated;
    }
}

/// Core applicator: takes validated matches and applies them to a function database.
pub struct FlirtApplicator {
    config: ApplyConfig,
}

impl FlirtApplicator {
    #[must_use] 
    pub const fn new(config: ApplyConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(ApplyConfig::default())
    }

    /// Apply a single resolved match to the function database.
    pub fn apply_match(
        &self,
        db: &mut FunctionDatabase,
        m: &ResolvedMatch,
        stats: &mut ApplyStats,
    ) -> ApplyOutcome {
        stats.total_matches += 1;

        if m.confidence.value() < self.config.min_confidence {
            stats.lower_confidence_rejected += 1;
            return ApplyOutcome::LowerConfidenceRejected {
                address: m.address,
                existing_confidence: 0,
                proposed_confidence: m.confidence.value(),
            };
        }

        let outcome = match db.get(m.address) {
            None => {
                stats.not_found += 1;
                return ApplyOutcome::AddressNotFound(m.address);
            }
            Some(entry) => match &entry.state {
                FunctionState::Unknown => {
                    let old = None;
                    stats.applied += 1;
                    ApplyOutcome::Applied {
                        address: m.address,
                        old_name: old,
                        new_name: m.primary_name.clone(),
                        confidence: m.confidence,
                    }
                }
                FunctionState::UserNamed(existing) => {
                    if self.config.flags.protect_user_names() {
                        stats.user_preserved += 1;
                        return ApplyOutcome::UserNamePreserved {
                            address: m.address,
                            existing: existing.clone(),
                            proposed: m.primary_name.clone(),
                        };
                    }
                    stats.applied += 1;
                    ApplyOutcome::Applied {
                        address: m.address,
                        old_name: Some(existing.clone()),
                        new_name: m.primary_name.clone(),
                        confidence: m.confidence,
                    }
                }
                FunctionState::FlirtNamed { name: existing_name, confidence: existing_conf, .. } => {
                    if existing_name == &m.primary_name {
                        stats.already_named += 1;
                        return ApplyOutcome::AlreadyNamed {
                            address: m.address,
                            name: existing_name.clone(),
                        };
                    }
                    if !self.config.flags.allow_overwrite_flirt() || m.confidence.value() <= *existing_conf {
                        stats.lower_confidence_rejected += 1;
                        return ApplyOutcome::LowerConfidenceRejected {
                            address: m.address,
                            existing_confidence: *existing_conf,
                            proposed_confidence: m.confidence.value(),
                        };
                    }
                    stats.applied += 1;
                    ApplyOutcome::Applied {
                        address: m.address,
                        old_name: Some(existing_name.clone()),
                        new_name: m.primary_name.clone(),
                        confidence: m.confidence,
                    }
                }
                FunctionState::Conflict(names) => {
                    let mut all = names.clone();
                    if !all.contains(&m.primary_name) {
                        all.push(m.primary_name.clone());
                    }
                    stats.conflicts += 1;
                    ApplyOutcome::Conflict {
                        address: m.address,
                        names: all,
                    }
                }
            },
        };

        self.commit_and_propagate(db, m, stats, &outcome);
        outcome
    }

    /// Commit a resolved match outcome to the database and apply tail/ref-name propagation.
    fn commit_and_propagate(
        &self,
        db: &mut FunctionDatabase,
        m: &ResolvedMatch,
        stats: &mut ApplyStats,
        outcome: &ApplyOutcome,
    ) {
        // Commit the change.
        if let Some(entry) = db.get_mut(m.address) {
            match outcome {
                ApplyOutcome::Applied { new_name, confidence, .. } => {
                    entry.state = FunctionState::FlirtNamed {
                        name: new_name.clone(),
                        library: m.library.clone(),
                        confidence: confidence.value(),
                    };
                    if self.config.flags.mark_as_library() {
                        entry.is_library = true;
                    }
                    if self.config.flags.attach_entry_comment() {
                        let comment = self.config.comment_template
                            .replace(TMPL_NAME, new_name)
                            .replace(TMPL_LIBRARY, &m.library)
                            .replace(TMPL_CONFIDENCE, &confidence.to_string());
                        entry.comment = Some(comment);
                    }
                    if self.config.flags.annotate_call_sites() {
                        for (offset, callee) in &m.ref_names {
                            let comment = format!("→ {callee}");
                            entry.call_comments.insert(*offset, comment);
                        }
                    }
                }
                ApplyOutcome::Conflict { names, .. } => {
                    entry.state = FunctionState::Conflict(names.clone());
                }
                _ => {}
            }
        }

        if !matches!(outcome, ApplyOutcome::Applied { .. }) {
            return;
        }

        // Apply tail-entry names (public symbols at offsets within this fn).
        for (offset, tail_name) in &m.tail_names {
            let tail_addr = m.address + u64::from(*offset);
            if db.get(tail_addr).is_none() {
                let mut tail_entry = FunctionEntry::new(tail_addr, 0);
                tail_entry.state = FunctionState::FlirtNamed {
                    name: tail_name.clone(),
                    library: m.library.clone(),
                    confidence: m.confidence.value(),
                };
                tail_entry.is_library = self.config.flags.mark_as_library();
                db.insert(tail_entry);
                stats.tail_names_applied += 1;
            }
        }

        // Propagate ref_names to unknown functions.
        if self.config.flags.propagate_ref_names() {
            for (_offset, ref_name) in &m.ref_names {
                // We don't have the call target address here, so we do a name-based lookup.
                // If the function is already named identically, skip; otherwise this is a hint.
                if db.by_name(ref_name).is_none() {
                    stats.ref_names_propagated += 1;
                    // Record it as a pending hint (not applied without an address).
                }
            }
        }
    }

    /// Apply a batch of resolved matches, returning all outcomes.
    pub fn apply_all(
        &self,
        db: &mut FunctionDatabase,
        matches: &[ResolvedMatch],
    ) -> (Vec<ApplyOutcome>, ApplyStats) {
        let mut stats = ApplyStats::default();
        let outcomes: Vec<ApplyOutcome> = matches
            .iter()
            .map(|m| self.apply_match(db, m, &mut stats))
            .collect();
        db.rebuild_index();
        (outcomes, stats)
    }

    /// Apply matches, then run a second pass using `ref_name` resolution to name
    /// any indirectly identified functions. Returns additional outcomes from
    /// the second pass.
    pub fn apply_with_propagation(
        &self,
        db: &mut FunctionDatabase,
        matches: &[ResolvedMatch],
        addr_by_name: &HashMap<String, FuncAddr>,
    ) -> (Vec<ApplyOutcome>, ApplyStats) {
        let (mut outcomes, mut stats) = self.apply_all(db, matches);

        // Second pass: resolve ref_names that have a known address.
        let mut ref_hits: Vec<ResolvedMatch> = Vec::new();
        for m in matches {
            for (_offset, ref_name) in &m.ref_names {
                if let Some(&ref_addr) = addr_by_name.get(ref_name.as_str())
                    && db.get(ref_addr).is_some_and(|e| matches!(e.state, FunctionState::Unknown)) {
                        ref_hits.push(ResolvedMatch {
                            address: ref_addr,
                            primary_name: ref_name.clone(),
                            alt_names: vec![],
                            library: m.library.clone(),
                            confidence: Confidence::new(m.confidence.value().saturating_sub(10)),
                            module_offset: 0,
                            crc16: 0,
                            crc_verified: false,
                            tail_names: vec![],
                            ref_names: vec![],
                        });
                    }
            }
        }

        // Deduplicate ref_hits by address, keeping highest confidence.
        let mut deduped: HashMap<FuncAddr, ResolvedMatch> = HashMap::new();
        for hit in ref_hits {
            deduped.entry(hit.address)
                .and_modify(|e| { if hit.confidence > e.confidence { *e = hit.clone(); } })
                .or_insert(hit);
        }

        let (extra_outcomes, extra_stats) = self.apply_all(db, &deduped.into_values().collect::<Vec<_>>());
        outcomes.extend(extra_outcomes);
        stats.merge(&extra_stats);
        (outcomes, stats)
    }

    /// Return the current configuration.
    #[must_use] 
    pub const fn config(&self) -> &ApplyConfig { &self.config }

    /// Update configuration.
    pub fn set_config(&mut self, config: ApplyConfig) { self.config = config; }
}

// ---------------------------------------------------------------------------
// Library-code marker
// ---------------------------------------------------------------------------

/// Mark all functions identified as library code across the whole database.
pub fn mark_library_functions(db: &mut FunctionDatabase) {
    for entry in db.entries.values_mut() {
        if matches!(&entry.state, FunctionState::FlirtNamed { .. }) {
            entry.is_library = true;
        }
    }
}

/// Return a set of addresses identified as library functions.
#[must_use] 
pub fn collect_library_addrs(db: &FunctionDatabase) -> HashSet<FuncAddr> {
    db.library_functions().map(|e| e.address).collect()
}

// ---------------------------------------------------------------------------
// Comment helpers
// ---------------------------------------------------------------------------

/// Format a call-site comment for a reference name at an offset within a function.
#[must_use] 
pub fn format_call_comment(ref_name: &str, offset: u16) -> String {
    format!("[+{offset:#06x}] → {ref_name}")
}

/// Attach call-site comments to the function at `base_addr` for every `ref_name`
/// in a match, using the actual call-target address from `addr_by_name`.
pub fn annotate_call_sites_full(
    db: &mut FunctionDatabase,
    base_addr: FuncAddr,
    ref_names: &[(u16, FuncName)],
    addr_by_name: &HashMap<String, FuncAddr>,
) {
    if let Some(entry) = db.get_mut(base_addr) {
        for (offset, ref_name) in ref_names {
            let target_info = addr_by_name
                .get(ref_name.as_str()).map_or_else(|| ref_name.clone(), |a| format!("{ref_name} @ {a:#010x}"));
            entry.call_comments.insert(*offset, format!("call {target_info}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Serialise the entire function database to JSON.
///
/// # Errors
///
/// Returns a `serde_json::Error` if serialisation fails.
pub fn db_to_json(db: &FunctionDatabase) -> Result<String, serde_json::Error> {
    let entries: Vec<&FunctionEntry> = db.entries.values().collect();
    serde_json::to_string_pretty(&entries)
}

/// Deserialise a list of `FunctionEntry` values and insert them into a new database.
///
/// # Errors
///
/// Returns a `serde_json::Error` if deserialisation fails.
pub fn db_from_json(json: &str) -> Result<FunctionDatabase, serde_json::Error> {
    let entries: Vec<FunctionEntry> = serde_json::from_str(json)?;
    let mut db = FunctionDatabase::new();
    for entry in entries {
        db.insert(entry);
    }
    Ok(db)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(addrs: &[u64]) -> FunctionDatabase {
        let mut db = FunctionDatabase::new();
        for &addr in addrs {
            db.insert(FunctionEntry::new(addr, 64));
        }
        db
    }

    fn make_match(addr: u64, name: &str, conf: u8) -> ResolvedMatch {
        ResolvedMatch {
            address: addr,
            primary_name: name.into(),
            alt_names: vec![],
            library: "libtest".into(),
            confidence: Confidence::new(conf),
            module_offset: 0,
            crc16: 0,
            crc_verified: false,
            tail_names: vec![],
            ref_names: vec![],
        }
    }

    #[test]
    fn test_apply_unknown() {
        let mut db = make_db(&[0x1000]);
        let applicator = FlirtApplicator::with_defaults();
        let mut stats = ApplyStats::default();
        let m = make_match(0x1000, "malloc", 90);
        let outcome = applicator.apply_match(&mut db, &m, &mut stats);
        assert!(outcome.was_applied());
        assert_eq!(stats.applied, 1);
        assert!(db.get(0x1000).unwrap().is_library);
    }

    #[test]
    fn test_protect_user_names() {
        let mut db = FunctionDatabase::new();
        let mut entry = FunctionEntry::new(0x2000, 32);
        entry.state = FunctionState::UserNamed("my_func".into());
        db.insert(entry);
        let applicator = FlirtApplicator::with_defaults();
        let mut stats = ApplyStats::default();
        let m = make_match(0x2000, "free", 95);
        let outcome = applicator.apply_match(&mut db, &m, &mut stats);
        assert!(matches!(outcome, ApplyOutcome::UserNamePreserved { .. }));
        assert_eq!(stats.user_preserved, 1);
    }

    #[test]
    fn test_lower_confidence_rejected() {
        let mut db = FunctionDatabase::new();
        let mut entry = FunctionEntry::new(0x3000, 32);
        entry.state = FunctionState::FlirtNamed {
            name: "strcpy".into(),
            library: "libc".into(),
            confidence: 95,
        };
        db.insert(entry);
        let applicator = FlirtApplicator::with_defaults();
        let mut stats = ApplyStats::default();
        let m = make_match(0x3000, "memcpy", 70);
        let _ = applicator.apply_match(&mut db, &m, &mut stats);
        assert_eq!(stats.lower_confidence_rejected, 1);
    }

    #[test]
    fn test_coverage_percent() {
        let mut db = make_db(&[0x100, 0x200, 0x300, 0x400]);
        let applicator = FlirtApplicator::with_defaults();
        let matches = vec![
            make_match(0x100, "fn_a", 90),
            make_match(0x200, "fn_b", 90),
        ];
        applicator.apply_all(&mut db, &matches);
        let cov = db.coverage_percent();
        assert!((cov - 50.0).abs() < 0.01, "expected 50%, got {cov}");
    }
}
