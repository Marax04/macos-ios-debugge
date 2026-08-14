//! Malware family enrichment: merges Malpedia family data with local analysis results.
//!
//! Provides actor→family→sample mapping, MITRE technique attribution,
//! platform tagging, and confidence-scored family profiles.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK technique
// ──────────────────────────────────────────────────────────────────────────────

/// A single MITRE ATT&CK technique reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g. "T1071.001").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Tactic (e.g. "command-and-control").
    pub tactic: String,
    /// Optional sub-technique parent ID.
    pub parent_id: Option<String>,
}

impl MitreTechnique {
    /// Create a new technique.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, tactic: impl Into<String>) -> Self {
        let id = id.into();
        let parent_id = if id.contains('.') {
            id.split('.').next().map(str::to_string)
        } else {
            None
        };
        Self { id, name: name.into(), tactic: tactic.into(), parent_id }
    }

    /// Returns `true` if this is a sub-technique.
    #[must_use]
    pub const fn is_sub_technique(&self) -> bool {
        self.parent_id.is_some()
    }
}

impl std::fmt::Display for MitreTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} — {} ({})", self.id, self.name, self.tactic)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Sample metadata
// ──────────────────────────────────────────────────────────────────────────────

/// Local analysis metadata for a sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSampleMetadata {
    pub sha256: String,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    /// Import hash (MD5 of import table).
    pub imphash: Option<String>,
    /// TLSH fuzzy hash.
    pub tlsh: Option<String>,
    /// SSDEEP context-triggered piecewise hash.
    pub ssdeep: Option<String>,
    /// PE compile timestamp (Unix seconds).
    pub compile_timestamp: Option<u64>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// Detected packer name.
    pub packer: Option<String>,
    /// Target architecture.
    pub arch: Option<String>,
    /// File format.
    pub format: Option<String>,
    /// Rich header hash.
    pub rich_hash: Option<String>,
    /// Section names.
    pub sections: Vec<String>,
    /// Top imported DLL names.
    pub imported_dlls: Vec<String>,
    /// Interesting strings extracted from the binary.
    pub strings: Vec<String>,
    /// Analyst-assigned tags.
    pub tags: Vec<String>,
}

impl LocalSampleMetadata {
    /// Create a minimal record.
    #[must_use]
    pub fn new(sha256: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into(),
            sha1: None,
            md5: None,
            imphash: None,
            tlsh: None,
            ssdeep: None,
            compile_timestamp: None,
            file_size: None,
            packer: None,
            arch: None,
            format: None,
            rich_hash: None,
            sections: Vec::new(),
            imported_dlls: Vec::new(),
            strings: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Returns `true` if the sample appears to be packed.
    #[must_use]
    pub const fn is_packed(&self) -> bool {
        self.packer.is_some()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// EnrichedFamily
// ──────────────────────────────────────────────────────────────────────────────

/// An enriched malware family record combining Malpedia data with local analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedFamily {
    /// Malpedia canonical name.
    pub name: String,
    /// Common name.
    pub common_name: String,
    /// Malware type/category.
    pub malware_type: String,
    /// Operating system / platform.
    pub platform: String,
    /// Country of origin (ISO code).
    pub country: Option<String>,
    /// All known aliases.
    pub aliases: Vec<String>,
    /// Narrative description.
    pub description: Option<String>,
    /// MITRE ATT&CK techniques attributed to this family.
    pub techniques: Vec<MitreTechnique>,
    /// Actor names known to use this family.
    pub actor_names: Vec<String>,
    /// Known sample hashes (SHA-256).
    pub samples: Vec<String>,
    /// Local analysis metadata for matched samples.
    pub local_samples: Vec<LocalSampleMetadata>,
    /// YARA rules covering this family.
    pub yara_rules: Vec<String>,
    /// Reference URLs.
    pub references: Vec<String>,
    /// Enrichment confidence [0, 100].
    pub confidence: u8,
    /// Source systems that contributed data.
    pub sources: Vec<String>,
}

impl EnrichedFamily {
    /// Create a minimal enriched family.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            common_name: String::new(),
            malware_type: "unknown".to_string(),
            platform: "unknown".to_string(),
            country: None,
            aliases: Vec::new(),
            description: None,
            techniques: Vec::new(),
            actor_names: Vec::new(),
            samples: Vec::new(),
            local_samples: Vec::new(),
            yara_rules: Vec::new(),
            references: Vec::new(),
            confidence: 50,
            sources: Vec::new(),
        }
    }

    /// Add a MITRE technique.
    pub fn add_technique(&mut self, tech: MitreTechnique) {
        if !self.techniques.iter().any(|t| t.id == tech.id) {
            self.techniques.push(tech);
        }
    }

    /// Add a local sample.
    pub fn add_local_sample(&mut self, meta: LocalSampleMetadata) {
        if !self.samples.contains(&meta.sha256) {
            self.samples.push(meta.sha256.clone());
        }
        if !self.local_samples.iter().any(|s| s.sha256 == meta.sha256) {
            self.local_samples.push(meta);
        }
    }

    /// Returns the number of local samples matched to this family.
    #[must_use]
    pub const fn local_sample_count(&self) -> usize {
        self.local_samples.len()
    }

    /// Returns the set of tactics used by this family.
    #[must_use]
    pub fn tactics(&self) -> HashSet<&str> {
        self.techniques.iter().map(|t| t.tactic.as_str()).collect()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ActorFamilyMap
// ──────────────────────────────────────────────────────────────────────────────

/// Bidirectional mapping between actors and malware families.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActorFamilyMap {
    /// `actor_name` → set of family names.
    actor_to_families: HashMap<String, HashSet<String>>,
    /// `family_name` → set of actor names.
    family_to_actors: HashMap<String, HashSet<String>>,
}

impl ActorFamilyMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an actor→family association.
    pub fn add(&mut self, actor: impl Into<String>, family: impl Into<String>) {
        let actor = actor.into();
        let family = family.into();
        self.actor_to_families
            .entry(actor.clone())
            .or_default()
            .insert(family.clone());
        self.family_to_actors
            .entry(family)
            .or_default()
            .insert(actor);
    }

    /// Families attributed to `actor`.
    #[must_use]
    pub fn families_for_actor(&self, actor: &str) -> Vec<&str> {
        self.actor_to_families
            .get(actor)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Actors attributed to `family`.
    #[must_use]
    pub fn actors_for_family(&self, family: &str) -> Vec<&str> {
        self.family_to_actors
            .get(family)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Total number of actor→family associations.
    #[must_use]
    pub fn association_count(&self) -> usize {
        self.actor_to_families.values().map(HashSet::len).sum()
    }

    /// All known actor names.
    #[must_use]
    pub fn actors(&self) -> Vec<&str> {
        self.actor_to_families.keys().map(String::as_str).collect()
    }

    /// All known family names.
    #[must_use]
    pub fn families(&self) -> Vec<&str> {
        self.family_to_actors.keys().map(String::as_str).collect()
    }

    /// Merge another map into this one.
    pub fn merge(&mut self, other: Self) {
        for (actor, families) in other.actor_to_families {
            for family in families {
                self.add(actor.clone(), family);
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MitreKnowledgeBase
// ──────────────────────────────────────────────────────────────────────────────

/// Lightweight ATT&CK knowledge base for technique lookup.
#[derive(Debug, Clone, Default)]
pub struct MitreKnowledgeBase {
    techniques: HashMap<String, MitreTechnique>,
}

impl MitreKnowledgeBase {
    /// Create an empty knowledge base.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a knowledge base with commonly observed malware techniques.
    #[must_use]
    pub fn with_common_techniques() -> Self {
        let mut kb = Self::new();
        kb.add(MitreTechnique::new("T1071", "Application Layer Protocol", "command-and-control"));
        kb.add(MitreTechnique::new("T1071.001", "Web Protocols", "command-and-control"));
        kb.add(MitreTechnique::new("T1071.004", "DNS", "command-and-control"));
        kb.add(MitreTechnique::new("T1055", "Process Injection", "defense-evasion"));
        kb.add(MitreTechnique::new("T1055.001", "DLL Injection", "defense-evasion"));
        kb.add(MitreTechnique::new("T1059", "Command and Scripting Interpreter", "execution"));
        kb.add(MitreTechnique::new("T1059.003", "Windows Command Shell", "execution"));
        kb.add(MitreTechnique::new("T1059.001", "PowerShell", "execution"));
        kb.add(MitreTechnique::new("T1486", "Data Encrypted for Impact", "impact"));
        kb.add(MitreTechnique::new("T1027", "Obfuscated Files or Information", "defense-evasion"));
        kb.add(MitreTechnique::new("T1105", "Ingress Tool Transfer", "command-and-control"));
        kb.add(MitreTechnique::new("T1003", "OS Credential Dumping", "credential-access"));
        kb.add(MitreTechnique::new("T1003.001", "LSASS Memory", "credential-access"));
        kb.add(MitreTechnique::new("T1566", "Phishing", "initial-access"));
        kb.add(MitreTechnique::new("T1566.001", "Spearphishing Attachment", "initial-access"));
        kb.add(MitreTechnique::new("T1041", "Exfiltration Over C2 Channel", "exfiltration"));
        kb.add(MitreTechnique::new("T1082", "System Information Discovery", "discovery"));
        kb.add(MitreTechnique::new("T1083", "File and Directory Discovery", "discovery"));
        kb.add(MitreTechnique::new("T1112", "Modify Registry", "defense-evasion"));
        kb.add(MitreTechnique::new("T1547.001", "Registry Run Keys / Startup Folder", "persistence"));
        kb
    }

    /// Add a technique.
    pub fn add(&mut self, tech: MitreTechnique) {
        self.techniques.insert(tech.id.clone(), tech);
    }

    /// Look up a technique by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Resolve a list of technique IDs to full `MitreTechnique` records.
    #[must_use]
    pub fn resolve_ids(&self, ids: &[String]) -> Vec<MitreTechnique> {
        ids.iter()
            .filter_map(|id| self.get(id))
            .cloned()
            .collect()
    }

    /// All techniques in the knowledge base.
    #[must_use]
    pub fn all(&self) -> Vec<&MitreTechnique> {
        self.techniques.values().collect()
    }

    /// All techniques for a given tactic.
    #[must_use]
    pub fn by_tactic(&self, tactic: &str) -> Vec<&MitreTechnique> {
        self.techniques
            .values()
            .filter(|t| t.tactic == tactic)
            .collect()
    }

    /// Total technique count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.techniques.len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// FamilyEnrichmentEngine
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the enrichment engine.
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    /// Minimum confidence threshold [0, 100] for an enrichment to be included.
    pub min_confidence: u8,
    /// Whether to resolve MITRE techniques from IDs.
    pub resolve_techniques: bool,
    /// Whether to merge actor attribution.
    pub merge_actors: bool,
    /// Whether to include local sample metadata.
    pub include_local_samples: bool,
    /// Maximum number of samples to include per family.
    pub max_samples_per_family: usize,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            min_confidence: 30,
            resolve_techniques: true,
            merge_actors: true,
            include_local_samples: true,
            max_samples_per_family: 100,
        }
    }
}

/// Result of an enrichment operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// Enriched family record.
    pub family: EnrichedFamily,
    /// Number of local samples matched.
    pub matched_samples: usize,
    /// Number of new techniques added.
    pub techniques_added: usize,
    /// Number of actor associations added.
    pub actors_added: usize,
    /// Enrichment warnings.
    pub warnings: Vec<String>,
}

/// Enriches malware family records by merging Malpedia data with local analysis.
#[derive(Debug)]
pub struct FamilyEnrichmentEngine {
    config: EnrichmentConfig,
    actor_map: ActorFamilyMap,
    mitre_kb: MitreKnowledgeBase,
    /// Hash → family name index (SHA-256 / SHA-1 / MD5 / imphash).
    hash_index: HashMap<String, String>,
}

impl FamilyEnrichmentEngine {
    /// Create a new engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EnrichmentConfig::default(),
            actor_map: ActorFamilyMap::new(),
            mitre_kb: MitreKnowledgeBase::with_common_techniques(),
            hash_index: HashMap::new(),
        }
    }

    /// Create with a custom config.
    #[must_use]
    pub fn with_config(config: EnrichmentConfig) -> Self {
        Self { config, ..Self::new() }
    }

    /// Register actor→family associations.
    pub fn register_actor_families(&mut self, actor: &str, families: &[String]) {
        for family in families {
            self.actor_map.add(actor, family.as_str());
        }
    }

    /// Index a Malpedia family's known sample hashes.
    pub fn index_family_hashes(&mut self, family_name: &str, sha256s: &[String]) {
        for hash in sha256s {
            self.hash_index.insert(hash.to_lowercase(), family_name.to_string());
        }
    }

    /// Look up which family a hash belongs to.
    #[must_use]
    pub fn lookup_family_by_hash(&self, hash: &str) -> Option<&str> {
        self.hash_index.get(&hash.to_lowercase()).map(String::as_str)
    }

    /// Build an `EnrichedFamily` from raw Malpedia data.
    #[must_use]
    pub fn enrich_family(
        &self,
        name: &str,
        common_name: &str,
        malware_type: &str,
        platform: &str,
        description: Option<&str>,
        aliases: Vec<String>,
        technique_ids: Vec<String>,
        known_samples: Vec<String>,
        references: Vec<String>,
        local_samples: Vec<LocalSampleMetadata>,
    ) -> EnrichmentResult {
        let mut family = EnrichedFamily::new(name);
        family.common_name = common_name.to_string();
        family.malware_type = malware_type.to_string();
        family.platform = platform.to_string();
        family.description = description.map(str::to_string);
        family.aliases = aliases;
        family.references = references;
        family.samples = known_samples;
        family.sources.push("malpedia".to_string());

        // Resolve MITRE techniques
        let techniques_added = if self.config.resolve_techniques {
            let techs = self.mitre_kb.resolve_ids(&technique_ids);
            let count = techs.len();
            for tech in techs {
                family.add_technique(tech);
            }
            // Add unresolved IDs as stubs
            for id in &technique_ids {
                if !family.techniques.iter().any(|t| &t.id == id) {
                    family.add_technique(MitreTechnique {
                        id: id.clone(),
                        name: format!("Unknown ({id})"),
                        tactic: "unknown".to_string(),
                        parent_id: None,
                    });
                }
            }
            count
        } else {
            0
        };

        // Merge actor attributions
        let actors_added = if self.config.merge_actors {
            let actors = self.actor_map.actors_for_family(name);
            let count = actors.len();
            family.actor_names = actors.iter().map(ToString::to_string).collect();
            count
        } else {
            0
        };

        // Add local samples
        let mut matched_samples = 0;
        if self.config.include_local_samples {
            let limit = self.config.max_samples_per_family;
            for meta in local_samples.into_iter().take(limit) {
                family.add_local_sample(meta);
                matched_samples += 1;
            }
        }

        // Compute confidence
        family.confidence = compute_confidence(
            !family.actor_names.is_empty(),
            !family.techniques.is_empty(),
            matched_samples,
            !family.yara_rules.is_empty(),
        );

        let mut warnings = Vec::new();
        if family.confidence < self.config.min_confidence {
            warnings.push(format!(
                "confidence {} below threshold {}",
                family.confidence, self.config.min_confidence
            ));
        }

        EnrichmentResult {
            family,
            matched_samples,
            techniques_added,
            actors_added,
            warnings,
        }
    }

    /// Merge data from a secondary Malpedia source into an existing family.
    pub fn merge_into(&self, target: &mut EnrichedFamily, source: &EnrichedFamily) {
        // Merge aliases
        for alias in &source.aliases {
            if !target.aliases.contains(alias) {
                target.aliases.push(alias.clone());
            }
        }
        // Merge techniques
        for tech in &source.techniques {
            target.add_technique(tech.clone());
        }
        // Merge actor names
        for actor in &source.actor_names {
            if !target.actor_names.contains(actor) {
                target.actor_names.push(actor.clone());
            }
        }
        // Merge samples
        for sha in &source.samples {
            if !target.samples.contains(sha) {
                target.samples.push(sha.clone());
            }
        }
        // Merge YARA rules
        for rule in &source.yara_rules {
            if !target.yara_rules.contains(rule) {
                target.yara_rules.push(rule.clone());
            }
        }
        // Merge references
        for r in &source.references {
            if !target.references.contains(r) {
                target.references.push(r.clone());
            }
        }
        // Merge sources
        for s in &source.sources {
            if !target.sources.contains(s) {
                target.sources.push(s.clone());
            }
        }
        // Recompute confidence
        target.confidence = target.confidence.max(source.confidence);
    }

    /// Enrich multiple families in batch.
    #[must_use] pub fn enrich_batch(
        &self,
        families: Vec<(String, String, String, Vec<String>)>,
    ) -> Vec<EnrichmentResult> {
        families
            .into_iter()
            .map(|(name, common, malware_type, tech_ids)| {
                self.enrich_family(
                    &name,
                    &common,
                    &malware_type,
                    "win",
                    None,
                    Vec::new(),
                    tech_ids,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect()
    }

    /// Generate an actor-to-family attribution report.
    #[must_use]
    pub fn actor_attribution_report(&self) -> ActorAttributionReport {
        let mut actor_entries: Vec<ActorEntry> = self
            .actor_map
            .actors()
            .iter()
            .map(|actor| {
                let families = self
                    .actor_map
                    .families_for_actor(actor)
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                ActorEntry { actor: (*actor).to_owned(), families, confidence: 70 }
            })
            .collect();
        actor_entries.sort_by(|a, b| a.actor.cmp(&b.actor));
        ActorAttributionReport {
            entries: actor_entries,
            total_associations: self.actor_map.association_count(),
        }
    }
}

impl Default for FamilyEnrichmentEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_confidence(
    has_actor: bool,
    has_techniques: bool,
    local_samples: usize,
    has_yara: bool,
) -> u8 {
    let mut score: u32 = 30; // base
    if has_actor { score += 20; }
    if has_techniques { score += 15; }
    if local_samples > 0 { score += 20; }
    if local_samples > 5 { score += 10; }
    if has_yara { score += 15; }
    score.min(100) as u8
}

// ──────────────────────────────────────────────────────────────────────────────
// Report types
// ──────────────────────────────────────────────────────────────────────────────

/// One entry in an actor attribution report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorEntry {
    pub actor: String,
    pub families: Vec<String>,
    pub confidence: u8,
}

/// Full actor attribution report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorAttributionReport {
    pub entries: Vec<ActorEntry>,
    pub total_associations: usize,
}

impl ActorAttributionReport {
    /// Find all families attributed to `actor`.
    #[must_use]
    pub fn families_for(&self, actor: &str) -> Vec<&str> {
        self.entries
            .iter()
            .find(|e| e.actor == actor)
            .map(|e| e.families.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PlatformClassifier
// ──────────────────────────────────────────────────────────────────────────────

/// Classifies a family by platform from its Malpedia name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Android,
    Ios,
    MultiPlatform,
    Unknown,
}

impl Platform {
    /// Parse from a Malpedia family name prefix (e.g. "win", "linux").
    #[must_use]
    pub fn from_prefix(prefix: &str) -> Self {
        match prefix.to_lowercase().as_str() {
            "win" | "win32" | "win64" => Self::Windows,
            "linux" => Self::Linux,
            "osx" | "macos" | "mac" => Self::MacOS,
            "android" => Self::Android,
            "ios" | "iphone" => Self::Ios,
            "multi" | "cross" => Self::MultiPlatform,
            _ => Self::Unknown,
        }
    }

    /// Parse from a Malpedia canonical family name (e.g. "win.emotet").
    #[must_use]
    pub fn from_family_name(name: &str) -> Self {
        name.split('.').next().map_or(Self::Unknown, Self::from_prefix)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOS => "macOS",
            Self::Android => "Android",
            Self::Ios => "iOS",
            Self::MultiPlatform => "Multi-Platform",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> FamilyEnrichmentEngine {
        let mut e = FamilyEnrichmentEngine::new();
        e.register_actor_families("APT28", &["win.x_agent".to_string(), "win.sofacy".to_string()]);
        e.register_actor_families("Lazarus", &["win.wannacry".to_string()]);
        e.index_family_hashes("win.emotet", &["deadbeef".to_string(), "aabbccdd".to_string()]);
        e
    }

    #[test]
    fn test_enrich_family_basic() {
        let e = engine();
        let result = e.enrich_family(
            "win.emotet",
            "Emotet",
            "trojan",
            "win",
            Some("Banking trojan"),
            vec!["Heodo".into()],
            vec!["T1071".into(), "T1055".into()],
            vec!["deadbeef".into()],
            vec![],
            vec![],
        );
        assert_eq!(result.family.name, "win.emotet");
        assert_eq!(result.family.common_name, "Emotet");
        assert!(!result.family.techniques.is_empty());
    }

    #[test]
    fn test_enrich_family_merges_actors() {
        let e = engine();
        let result = e.enrich_family(
            "win.x_agent",
            "X-Agent",
            "backdoor",
            "win",
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(result.family.actor_names.contains(&"APT28".to_string()));
    }

    #[test]
    fn test_lookup_family_by_hash() {
        let e = engine();
        assert_eq!(e.lookup_family_by_hash("deadbeef"), Some("win.emotet"));
        assert_eq!(e.lookup_family_by_hash("DEADBEEF"), Some("win.emotet")); // case-insensitive
        assert!(e.lookup_family_by_hash("notfound").is_none());
    }

    #[test]
    fn test_actor_family_map_bidirectional() {
        let mut map = ActorFamilyMap::new();
        map.add("APT28", "win.x_agent");
        map.add("APT28", "win.sofacy");
        map.add("Lazarus", "win.wannacry");

        let fams = map.families_for_actor("APT28");
        assert!(fams.contains(&"win.x_agent"));
        assert!(fams.contains(&"win.sofacy"));

        let actors = map.actors_for_family("win.wannacry");
        assert!(actors.contains(&"Lazarus"));
    }

    #[test]
    fn test_actor_family_map_count() {
        let mut map = ActorFamilyMap::new();
        map.add("A", "F1");
        map.add("A", "F2");
        map.add("B", "F1");
        assert_eq!(map.association_count(), 3);
    }

    #[test]
    fn test_actor_family_map_merge() {
        let mut map1 = ActorFamilyMap::new();
        map1.add("A", "F1");
        let mut map2 = ActorFamilyMap::new();
        map2.add("B", "F2");
        map1.merge(map2);
        assert_eq!(map1.association_count(), 2);
    }

    #[test]
    fn test_mitre_kb_lookup() {
        let kb = MitreKnowledgeBase::with_common_techniques();
        let t = kb.get("T1071").unwrap();
        assert_eq!(t.tactic, "command-and-control");
        assert!(!t.is_sub_technique());
    }

    #[test]
    fn test_mitre_kb_sub_technique() {
        let kb = MitreKnowledgeBase::with_common_techniques();
        let t = kb.get("T1071.001").unwrap();
        assert!(t.is_sub_technique());
        assert_eq!(t.parent_id.as_deref(), Some("T1071"));
    }

    #[test]
    fn test_mitre_kb_by_tactic() {
        let kb = MitreKnowledgeBase::with_common_techniques();
        let c2 = kb.by_tactic("command-and-control");
        assert!(!c2.is_empty());
        for t in &c2 {
            assert_eq!(t.tactic, "command-and-control");
        }
    }

    #[test]
    fn test_platform_from_family_name() {
        assert_eq!(Platform::from_family_name("win.emotet"), Platform::Windows);
        assert_eq!(Platform::from_family_name("linux.mirai"), Platform::Linux);
        assert_eq!(Platform::from_family_name("android.anubis"), Platform::Android);
        assert_eq!(Platform::from_family_name("osx.flashback"), Platform::MacOS);
        assert_eq!(Platform::from_family_name("unknown_thing"), Platform::Unknown);
    }

    #[test]
    fn test_enriched_family_tactics() {
        let mut f = EnrichedFamily::new("win.test");
        f.add_technique(MitreTechnique::new("T1071", "App Layer Protocol", "command-and-control"));
        f.add_technique(MitreTechnique::new("T1055", "Process Injection", "defense-evasion"));
        let tactics = f.tactics();
        assert!(tactics.contains("command-and-control"));
        assert!(tactics.contains("defense-evasion"));
    }

    #[test]
    fn test_enriched_family_dedup_techniques() {
        let mut f = EnrichedFamily::new("win.test");
        let t = MitreTechnique::new("T1071", "App Layer Protocol", "command-and-control");
        f.add_technique(t.clone());
        f.add_technique(t);
        assert_eq!(f.techniques.len(), 1);
    }

    #[test]
    fn test_merge_into() {
        let e = engine();
        let mut target = EnrichedFamily::new("win.emotet");
        target.techniques.push(MitreTechnique::new("T1071", "A", "c2"));

        let mut source = EnrichedFamily::new("win.emotet");
        source.techniques.push(MitreTechnique::new("T1055", "B", "defense"));
        source.actor_names.push("TA505".to_string());

        e.merge_into(&mut target, &source);
        assert_eq!(target.techniques.len(), 2);
        assert!(target.actor_names.contains(&"TA505".to_string()));
    }

    #[test]
    fn test_enrich_batch() {
        let e = engine();
        let batch = vec![
            ("win.emotet".into(), "Emotet".into(), "trojan".into(), vec!["T1071".into()]),
            ("win.trickbot".into(), "TrickBot".into(), "trojan".into(), vec![]),
        ];
        let results = e.enrich_batch(batch);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_actor_attribution_report() {
        let e = engine();
        let report = e.actor_attribution_report();
        assert!(!report.entries.is_empty());
        assert!(report.total_associations >= 3);
    }

    #[test]
    fn test_local_sample_is_packed() {
        let mut s = LocalSampleMetadata::new("deadbeef");
        assert!(!s.is_packed());
        s.packer = Some("UPX".to_string());
        assert!(s.is_packed());
    }

    #[test]
    fn test_enriched_family_add_local_sample() {
        let mut f = EnrichedFamily::new("win.emotet");
        let s = LocalSampleMetadata::new("deadbeef");
        f.add_local_sample(s);
        assert_eq!(f.local_sample_count(), 1);
        // Adding same hash twice should not duplicate
        let s2 = LocalSampleMetadata::new("deadbeef");
        f.add_local_sample(s2);
        assert_eq!(f.local_sample_count(), 1);
    }

    #[test]
    fn test_confidence_increases_with_evidence() {
        let low = compute_confidence(false, false, 0, false);
        let high = compute_confidence(true, true, 10, true);
        assert!(high > low);
        assert!(high <= 100);
    }
}
