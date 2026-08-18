//! `rustre-ti-malpedia`
//!
//! Malpedia malware knowledge base integration for the `RustRE` Suite.
//! Full async client with caching, family classification, actor attribution,
//! YARA rules, sample management, and offline local database support.

pub mod attribution_engine;
pub mod cache;
pub mod client;
pub mod error;
pub mod family_enrichment;
pub mod malpedia_client;
pub mod family_database;
pub mod family_profiles;
pub mod malpedia_yara;
pub mod matcher;
pub mod models;
pub mod navigator;
pub mod sample_search;
pub mod stats;
pub mod yara_download;
pub mod malpedia_family_db;
pub mod malpedia_sample_finder;
pub mod malpedia_yara_fetcher;

pub use malpedia_yara::{
    FamilyYara, MalpediaYara, RuleMetadata, YaraCache, YaraDownloader, YaraRule, YaraRuleSet,
};

pub use cache::MalpediaCache;
pub use client::MalpediaClient;
pub use error::MalpediaError;
pub use matcher::FamilyMatcher;
pub use models::{
    MalpediaActor, MalpediaFamily, MalpediaFamilySummary, MalpediaSample, MalpediaThreatActor,
};
pub use navigator::to_attack_navigator;
pub use sample_search::{
    ClusterReport, RelatedSampleSearch, SampleDatabase, SampleMatch, SampleMetadata,
};
pub use stats::{
    DatabaseStats, FamilyDistribution, TimelineEntry, actor_country_distribution,
    platform_distribution,
};

use async_trait::async_trait;
use rustre_threatintel::{IoC, IoCType, MalwareType, TiError, TiProvider, TiResult, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// MalpediaError re-export for convenience
// ---------------------------------------------------------------------------

/// All errors from the Malpedia integration layer.
#[derive(Debug, Clone)]
pub enum MalpediaClientError {
    /// Authentication required but no key provided.
    NotAuthenticated,
    /// The answer can only come from the live Malpedia service (or a local
    /// database supplied by the caller), and neither was available.
    ///
    /// This is returned INSTEAD of an invented family / sample / actor record.
    NetworkLookupRequired(String),
    /// The requested family was not found.
    FamilyNotFound(String),
    /// The requested actor was not found.
    ActorNotFound(String),
    /// The requested sample was not found.
    SampleNotFound(String),
    /// HTTP-level error.
    Http(String),
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// JSON parse error.
    Parse(String),
    /// Cache error.
    Cache(String),
    /// Database error.
    Database(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for MalpediaClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthenticated => write!(f, "Malpedia API key required"),
            Self::NetworkLookupRequired(what) => write!(
                f,
                "network lookup required for {what}: no Malpedia API key and no local                  database is configured, so no record was produced"
            ),
            Self::FamilyNotFound(n) => write!(f, "family not found: {n}"),
            Self::ActorNotFound(n) => write!(f, "actor not found: {n}"),
            Self::SampleNotFound(h) => write!(f, "sample not found: {h}"),
            Self::Http(m) => write!(f, "HTTP error: {m}"),
            Self::RateLimitExceeded => write!(f, "Malpedia rate limit exceeded"),
            Self::Parse(m) => write!(f, "parse error: {m}"),
            Self::Cache(m) => write!(f, "cache error: {m}"),
            Self::Database(m) => write!(f, "database error: {m}"),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for MalpediaClientError {}

// ---------------------------------------------------------------------------
// MalpediaApiKey
// ---------------------------------------------------------------------------

/// API key management for Malpedia authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaApiKey {
    /// The API key string.
    pub key: String,
    /// When this key was last rotated (Unix timestamp).
    pub created_at: u64,
    /// Whether this key has been validated against the Malpedia API.
    pub validated: bool,
    /// Optional label/description for this key.
    pub label: Option<String>,
}

impl MalpediaApiKey {
    /// Create a new API key.
    #[must_use]
    pub fn new(key: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            key,
            created_at: now,
            validated: false,
            label: None,
        }
    }

    /// Mark this key as validated.
    pub const fn mark_validated(&mut self) {
        self.validated = true;
    }

    /// Return `true` if the key is non-empty and has been validated against the API.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.key.is_empty() && self.validated
    }
}

// ---------------------------------------------------------------------------
// MalpediaStats
// ---------------------------------------------------------------------------

/// High-level statistics about the Malpedia knowledge base.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MalpediaStats {
    /// Total number of tracked malware families.
    pub family_count: u64,
    /// Total number of tracked threat actors.
    pub actor_count: u64,
    /// Total number of tracked samples.
    pub sample_count: u64,
    /// Total number of YARA rules.
    pub yara_rule_count: u64,
    /// Platform breakdowns (e.g. {"win": 1500, "linux": 200}).
    pub platform_breakdown: HashMap<String, u64>,
    /// Country-of-origin breakdown for actors.
    pub actor_country_breakdown: HashMap<String, u64>,
    /// Timestamp of the last statistics update.
    pub last_updated: u64,
}

impl MalpediaStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An EMPTY statistics snapshot — not a lookup.
    ///
    /// See the body: no corpus figures are invented here.
    #[must_use]
    pub fn mock() -> Self {
        // Malpedia corpus statistics are a property of the live service.  This
        // function has no network access, so it reports an EMPTY snapshot
        // (every counter zero, `last_updated` zero) rather than the invented
        // 2269 families / 80 actors / 12543 samples it used to return.
        // `MalpediaApiClient::get_stats` now returns
        // `MalpediaClientError::NetworkLookupRequired` for the same reason.
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// MalpediaFamilySpec (full spec-required type)
// ---------------------------------------------------------------------------

/// A Malpedia malware family record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaFamilySpec {
    /// Malpedia canonical name (e.g. `win.emotet`).
    pub name: String,
    /// Human-readable common name.
    pub common_name: String,
    /// Family classification string.
    pub malware_type: String,
    /// Alternative family names.
    pub aliases: Vec<String>,
    /// Target operating system / platform.
    pub platform: String,
    /// Country of origin (ISO code), if known.
    pub country: Option<String>,
    /// Optional description text.
    pub description: Option<String>,
    /// Embedded YARA rules for this family.
    pub yara_rules: Vec<String>,
    /// Known SHA-256 sample hashes.
    pub samples: Vec<String>,
    /// Reference URLs.
    pub references: Vec<String>,
    /// MITRE ATT&CK technique IDs.
    pub attack_techniques: Vec<String>,
    /// Analyst notes.
    pub notes: Option<String>,
    /// Malpedia family URL.
    pub url: Option<String>,
}

impl MalpediaFamilySpec {
    /// Derive the [`MalwareType`] for this family.
    #[must_use]
    pub fn as_malware_type(&self) -> MalwareType {
        MalpediaApiClient::family_to_malware_type(&self.malware_type)
    }

    /// Return `true` if the given SHA-256 is among the known samples.
    #[must_use]
    pub fn has_sample(&self, sha256: &str) -> bool {
        self.samples.iter().any(|s| s.eq_ignore_ascii_case(sha256))
    }

    /// Return the platform prefix (e.g. "win", "linux").
    #[must_use]
    pub fn platform_prefix(&self) -> &str {
        if let Some(dot) = self.name.find('.') {
            &self.name[..dot]
        } else {
            &self.platform
        }
    }
}

// ---------------------------------------------------------------------------
// MalpediaActorSpec
// ---------------------------------------------------------------------------

/// A Malpedia threat actor record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaActorSpec {
    /// Actor primary name.
    pub name: String,
    /// Alternative names / aliases.
    pub aliases: Vec<String>,
    /// ISO country code of suspected origin.
    pub country: Option<String>,
    /// Actor motivation.
    pub motivation: Option<String>,
    /// Target industry sectors.
    pub target_sectors: Vec<String>,
    /// Attributed malware family names.
    pub families: Vec<String>,
    /// MITRE ATT&CK group IDs.
    pub attack_groups: Vec<String>,
    /// Attribution confidence [0, 100].
    pub attribution_confidence: u8,
    /// Optional notes.
    pub notes: Option<String>,
    /// Reference URLs.
    pub references: Vec<String>,
}

impl MalpediaActorSpec {
    /// Create a minimal actor spec.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self {
            name,
            aliases: Vec::new(),
            country: None,
            motivation: None,
            target_sectors: Vec::new(),
            families: Vec::new(),
            attack_groups: Vec::new(),
            attribution_confidence: 50,
            notes: None,
            references: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MalpediaSampleSpec
// ---------------------------------------------------------------------------

/// A Malpedia malware sample record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaSampleSpec {
    /// SHA-256 hash of the sample.
    pub sha256: String,
    /// SHA-1 hash of the sample.
    pub sha1: Option<String>,
    /// MD5 hash of the sample.
    pub md5: Option<String>,
    /// Whether the sample appears packed.
    pub packed: bool,
    /// Target architecture (x86, x64, arm, etc.).
    pub architecture: Option<String>,
    /// File format (PE32, ELF, etc.).
    pub format: Option<String>,
    /// Version string from version resources.
    pub version: Option<String>,
    /// PE compile time (Unix timestamp).
    pub compile_time: Option<u64>,
    /// Associated malware family.
    pub family: String,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// Import hash.
    pub imphash: Option<String>,
}

impl MalpediaSampleSpec {
    /// Create a minimal sample record.
    #[must_use]
    pub const fn new(sha256: String, family: String) -> Self {
        Self {
            sha256,
            sha1: None,
            md5: None,
            packed: false,
            architecture: None,
            format: None,
            version: None,
            compile_time: None,
            family,
            file_size: None,
            imphash: None,
        }
    }
}

// ---------------------------------------------------------------------------
// MalpediaYaraRule
// ---------------------------------------------------------------------------

/// A Malpedia YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaYaraRule {
    /// Rule name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Rule strings (identifier → pattern).
    pub strings: Vec<(String, String)>,
    /// Condition expression.
    pub condition: String,
    /// Classification tags.
    pub tags: Vec<String>,
    /// Associated malware family.
    pub family: String,
    /// Author name.
    pub author: Option<String>,
    /// Rule date string.
    pub date: Option<String>,
    /// MD5 hash of the target sample.
    pub hash: Option<String>,
}

impl MalpediaYaraRule {
    /// Create a minimal YARA rule.
    #[must_use]
    pub fn new(name: String, family: String) -> Self {
        Self {
            name,
            description: String::new(),
            strings: Vec::new(),
            condition: "any of them".to_string(),
            tags: Vec::new(),
            family,
            author: None,
            date: None,
            hash: None,
        }
    }

    /// Generate a minimal YARA rule text representation.
    #[must_use]
    pub fn to_yara_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!("rule {} {{\n", self.name);
        if !self.tags.is_empty() {
            let _ = writeln!(s, "  tags: {}", self.tags.join(", "));
        }
        s.push_str("  meta:\n");
        let _ = writeln!(s, "    description = \"{}\"", self.description);
        let _ = writeln!(s, "    family = \"{}\"", self.family);
        if let Some(ref auth) = self.author {
            let _ = writeln!(s, "    author = \"{auth}\"");
        }
        s.push_str("  strings:\n");
        for (id, pat) in &self.strings {
            let _ = writeln!(s, "    ${id} = {pat}");
        }
        s.push_str("  condition:\n");
        let _ = writeln!(s, "    {}", self.condition);
        s.push_str("}\n");
        s
    }
}

// ---------------------------------------------------------------------------
// MalpediaSearchQuery
// ---------------------------------------------------------------------------

/// Builder for Malpedia search queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MalpediaSearchQuery {
    /// Search term (family name, hash, etc.).
    pub query: Option<String>,
    /// Filter by platform.
    pub platform: Option<String>,
    /// Filter by malware type.
    pub malware_type: Option<String>,
    /// Filter by country of origin.
    pub country: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Result offset (for pagination).
    pub offset: Option<usize>,
    /// Whether to include YARA rules in results.
    pub include_yara: bool,
    /// Whether to include samples in results.
    pub include_samples: bool,
}

impl MalpediaSearchQuery {
    /// Create an empty search query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the search term.
    #[must_use]
    pub fn with_query(mut self, q: impl Into<String>) -> Self {
        self.query = Some(q.into());
        self
    }

    /// Filter by platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Filter by malware type string.
    #[must_use]
    pub fn with_malware_type(mut self, t: impl Into<String>) -> Self {
        self.malware_type = Some(t.into());
        self
    }

    /// Set a limit on results.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Include YARA rules in results.
    #[must_use]
    pub const fn include_yara(mut self) -> Self {
        self.include_yara = true;
        self
    }

    /// Include samples in results.
    #[must_use]
    pub const fn include_samples(mut self) -> Self {
        self.include_samples = true;
        self
    }
}

// ---------------------------------------------------------------------------
// FamilyAliasResolver
// ---------------------------------------------------------------------------

/// Resolves family name aliases to their canonical Malpedia form.
#[derive(Debug, Clone)]
pub struct FamilyAliasResolver {
    /// Map of alias (lowercase) → canonical name.
    aliases: HashMap<String, String>,
}

impl FamilyAliasResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
        }
    }

    /// Load a default set of well-known aliases.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        // Well-known aliases
        r.register("heodo", "win.emotet");
        r.register("geodo", "win.emotet");
        r.register("emotet", "win.emotet");
        r.register("trickbot", "win.trickbot");
        r.register("trickybot", "win.trickbot");
        r.register("wannacrypt", "win.wannacry");
        r.register("wannacryptor", "win.wannacry");
        r.register("wcry", "win.wannacry");
        r.register("sofacy", "win.x_agent");
        r.register("fancy bear", "win.x_agent");
        r.register("cozycar", "win.cozycar");
        r.register("cozy bear", "win.cozycar");
        r.register("mimikatz", "win.mimikatz");
        r.register("notpetya", "win.notpetya");
        r.register("petya", "win.petya");
        r.register("ryuk", "win.ryuk");
        r.register("conti", "win.conti");
        r.register("lockbit", "win.lockbit");
        r.register("revil", "win.revil");
        r.register("sodinokibi", "win.revil");
        r.register("cobalt strike", "win.cobalt_strike");
        r.register("cobaltstrike", "win.cobalt_strike");
        r
    }

    /// Register an alias mapping.
    pub fn register(&mut self, alias: &str, canonical: &str) {
        self.aliases
            .insert(alias.to_lowercase(), canonical.to_string());
    }

    /// Resolve an alias to its canonical name.
    ///
    /// Returns `None` if the alias is not known.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&str> {
        self.aliases.get(&name.to_lowercase()).map(String::as_str)
    }

    /// Resolve or return the normalized original name.
    #[must_use]
    pub fn resolve_or_normalize(&self, name: &str) -> String {
        self.resolve(name).map_or_else(|| MalpediaApiClient::normalize_family_name(name), String::from)
    }

    /// Total number of registered aliases.
    #[must_use]
    pub fn count(&self) -> usize {
        self.aliases.len()
    }
}

impl Default for FamilyAliasResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FamilyClassifier
// ---------------------------------------------------------------------------

/// Scores samples against malware family signatures.
#[derive(Debug)]
pub struct FamilyClassifier {
    /// Family name → (description, type string, keywords).
    families: HashMap<String, (String, String, Vec<String>)>,
}

impl FamilyClassifier {
    /// Create an empty classifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: HashMap::new(),
        }
    }

    /// Register a family with keywords for classification.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        type_str: impl Into<String>,
        keywords: Vec<String>,
    ) {
        self.families
            .insert(name.into(), (description.into(), type_str.into(), keywords));
    }

    /// Score `content` against all registered families.
    ///
    /// Returns a sorted list of `(family_name, score)` from highest to lowest.
    #[must_use]
    pub fn score(&self, content: &str) -> Vec<(String, u32)> {
        let lower = content.to_lowercase();
        let mut scores: Vec<(String, u32)> = self
            .families
            .iter()
            .map(|(name, (_, _, keywords))| {
                let score: u32 = keywords
                    .iter()
                    .filter(|kw| lower.contains(kw.as_str()))
                    .count()
                    .try_into()
                    .unwrap_or(u32::MAX);
                (name.clone(), score)
            })
            .filter(|(_, s)| *s > 0)
            .collect();
        scores.sort_by(|a, b| b.1.cmp(&a.1));
        scores
    }

    /// Return the best-matching family, or `None` if no keywords match.
    #[must_use]
    pub fn classify(&self, content: &str) -> Option<String> {
        self.score(content).into_iter().next().map(|(n, _)| n)
    }

    /// Create a default classifier with common malware families.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut c = Self::new();
        c.register(
            "Emotet",
            "Banking trojan / loader",
            "trojan",
            vec![
                "emotet".to_string(),
                "heodo".to_string(),
                "geodo".to_string(),
            ],
        );
        c.register(
            "TrickBot",
            "Banking trojan",
            "trojan",
            vec![
                "trickbot".to_string(),
                "trick".to_string(),
                "anchor".to_string(),
            ],
        );
        c.register(
            "WannaCry",
            "Ransomware",
            "ransomware",
            vec![
                "wannacry".to_string(),
                "wcry".to_string(),
                "wannacrypt".to_string(),
            ],
        );
        c.register(
            "Mimikatz",
            "Credential dumper",
            "tool",
            vec![
                "mimikatz".to_string(),
                "sekurlsa".to_string(),
                "lsadump".to_string(),
            ],
        );
        c.register(
            "CobaltStrike",
            "Post-exploitation framework",
            "tool",
            vec![
                "cobaltstrike".to_string(),
                "beacon".to_string(),
                "cobalt strike".to_string(),
            ],
        );
        c
    }
}

impl Default for FamilyClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ActorAttribution
// ---------------------------------------------------------------------------

/// Confidence-scored attribution to a threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorAttribution {
    /// Actor name.
    pub actor: String,
    /// Attribution confidence [0, 100].
    pub confidence: u8,
    /// Evidence items supporting this attribution.
    pub evidence: Vec<String>,
    /// Attribution method used.
    pub method: AttributionMethod,
    /// Analyst notes.
    pub notes: Option<String>,
}

/// Method used to attribute activity to an actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionMethod {
    /// Shared infrastructure (IPs, domains).
    SharedInfrastructure,
    /// Shared malware code / family.
    SharedMalware,
    /// Shared YARA rule matches.
    YaraMatch,
    /// Shared TTPs.
    SharedTtps,
    /// Human intelligence.
    HumInt,
    /// Open-source intelligence.
    OsInt,
    /// Technical indicators only.
    TechnicalIndicators,
    /// Multiple combined methods.
    Combined,
}

impl std::fmt::Display for AttributionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SharedInfrastructure => "SharedInfrastructure",
            Self::SharedMalware => "SharedMalware",
            Self::YaraMatch => "YaraMatch",
            Self::SharedTtps => "SharedTtps",
            Self::HumInt => "HumInt",
            Self::OsInt => "OsInt",
            Self::TechnicalIndicators => "TechnicalIndicators",
            Self::Combined => "Combined",
        };
        write!(f, "{s}")
    }
}

impl ActorAttribution {
    /// Create a minimal attribution.
    #[must_use]
    pub const fn new(actor: String, confidence: u8, method: AttributionMethod) -> Self {
        Self {
            actor,
            confidence,
            evidence: Vec::new(),
            method,
            notes: None,
        }
    }

    /// Add an evidence item.
    pub fn add_evidence(&mut self, e: impl Into<String>) {
        self.evidence.push(e.into());
    }

    /// Return `true` if confidence is >= 75 (high confidence).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ---------------------------------------------------------------------------
// MalpediaLocalDb
// ---------------------------------------------------------------------------

/// How many records a corpus load inserted, per kind.
///
/// Returned so a caller can distinguish an empty corpus from a loaded one —
/// "0 families" is a fact worth reporting, not a silent success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusLoadCounts {
    pub families: usize,
    pub actors: usize,
    pub samples: usize,
}

impl CorpusLoadCounts {
    /// Total records inserted across all kinds.
    #[must_use]
    pub const fn total(self) -> usize {
        self.families + self.actors + self.samples
    }

    /// Whether the corpus contained nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total() == 0
    }
}

/// Offline local database populated from Malpedia data dumps.
#[derive(Debug)]
pub struct MalpediaLocalDb {
    families: Arc<Mutex<HashMap<String, MalpediaFamilySpec>>>,
    actors: Arc<Mutex<HashMap<String, MalpediaActorSpec>>>,
    samples: Arc<Mutex<HashMap<String, MalpediaSampleSpec>>>,
    yara_rules: Arc<Mutex<Vec<MalpediaYaraRule>>>,
}

impl MalpediaLocalDb {
    /// Create an empty local database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: Arc::new(Mutex::new(HashMap::new())),
            actors: Arc::new(Mutex::new(HashMap::new())),
            samples: Arc::new(Mutex::new(HashMap::new())),
            yara_rules: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Insert a family record.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    /// Load a corpus from a JSON export.
    ///
    /// ⚠ Why this exists. Before it, the only ways to fill this database were
    /// `insert_*` one record at a time and `populate_mock_data`. The MCP layer
    /// took the second: `tools/ti_malpedia.rs` called `populate_mock_data()`
    /// and reported the result as a corpus lookup, so "is this hash known
    /// malware" was answered out of a test fixture. There was no way to point
    /// the client at real data even if you had it.
    ///
    /// Expects an object with any of the keys `families`, `actors`, `samples`,
    /// each an array of the corresponding record. Unknown keys are ignored, so
    /// a richer export still loads. Returns how many of each were inserted, so
    /// a caller can tell "loaded nothing" from "loaded".
    ///
    /// # Errors
    /// Returns the parse error if `json` is not a JSON object, or if a record
    /// inside a known key does not match its schema — a malformed corpus is
    /// reported, never partially guessed.
    pub fn load_json(&self, json: &str) -> Result<CorpusLoadCounts, serde_json::Error> {
        #[derive(Deserialize, Default)]
        struct Corpus {
            #[serde(default)]
            families: Vec<MalpediaFamilySpec>,
            #[serde(default)]
            actors: Vec<MalpediaActorSpec>,
            #[serde(default)]
            samples: Vec<MalpediaSampleSpec>,
        }
        let corpus: Corpus = serde_json::from_str(json)?;
        let counts = CorpusLoadCounts {
            families: corpus.families.len(),
            actors: corpus.actors.len(),
            samples: corpus.samples.len(),
        };
        for f in corpus.families {
            self.insert_family(f);
        }
        for a in corpus.actors {
            self.insert_actor(a);
        }
        for sm in corpus.samples {
            self.insert_sample(sm);
        }
        Ok(counts)
    }

    /// Load a corpus from a file on disk. See [`Self::load_json`].
    ///
    /// # Errors
    /// Returns a message naming the path when the file cannot be read, or the
    /// parse error when its contents are not a valid corpus.
    pub fn load_path(&self, path: &std::path::Path) -> Result<CorpusLoadCounts, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read corpus '{}': {e}", path.display()))?;
        self.load_json(&text)
            .map_err(|e| format!("corpus '{}' is not valid: {e}", path.display()))
    }

    pub fn insert_family(&self, family: MalpediaFamilySpec) {
        self.families
            .lock()
            .unwrap()
            .insert(family.name.clone(), family);
    }

    /// Insert an actor record.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn insert_actor(&self, actor: MalpediaActorSpec) {
        self.actors
            .lock()
            .unwrap()
            .insert(actor.name.clone(), actor);
    }

    /// Insert a sample record.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn insert_sample(&self, sample: MalpediaSampleSpec) {
        let key = sample.sha256.to_lowercase();
        self.samples
            .lock()
            .unwrap()
            .insert(key, sample);
    }

    /// Insert a YARA rule.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn insert_yara(&self, rule: MalpediaYaraRule) {
        self.yara_rules.lock().unwrap().push(rule);
    }

    /// Look up a family by name.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_family(&self, name: &str) -> Option<MalpediaFamilySpec> {
        self.families.lock().unwrap().get(name).cloned()
    }

    /// Look up an actor by name.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_actor(&self, name: &str) -> Option<MalpediaActorSpec> {
        self.actors.lock().unwrap().get(name).cloned()
    }

    /// Look up a sample by SHA-256.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_sample(&self, sha256: &str) -> Option<MalpediaSampleSpec> {
        self.samples
            .lock()
            .unwrap()
            .get(&sha256.to_lowercase())
            .cloned()
    }

    /// List all families.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn list_families(&self) -> Vec<MalpediaFamilySpec> {
        self.families.lock().unwrap().values().cloned().collect()
    }

    /// List all actors.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn list_actors(&self) -> Vec<MalpediaActorSpec> {
        self.actors.lock().unwrap().values().cloned().collect()
    }

    /// Count of all families.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn family_count(&self) -> usize {
        self.families.lock().unwrap().len()
    }

    /// Count of all actors.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.actors.lock().unwrap().len()
    }

    /// Count of all samples.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.lock().unwrap().len()
    }

    /// Search families by partial name match.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn search_families(&self, query: &str) -> Vec<MalpediaFamilySpec> {
        let q = query.to_lowercase();
        self.families
            .lock()
            .unwrap()
            .values()
            .filter(|f| {
                f.name.to_lowercase().contains(&q)
                    || f.common_name.to_lowercase().contains(&q)
                    || f.aliases.iter().any(|a| a.to_lowercase().contains(&q))
            })
            .cloned()
            .collect()
    }

    /// Find sample by any hash (SHA-256, SHA-1, or MD5).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn find_by_hash(&self, hash: &str) -> Option<MalpediaSampleSpec> {
        let h = hash.to_lowercase();
        let guard = self.samples.lock().unwrap();
        guard
            .values()
            .find(|s| {
                s.sha256.to_lowercase() == h
                    || s.sha1.as_deref().map(str::to_lowercase) == Some(h.clone())
                    || s.md5.as_deref().map(str::to_lowercase) == Some(h.clone())
            })
            .cloned()
    }

    /// Compute corpus statistics from the records actually held here.
    ///
    /// Every counter is a real count over caller-supplied data — nothing is
    /// invented.  A database the caller has not populated yields zeros.
    ///
    /// # Panics
    /// Panics if an internal mutex is poisoned.
    #[must_use]
    pub fn compute_stats(&self) -> MalpediaStats {
        let families = self.families.lock().unwrap();
        let actors = self.actors.lock().unwrap();
        let samples = self.samples.lock().unwrap();
        let yara = self.yara_rules.lock().unwrap();

        let mut platform_breakdown: HashMap<String, u64> = HashMap::new();
        let mut yara_rule_count = yara.len() as u64;
        for f in families.values() {
            if !f.platform.is_empty() {
                *platform_breakdown.entry(f.platform.clone()).or_insert(0) += 1;
            }
            yara_rule_count += f.yara_rules.len() as u64;
        }
        let mut actor_country_breakdown: HashMap<String, u64> = HashMap::new();
        for a in actors.values() {
            if let Some(ref c) = a.country {
                *actor_country_breakdown.entry(c.clone()).or_insert(0) += 1;
            }
        }
        MalpediaStats {
            family_count: families.len() as u64,
            actor_count: actors.len() as u64,
            sample_count: samples.len() as u64,
            yara_rule_count,
            platform_breakdown,
            actor_country_breakdown,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Populate with a small set of TEST FIXTURE records.
    ///
    /// These are hand-written examples for unit tests, NOT a Malpedia
    /// download.  Do not serve them to a user as a lookup result.
    pub fn populate_mock_data(&self) {
        // Families
        self.insert_family(MalpediaFamilySpec {
            name: "win.emotet".to_string(),
            common_name: "Emotet".to_string(),
            malware_type: "trojan".to_string(),
            aliases: vec!["Heodo".to_string(), "Geodo".to_string()],
            platform: "win".to_string(),
            country: None,
            description: Some("Banking trojan turned loader".to_string()),
            yara_rules: vec!["rule win_emotet { condition: false }".to_string()],
            samples: vec!["deadbeef".to_string()],
            references: vec![
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet".to_string(),
            ],
            attack_techniques: vec!["T1071".to_string(), "T1055".to_string()],
            notes: None,
            url: Some("https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet".to_string()),
        });
        self.insert_family(MalpediaFamilySpec {
            name: "win.wannacry".to_string(),
            common_name: "WannaCry".to_string(),
            malware_type: "ransomware".to_string(),
            aliases: vec!["WanaCrypt0r".to_string(), "WCry".to_string()],
            platform: "win".to_string(),
            country: Some("KP".to_string()),
            description: Some("Ransomware worm using EternalBlue".to_string()),
            yara_rules: vec![],
            samples: vec!["aabbccdd".to_string()],
            references: vec![],
            attack_techniques: vec!["T1486".to_string()],
            notes: None,
            url: None,
        });

        // Actors
        let mut apt28 = MalpediaActorSpec::new("APT28".to_string());
        apt28.country = Some("RU".to_string());
        apt28.motivation = Some("espionage".to_string());
        apt28.families = vec!["win.x_agent".to_string(), "win.sofacy".to_string()];
        apt28.attribution_confidence = 85;
        self.insert_actor(apt28);

        let mut lazarus = MalpediaActorSpec::new("Lazarus".to_string());
        lazarus.country = Some("KP".to_string());
        lazarus.motivation = Some("financial_gain".to_string());
        lazarus.families = vec!["win.wannacry".to_string()];
        lazarus.attribution_confidence = 70;
        self.insert_actor(lazarus);

        // Samples
        self.insert_sample(MalpediaSampleSpec::new(
            "deadbeef".to_string(),
            "win.emotet".to_string(),
        ));
        self.insert_sample(MalpediaSampleSpec::new(
            "aabbccdd".to_string(),
            "win.wannacry".to_string(),
        ));

        // YARA rules
        self.insert_yara(MalpediaYaraRule::new(
            "detect_emotet".to_string(),
            "win.emotet".to_string(),
        ));
    }
}

impl Default for MalpediaLocalDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MalpediaApiClient (spec-required full implementation)
// ---------------------------------------------------------------------------

/// Malpedia API client (mock implementation with full spec API).
pub struct MalpediaApiClient {
    api_key: Option<String>,
    base_url: String,
    local_db: Option<Arc<MalpediaLocalDb>>,
    stats_cache: Arc<Mutex<Option<(MalpediaStats, u64)>>>,
    ttl_secs: u64,
    timeout: Duration,
}

impl MalpediaApiClient {
    /// Create a new Malpedia client.
    #[must_use]
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            base_url: "https://malpedia.caad.fkie.fraunhofer.de".to_string(),
            local_db: None,
            stats_cache: Arc::new(Mutex::new(None)),
            ttl_secs: 3600,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the per-request HTTP timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Return the configured per-request HTTP timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Attach a local database for offline operation.
    #[must_use]
    pub fn with_local_db(mut self, db: MalpediaLocalDb) -> Self {
        self.local_db = Some(Arc::new(db));
        self
    }

    /// Override the base URL.
    #[must_use]
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    /// Set the cache TTL in seconds.
    #[must_use]
    pub const fn with_ttl(mut self, secs: u64) -> Self {
        self.ttl_secs = secs;
        self
    }

    /// Build an EMPTY [`MalpediaFamilySpec`] skeleton for the given name.
    ///
    /// This is NOT a lookup and asserts nothing about the family: only the
    /// name, the normalised identifier and the canonical Malpedia URL — all of
    /// which are derived from the argument — are filled in.  Every field that
    /// would be a claim about the malware (type, platform, aliases, YARA
    /// rules, samples, ATT&CK techniques) is left empty.
    #[must_use]
    pub fn mock_family_response(&self, name: &str) -> MalpediaFamilySpec {
        let normalised = Self::normalize_family_name(name);
        MalpediaFamilySpec {
            name: normalised.clone(),
            common_name: name.to_string(),
            malware_type: String::new(),
            aliases: vec![],
            platform: normalised
                .split_once('.')
                .map_or_else(String::new, |(p, _)| p.to_string()),
            country: None,
            description: None,
            yara_rules: vec![],
            samples: vec![],
            references: vec![],
            attack_techniques: vec![],
            notes: Some(
                "no lookup performed: this record carries no Malpedia data".to_string(),
            ),
            url: Some(format!(
                "https://malpedia.caad.fkie.fraunhofer.de/details/{normalised}"
            )),
        }
    }

    /// Normalise a family name for use as a Malpedia identifier.
    #[must_use]
    pub fn normalize_family_name(name: &str) -> String {
        name.to_lowercase().replace([' ', '-'], "_")
    }

    /// Map a Malpedia `malware_type` string to a [`MalwareType`].
    #[must_use]
    pub fn family_to_malware_type(family_type: &str) -> MalwareType {
        match family_type.to_lowercase().as_str() {
            "ransomware" => MalwareType::Ransomware,
            "trojan" => MalwareType::Trojan,
            "backdoor" => MalwareType::Backdoor,
            "rootkit" => MalwareType::Rootkit,
            "worm" => MalwareType::Worm,
            "virus" => MalwareType::Virus,
            "spyware" | "stalkerware" => MalwareType::Spyware,
            "adware" => MalwareType::Adware,
            "dropper" | "loader" => MalwareType::Dropper,
            "downloader" => MalwareType::Downloader,
            "banker" | "banking" => MalwareType::Banker,
            "stealer" | "infostealer" => MalwareType::Stealer,
            "botnet" | "bot" => MalwareType::Botnet,
            "cryptominer" | "miner" => MalwareType::Cryptominer,
            "fileless" => MalwareType::Fileless,
            "pua" | "pup" => MalwareType::PotentiallyUnwanted,
            _ => MalwareType::Unknown,
        }
    }

    /// Whether this client has a valid (non-empty) API key.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.is_empty())
    }

    /// Authenticate and validate the API key (mock).
    ///
    /// # Errors
    /// Returns an error if no API key is configured.
    pub fn authenticate(&self) -> Result<bool, MalpediaClientError> {
        if self.is_authenticated() {
            Ok(true)
        } else {
            Err(MalpediaClientError::NotAuthenticated)
        }
    }

    /// Search families by name query.
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    pub fn search_family(
        &self,
        query: &str,
    ) -> Result<Vec<MalpediaFamilySpec>, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return Ok(db.search_families(query));
        }
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "family search for '{query}'"
        )))
    }

    /// Get a specific family by its canonical name.
    ///
    /// # Errors
    /// Returns an error if the family is not found.
    pub fn get_family(&self, name: &str) -> Result<MalpediaFamilySpec, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return db
                .get_family(name)
                .ok_or_else(|| MalpediaClientError::FamilyNotFound(name.to_string()));
        }
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "family '{name}'"
        )))
    }

    /// List all families (paginated).
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    pub fn list_families(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<MalpediaFamilySpec>, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            let all = db.list_families();
            let start = offset.unwrap_or(0);
            let end = limit.map_or(all.len(), |l| (start + l).min(all.len()));
            return Ok(all
                .into_iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .collect());
        }
        Err(MalpediaClientError::NetworkLookupRequired(
            "family listing".to_string(),
        ))
    }

    /// Get a sample record by its SHA-256.
    ///
    /// # Errors
    /// Returns an error if the sample is not found.
    pub fn get_sample(
        &self,
        sha256: &str,
    ) -> Result<MalpediaSampleSpec, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return db
                .get_sample(sha256)
                .ok_or_else(|| MalpediaClientError::SampleNotFound(sha256.to_string()));
        }
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "sample {sha256}"
        )))
    }

    /// Get an actor by name.
    ///
    /// # Errors
    /// Returns an error if the actor is not found.
    pub fn get_actor(&self, name: &str) -> Result<MalpediaActorSpec, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return db
                .get_actor(name)
                .ok_or_else(|| MalpediaClientError::ActorNotFound(name.to_string()));
        }
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "actor '{name}'"
        )))
    }

    /// List all actors.
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    pub fn list_actors(&self) -> Result<Vec<MalpediaActorSpec>, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return Ok(db.list_actors());
        }
        Err(MalpediaClientError::NetworkLookupRequired(
            "actor listing".to_string(),
        ))
    }

    /// Search by file hash (SHA-256, SHA-1, or MD5).
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    pub fn search_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<MalpediaSampleSpec>, MalpediaClientError> {
        if let Some(ref db) = self.local_db {
            return Ok(db.find_by_hash(hash));
        }
        // Without a local corpus this is a remote lookup.  Returning `Ok(None)`
        // would assert "this hash is unknown to Malpedia", which is a claim we
        // cannot make offline, so an error is returned instead.
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "hash {hash}"
        )))
    }

    /// Get YARA rules for a specific family.
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    pub fn get_yara_rules(
        &self,
        family: &str,
    ) -> Result<Vec<MalpediaYaraRule>, MalpediaClientError> {
        if let Some(ref db) = self.local_db
            && let Some(f) = db.get_family(&Self::normalize_family_name(family))
        {
            return Ok(f
                .yara_rules
                .iter()
                .enumerate()
                .map(|(i, src)| {
                    let mut r = MalpediaYaraRule::new(
                        format!("{}_{i}", Self::normalize_family_name(family)),
                        family.to_string(),
                    );
                    r.description = src.clone();
                    r
                })
                .collect());
        }
        Err(MalpediaClientError::NetworkLookupRequired(format!(
            "YARA rules for family '{family}'"
        )))
    }

    /// Get aggregated statistics.
    ///
    /// # Errors
    /// Returns an error if the local database is unavailable.
    ///
    /// # Panics
    /// Panics if the internal stats mutex is poisoned.
    pub fn get_stats(&self) -> Result<MalpediaStats, MalpediaClientError> {
        // Check cache
        {
            let guard = self.stats_cache.lock().unwrap();
            if let Some((ref stats, ts)) = *guard {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now.saturating_sub(ts) < self.ttl_secs {
                    return Ok(stats.clone());
                }
            }
        }
        // Corpus-wide counters are only knowable from the live service.
        if let Some(ref db) = self.local_db {
            let stats = db.compute_stats();
            {
                let mut guard = self.stats_cache.lock().unwrap();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                *guard = Some((stats.clone(), now));
            }
            return Ok(stats);
        }
        Err(MalpediaClientError::NetworkLookupRequired(
            "corpus statistics".to_string(),
        ))
    }

    /// Execute a structured search query.
    ///
    /// # Errors
    /// Returns an error if the search fails.
    pub fn search(
        &self,
        query: &MalpediaSearchQuery,
    ) -> Result<Vec<MalpediaFamilySpec>, MalpediaClientError> {
        let q = query.query.as_deref().unwrap_or("");
        let results = self.search_family(q)?;
        let filtered: Vec<MalpediaFamilySpec> = results
            .into_iter()
            .filter(|f| {
                if let Some(ref p) = query.platform
                    && !f.platform.eq_ignore_ascii_case(p) {
                        return false;
                    }
                if let Some(ref t) = query.malware_type
                    && !f.malware_type.eq_ignore_ascii_case(t) {
                        return false;
                    }
                true
            })
            .take(query.limit.unwrap_or(usize::MAX))
            .collect();
        Ok(filtered)
    }
}

#[async_trait]
impl TiProvider for MalpediaApiClient {
    fn name(&self) -> &'static str {
        "malpedia"
    }

    fn supported_ioc_types(&self) -> Vec<IoCType> {
        vec![
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Sha512,
        ]
    }

    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError> {
        // A verdict must come from the corpus, never from the shape of the
        // string being queried.
        let sample = self
            .search_by_hash(&ioc.value)
            .map_err(|e| TiError::Other(e.to_string()))?;
        let mut result = TiResult::new(ioc.clone());
        if ioc.is_hash() {
            let malicious = sample.is_some();
            result.verdicts.push(Verdict {
                malicious,
                confidence: if malicious { 90 } else { 0 },
                tags: if malicious {
                    vec!["malpedia-corpus-hit".to_string()]
                } else {
                    vec![]
                },
                engine_count: 1,
                positive_count: u32::from(malicious),
                first_seen: None,
                last_seen: None,
                description: Some(if malicious {
                    format!("{} is present in the Malpedia corpus", ioc.value)
                } else {
                    format!("{} is absent from the Malpedia corpus", ioc.value)
                }),
                provider: "malpedia".to_string(),
            });
            if let Some(sp) = sample
                && !sp.family.is_empty()
            {
                result.malware_families.push(sp.family);
            }
        }
        Ok(result)
    }

    fn rate_limit_per_minute(&self) -> u32 {
        60
    }
}

// ---------------------------------------------------------------------------
// MalpediaOrganisation (additional spec type)
// ---------------------------------------------------------------------------

/// Organisation record in Malpedia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaOrganisation {
    /// Organisation short name.
    pub short_name: String,
    /// Full organisation name.
    pub full_name: Option<String>,
    /// URL.
    pub url: Option<String>,
}

// ---------------------------------------------------------------------------
// SignatureScoreResult
// ---------------------------------------------------------------------------

/// Result of scoring a sample against family signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureScoreResult {
    /// Family name.
    pub family: String,
    /// Score (number of matching keywords/signatures).
    pub score: u32,
    /// Confidence percentage derived from score.
    pub confidence_pct: u8,
}

impl SignatureScoreResult {
    /// Create from family + score.
    #[must_use]
    pub fn new(family: String, score: u32, max_score: u32) -> Self {
        let confidence_pct = if max_score == 0 {
            0
        } else {
            // Compute entirely in u32 arithmetic to avoid float-cast warnings.
            // score ≤ max_score, so the result is always ≤ 100.
            u8::try_from((u64::from(score) * 100 / u64::from(max_score)).min(100))
                .unwrap_or(100)
        };
        Self {
            family,
            score,
            confidence_pct,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (30+)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::IoCType;

    fn client() -> MalpediaApiClient {
        MalpediaApiClient::new(Some("test-key".to_string()))
    }

    fn anon_client() -> MalpediaApiClient {
        MalpediaApiClient::new(None)
    }

    fn hash_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Sha256, val.to_string(), "test".to_string())
    }

    fn db_with_data() -> MalpediaLocalDb {
        let db = MalpediaLocalDb::new();
        db.populate_mock_data();
        db
    }

    // ---- MalpediaApiClient basics ----

    #[test]
    fn test_client_new_authenticated() {
        assert!(client().is_authenticated());
    }

    #[test]
    fn test_client_new_anonymous() {
        assert!(!anon_client().is_authenticated());
    }

    #[test]
    fn test_client_empty_key_not_authenticated() {
        let c = MalpediaApiClient::new(Some(String::new()));
        assert!(!c.is_authenticated());
    }

    #[test]
    fn test_provider_name() {
        assert_eq!(client().name(), "malpedia");
    }

    #[test]
    fn test_provider_rate_limit() {
        assert_eq!(client().rate_limit_per_minute(), 60);
    }

    #[test]
    fn test_supported_types() {
        let types = client().supported_ioc_types();
        assert!(types.contains(&IoCType::Sha256));
        assert!(types.contains(&IoCType::Md5));
        assert!(!types.contains(&IoCType::Ip));
    }

    // ---- normalize_family_name ----

    #[test]
    fn test_normalize_spaces() {
        assert_eq!(
            MalpediaApiClient::normalize_family_name("WannaCry"),
            "wannacry"
        );
    }

    #[test]
    fn test_normalize_spaces_to_underscore() {
        assert_eq!(
            MalpediaApiClient::normalize_family_name("Fancy Bear"),
            "fancy_bear"
        );
    }

    #[test]
    fn test_normalize_hyphen_to_underscore() {
        assert_eq!(
            MalpediaApiClient::normalize_family_name("Poison-Ivy"),
            "poison_ivy"
        );
    }

    // ---- family_to_malware_type ----

    #[test]
    fn test_type_ransomware() {
        assert_eq!(
            MalpediaApiClient::family_to_malware_type("ransomware"),
            MalwareType::Ransomware
        );
    }

    #[test]
    fn test_type_banker() {
        assert_eq!(
            MalpediaApiClient::family_to_malware_type("banker"),
            MalwareType::Banker
        );
    }

    #[test]
    fn test_type_infostealer() {
        assert_eq!(
            MalpediaApiClient::family_to_malware_type("infostealer"),
            MalwareType::Stealer
        );
    }

    #[test]
    fn test_type_unknown() {
        assert_eq!(
            MalpediaApiClient::family_to_malware_type("something_weird"),
            MalwareType::Unknown
        );
    }

    // ---- async API ----

    #[test]
    fn test_authenticate_ok() {
        assert!(client().authenticate().is_ok());
    }

    #[test]
    fn test_authenticate_fail() {
        assert!(anon_client().authenticate().is_err());
    }

    // ---- Honesty: with no local corpus, nothing is invented ----

    fn db_client() -> MalpediaApiClient {
        let db = MalpediaLocalDb::new();
        db.populate_mock_data();
        MalpediaApiClient::new(Some("k".to_string())).with_local_db(db)
    }

    #[test]
    fn test_get_family_without_corpus_errors() {
        assert!(matches!(
            client().get_family("emotet"),
            Err(MalpediaClientError::NetworkLookupRequired(_))
        ));
    }

    #[test]
    fn test_get_family_from_corpus_works() {
        let f = db_client().get_family("win.emotet").unwrap();
        assert_eq!(f.common_name, "Emotet");
    }

    #[test]
    fn test_list_families_without_corpus_errors() {
        assert!(client().list_families(None, None).is_err());
    }

    #[test]
    fn test_list_families_from_corpus_works() {
        assert!(!db_client().list_families(None, None).unwrap().is_empty());
    }

    #[test]
    fn test_get_stats_without_corpus_errors() {
        assert!(matches!(
            client().get_stats(),
            Err(MalpediaClientError::NetworkLookupRequired(_))
        ));
    }

    #[test]
    fn test_get_stats_from_corpus_counts_real_records() {
        let c = db_client();
        let stats = c.get_stats().unwrap();
        let listed = c.list_families(None, None).unwrap().len() as u64;
        assert_eq!(stats.family_count, listed);
        assert!(stats.family_count > 0);
    }

    #[test]
    fn test_search_by_hash_without_corpus_errors() {
        // The old code answered "known" for anything containing "evil" and
        // "unknown" for everything else.  Both were inventions.
        assert!(client().search_by_hash("evil_hash").is_err());
        assert!(client().search_by_hash("safe_hash").is_err());
    }

    #[test]
    fn test_search_by_hash_uses_the_corpus() {
        let c = db_client();
        assert!(c.search_by_hash("deadbeef").unwrap().is_some());
        assert!(c.search_by_hash("evil_hash").unwrap().is_none());
    }

    #[test]
    fn test_get_yara_rules_without_corpus_errors() {
        assert!(client().get_yara_rules("emotet").is_err());
    }

    #[test]
    fn test_get_yara_rules_come_from_the_corpus() {
        let rules = db_client().get_yara_rules("win.emotet").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].description.contains("rule win_emotet"));
        // A family the corpus has no rules for yields none, not a made-up one.
        assert!(db_client().get_yara_rules("win.wannacry").unwrap().is_empty());
    }

    #[test]
    fn test_mock_family_response_asserts_nothing() {
        let f = client().mock_family_response("Win Emotet");
        assert_eq!(f.name, "win_emotet");
        assert!(f.malware_type.is_empty());
        assert!(f.aliases.is_empty());
        assert!(f.yara_rules.is_empty());
        assert!(f.samples.is_empty());
        assert!(f.attack_techniques.is_empty());
        assert!(f.description.is_none());
    }

    #[tokio::test]
    async fn test_lookup_without_corpus_errors() {
        let ioc = hash_ioc("safe_hash");
        let err = client().lookup(&ioc).await.unwrap_err();
        assert!(err.to_string().contains("network lookup required"));
    }

    #[tokio::test]
    async fn test_lookup_uses_the_corpus() {
        let hit = db_client().lookup(&hash_ioc("deadbeef")).await.unwrap();
        assert!(hit.is_malicious());
        assert_eq!(hit.malware_families, vec!["win.emotet".to_string()]);

        let miss = db_client().lookup(&hash_ioc("evil_hash")).await.unwrap();
        assert!(!miss.is_malicious());
        assert!(miss.malware_families.is_empty());
    }

    #[tokio::test]
    async fn test_bulk_lookup_without_corpus_errors() {
        let iocs = vec![hash_ioc("a"), hash_ioc("b")];
        assert!(client().bulk_lookup(&iocs).await.is_err());
    }

    // ---- MalpediaLocalDb ----

    #[test]
    fn test_local_db_family_count() {
        let db = db_with_data();
        assert_eq!(db.family_count(), 2);
    }

    #[test]
    fn test_local_db_actor_count() {
        let db = db_with_data();
        assert_eq!(db.actor_count(), 2);
    }

    #[test]
    fn test_local_db_sample_count() {
        let db = db_with_data();
        assert_eq!(db.sample_count(), 2);
    }

    #[test]
    fn test_local_db_get_family() {
        let db = db_with_data();
        let f = db.get_family("win.emotet");
        assert!(f.is_some());
        assert_eq!(f.unwrap().common_name, "Emotet");
    }

    #[test]
    fn test_local_db_search_families() {
        let db = db_with_data();
        let results = db.search_families("emotet");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_local_db_find_by_hash() {
        let db = db_with_data();
        let result = db.find_by_hash("deadbeef");
        assert!(result.is_some());
    }

    // ---- FamilyAliasResolver ----

    #[test]
    fn test_alias_resolver_defaults() {
        let r = FamilyAliasResolver::with_defaults();
        assert!(r.count() > 0);
        assert_eq!(r.resolve("heodo"), Some("win.emotet"));
    }

    #[test]
    fn test_alias_resolver_resolve_or_normalize() {
        let r = FamilyAliasResolver::with_defaults();
        assert_eq!(r.resolve_or_normalize("heodo"), "win.emotet");
        assert_eq!(r.resolve_or_normalize("Unknown Family"), "unknown_family");
    }

    // ---- FamilyClassifier ----

    #[test]
    fn test_classifier_classify() {
        let c = FamilyClassifier::with_defaults();
        let r = c.classify("emotet banking trojan heodo");
        assert_eq!(r.as_deref(), Some("Emotet"));
    }

    #[test]
    fn test_classifier_no_match() {
        let c = FamilyClassifier::with_defaults();
        let r = c.classify("completely unrelated text xyz123");
        assert!(r.is_none());
    }

    // ---- ActorAttribution ----

    #[test]
    fn test_actor_attribution_high_confidence() {
        let a = ActorAttribution::new("APT28".to_string(), 80, AttributionMethod::Combined);
        assert!(a.is_high_confidence());
    }

    #[test]
    fn test_actor_attribution_low_confidence() {
        let a = ActorAttribution::new("Unknown".to_string(), 30, AttributionMethod::OsInt);
        assert!(!a.is_high_confidence());
    }

    // ---- MalpediaYaraRule ----

    #[test]
    fn test_yara_rule_to_text() {
        let mut r = MalpediaYaraRule::new("test_rule".to_string(), "win.test".to_string());
        r.strings
            .push(("s0".to_string(), "{ DE AD BE EF }".to_string()));
        let text = r.to_yara_text();
        assert!(text.contains("rule test_rule"));
        assert!(text.contains("win.test"));
    }

    // ---- MalpediaStats ----

    #[test]
    fn test_stats_mock_is_empty_not_invented() {
        let s = MalpediaStats::mock();
        assert_eq!(s.family_count, 0);
        assert_eq!(s.actor_count, 0);
        assert_eq!(s.sample_count, 0);
        assert_eq!(s.yara_rule_count, 0);
        assert_eq!(s.last_updated, 0);
        assert!(s.platform_breakdown.is_empty());
        assert!(s.actor_country_breakdown.is_empty());
    }

    #[test]
    fn test_compute_stats_counts_only_real_records() {
        let db = MalpediaLocalDb::new();
        assert_eq!(db.compute_stats().family_count, 0);
        db.populate_mock_data();
        let s = db.compute_stats();
        assert_eq!(s.family_count, db.list_families().len() as u64);
        assert!(s.platform_breakdown.values().sum::<u64>() <= s.family_count);
    }

    // ---- MalpediaSearchQuery ----

    #[test]
    fn test_search_query_builder() {
        let q = MalpediaSearchQuery::new()
            .with_query("emotet")
            .with_platform("win")
            .with_limit(10)
            .include_yara();
        assert_eq!(q.query.as_deref(), Some("emotet"));
        assert_eq!(q.limit, Some(10));
        assert!(q.include_yara);
    }

    #[test]
    fn test_client_with_local_db() {
        let db = db_with_data();
        let c = MalpediaApiClient::new(None).with_local_db(db);
        let f = c.get_family("win.emotet");
        assert!(f.is_ok());
    }

    #[test]
    fn test_family_spec_platform_prefix() {
        let f = client().mock_family_response("emotet");
        // name normalised → "emotet", has no dot → falls back to platform
        let _ = f.platform_prefix();
    }

    #[test]
    fn test_sample_spec_new() {
        let s = MalpediaSampleSpec::new("deadbeef".to_string(), "win.emotet".to_string());
        assert_eq!(s.sha256, "deadbeef");
        assert!(!s.packed);
    }
}
