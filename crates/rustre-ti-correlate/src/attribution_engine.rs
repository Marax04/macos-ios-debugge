//! Attribution engine — score threat reports and campaigns against known
//! threat actors.
//!
//! [`AttributionEngine`] maintains a registry of [`ThreatActor`] profiles and
//! evaluates incoming evidence to produce ranked [`AttributionResult`] lists.
//! Each result carries an overall score and a per-signal breakdown, allowing
//! analysts to inspect which evidence drove the attribution.
//!
//! The entry point [`score_attribution`] takes a slice of evidence signals and
//! returns results sorted by descending score.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_threatintel::{IoC, ThreatReport, Ttp};

// ---------------------------------------------------------------------------
// ThreatActor
// ---------------------------------------------------------------------------

/// Profile of a known threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    /// Unique actor identifier (e.g. "APT28", "FIN7").
    pub id: String,
    /// Common aliases.
    pub aliases: Vec<String>,
    /// Nation-state or region association.
    pub origin: Option<String>,
    /// MITRE ATT&CK TTP identifiers attributed to this actor.
    pub ttps: Vec<String>,
    /// Known infrastructure patterns (regex strings or literal indicators).
    pub infrastructure: Vec<String>,
    /// Malware families associated with this actor.
    pub families: Vec<String>,
    /// Analyst-assigned confidence that this profile is accurate, 0–100.
    pub profile_confidence: u8,
}

impl ThreatActor {
    /// Create a minimal actor profile.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aliases: Vec::new(),
            origin: None,
            ttps: Vec::new(),
            infrastructure: Vec::new(),
            families: Vec::new(),
            profile_confidence: 50,
        }
    }

    /// Add an alias.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    /// Set the origin.
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// Add a TTP.
    pub fn with_ttp(mut self, ttp: impl Into<String>) -> Self {
        self.ttps.push(ttp.into());
        self
    }

    /// Add a malware family.
    pub fn with_family(mut self, family: impl Into<String>) -> Self {
        self.families.push(family.into());
        self
    }

    /// Set the profile confidence.
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.profile_confidence = c;
        self
    }
}

impl fmt::Display for ThreatActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let origin = self.origin.as_deref().unwrap_or("unknown");
        write!(f, "{} [{}] ttps={} families={}", self.id, origin, self.ttps.len(), self.families.len())
    }
}

// ---------------------------------------------------------------------------
// Signal — one piece of evidence for scoring
// ---------------------------------------------------------------------------

/// A single evidence signal used to score actor attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Human-readable description.
    pub description: String,
    /// Signal category.
    pub kind: SignalKind,
    /// Raw value (e.g. TTP ID, family name, IoC value).
    pub value: String,
    /// Analyst weight, 0.0–1.0.  Higher = more important.
    pub weight: f32,
}

impl Signal {
    /// Create a signal from a TTP.
    #[must_use]
    pub fn from_ttp(ttp: &Ttp, weight: f32) -> Self {
        Self {
            description: format!("TTP {}: {}", ttp.technique_id, ttp.name),
            kind: SignalKind::Ttp,
            value: ttp.technique_id.clone(),
            weight,
        }
    }

    /// Create a signal from a malware family name.
    #[must_use]
    pub fn from_family(family: impl Into<String>, weight: f32) -> Self {
        let family = family.into();
        Self {
            description: format!("malware family: {}", family),
            kind: SignalKind::MalwareFamily,
            value: family,
            weight,
        }
    }

    /// Create a signal from an IoC value.
    #[must_use]
    pub fn from_ioc(ioc: &IoC, weight: f32) -> Self {
        Self {
            description: format!("IoC {:?}: {}", ioc.ioc_type, ioc.value),
            kind: SignalKind::Infrastructure,
            value: ioc.value.clone(),
            weight,
        }
    }
}

/// Category of a signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalKind {
    /// MITRE ATT&CK TTP match.
    Ttp,
    /// Malware family match.
    MalwareFamily,
    /// Infrastructure / IoC match.
    Infrastructure,
    /// Victimology match.
    Victimology,
    /// Temporal correlation.
    Temporal,
    /// Analyst-supplied manual signal.
    Manual,
}

impl fmt::Display for SignalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ttp            => write!(f, "TTP"),
            Self::MalwareFamily  => write!(f, "FAMILY"),
            Self::Infrastructure => write!(f, "INFRA"),
            Self::Victimology    => write!(f, "VICTIM"),
            Self::Temporal       => write!(f, "TEMPORAL"),
            Self::Manual         => write!(f, "MANUAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScoreBreakdown — per-signal contribution
// ---------------------------------------------------------------------------

/// Contribution of a single signal to an actor's attribution score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreContribution {
    /// The signal that produced this contribution.
    pub signal: Signal,
    /// Whether the signal matched this actor.
    pub matched: bool,
    /// Points awarded (0.0 if not matched).
    pub points: f32,
}

// ---------------------------------------------------------------------------
// AttributionResult
// ---------------------------------------------------------------------------

/// Result of scoring a set of signals against one [`ThreatActor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    /// The actor being scored.
    pub actor_id: String,
    /// Normalised attribution score, 0.0–1.0.
    pub score: f32,
    /// Number of signals that matched this actor.
    pub matched_signals: usize,
    /// Analyst confidence in the attribution, 0–100.
    pub confidence: u8,
    /// Per-signal breakdown.
    pub breakdown: Vec<ScoreContribution>,
    /// Optional free-form notes.
    pub notes: Vec<String>,
}

impl AttributionResult {
    /// Returns `true` when the score is above `threshold`.
    #[must_use]
    pub fn is_above_threshold(&self, threshold: f32) -> bool {
        self.score >= threshold
    }

    /// Attribution label: "High", "Medium", "Low", or "Unlikely".
    #[must_use]
    pub fn label(&self) -> &'static str {
        if self.score >= 0.75 {
            "High"
        } else if self.score >= 0.50 {
            "Medium"
        } else if self.score >= 0.25 {
            "Low"
        } else {
            "Unlikely"
        }
    }
}

impl fmt::Display for AttributionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} score={:.3} ({}) matches={} conf={}",
            self.actor_id, self.score, self.label(), self.matched_signals, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// AttributionEngine
// ---------------------------------------------------------------------------

/// Scores evidence signals against known [`ThreatActor`] profiles.
pub struct AttributionEngine {
    actors: HashMap<String, ThreatActor>,
    /// Minimum score to include in results (default 0.1).
    min_score: f32,
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AttributionEngine {
    /// Create an empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            actors: HashMap::new(),
            min_score: 0.1,
        }
    }

    /// Override the minimum score threshold.
    pub fn with_min_score(mut self, s: f32) -> Self {
        self.min_score = s;
        self
    }

    /// Register a threat actor.
    pub fn register(&mut self, actor: ThreatActor) {
        self.actors.insert(actor.id.clone(), actor);
    }

    /// Register multiple actors.
    pub fn register_all(&mut self, actors: impl IntoIterator<Item = ThreatActor>) {
        for a in actors {
            self.register(a);
        }
    }

    /// Score a slice of signals against all registered actors.
    ///
    /// Returns results sorted by descending score, filtered by `min_score`.
    #[must_use]
    pub fn score(&self, signals: &[Signal]) -> Vec<AttributionResult> {
        let mut results: Vec<AttributionResult> = self
            .actors
            .values()
            .map(|actor| self.score_actor(actor, signals))
            .filter(|r| r.score >= self.min_score)
            .collect();
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Score signals extracted from a [`ThreatReport`] against all actors.
    #[must_use]
    pub fn score_report(&self, report: &ThreatReport) -> Vec<AttributionResult> {
        let mut signals: Vec<Signal> = Vec::new();
        for ttp in &report.ttps {
            signals.push(Signal::from_ttp(ttp, 0.8));
        }
        for ioc in &report.iocs {
            signals.push(Signal::from_ioc(ioc, 0.6));
        }
        for family in &report.malware_families {
            signals.push(Signal::from_family(family, 0.9));
        }
        self.score(&signals)
    }

    /// Return the top-N attribution results.
    #[must_use]
    pub fn top_n(&self, signals: &[Signal], n: usize) -> Vec<AttributionResult> {
        let mut results = self.score(signals);
        results.truncate(n);
        results
    }

    /// Number of registered actors.
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    /// Retrieve a registered actor by id.
    #[must_use]
    pub fn get_actor(&self, id: &str) -> Option<&ThreatActor> {
        self.actors.get(id)
    }

    /// Like [`get_actor`] but returns an [`anyhow::Result`] with a descriptive
    /// error message when the actor id is not registered, so callers receive
    /// structured context instead of a bare `None`.
    pub fn get_actor_or_err(&self, id: &str) -> Result<&ThreatActor> {
        if self.actors.is_empty() {
            bail!("AttributionEngine has no registered actors; call register() first");
        }
        self.actors
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Actor '{}' is not registered in AttributionEngine ({} actors known)", id, self.actors.len()))
    }

    /// Score signals and return an error if the engine has no registered actors
    /// so callers can distinguish an empty registry from a genuine no-match.
    pub fn score_or_err(&self, signals: &[Signal]) -> Result<Vec<AttributionResult>> {
        if self.actors.is_empty() {
            bail!("AttributionEngine::score_or_err: no threat actors registered");
        }
        Ok(self.score(signals))
    }

    // -----------------------------------------------------------------------
    // Scoring logic
    // -----------------------------------------------------------------------

    fn score_actor(&self, actor: &ThreatActor, signals: &[Signal]) -> AttributionResult {
        let mut breakdown = Vec::new();
        let mut total_weight = 0.0f32;
        let mut total_points = 0.0f32;
        let mut matched = 0usize;

        for signal in signals {
            total_weight += signal.weight;
            let hit = self.signal_matches_actor(actor, signal);
            let points = if hit { signal.weight } else { 0.0 };
            if hit { matched += 1; }
            total_points += points;
            breakdown.push(ScoreContribution {
                signal: signal.clone(),
                matched: hit,
                points,
            });
        }

        let raw_score = if total_weight == 0.0 {
            0.0
        } else {
            total_points / total_weight
        };

        // Apply profile confidence as a scaling factor
        let scale = actor.profile_confidence as f32 / 100.0;
        let score = (raw_score * scale).min(1.0);
        let confidence = (score * 100.0) as u8;

        AttributionResult {
            actor_id: actor.id.clone(),
            score,
            matched_signals: matched,
            confidence,
            breakdown,
            notes: Vec::new(),
        }
    }

    fn signal_matches_actor(&self, actor: &ThreatActor, signal: &Signal) -> bool {
        match signal.kind {
            SignalKind::Ttp => actor.ttps.iter().any(|t| t == &signal.value),
            SignalKind::MalwareFamily => actor.families.iter().any(|f| {
                f.to_lowercase() == signal.value.to_lowercase()
            }),
            SignalKind::Infrastructure => actor.infrastructure.iter().any(|i| {
                signal.value.contains(i.as_str()) || i.contains(signal.value.as_str())
            }),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// score_attribution — free function
// ---------------------------------------------------------------------------

/// Score a set of signals against a list of actors and return ranked results.
///
/// This is a convenience wrapper that creates a temporary [`AttributionEngine`],
/// registers the actors, and calls [`AttributionEngine::score`].
#[must_use]
pub fn score_attribution(
    actors: &[ThreatActor],
    signals: &[Signal],
    min_score: f32,
) -> Vec<AttributionResult> {
    let mut engine = AttributionEngine::new().with_min_score(min_score);
    for actor in actors {
        engine.register(actor.clone());
    }
    engine.score(signals)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_actor(id: &str, ttps: &[&str], families: &[&str]) -> ThreatActor {
        let mut a = ThreatActor::new(id).with_confidence(100);
        for t in ttps { a = a.with_ttp(*t); }
        for f in families { a = a.with_family(*f); }
        a
    }

    fn make_ttp_signal(id: &str) -> Signal {
        Signal {
            description: format!("TTP {}", id),
            kind: SignalKind::Ttp,
            value: id.to_string(),
            weight: 1.0,
        }
    }

    fn make_family_signal(family: &str) -> Signal {
        Signal {
            description: format!("family {}", family),
            kind: SignalKind::MalwareFamily,
            value: family.to_string(),
            weight: 1.0,
        }
    }

    #[test]
    fn test_register_and_get_actor() {
        let mut engine = AttributionEngine::new();
        engine.register(make_actor("APT28", &["T1059"], &[]));
        assert!(engine.get_actor("APT28").is_some());
        assert_eq!(engine.actor_count(), 1);
    }

    #[test]
    fn test_score_perfect_match() {
        let mut engine = AttributionEngine::new();
        engine.register(make_actor("APT28", &["T1059", "T1105"], &["Sofacy"]));
        let signals = vec![
            make_ttp_signal("T1059"),
            make_ttp_signal("T1105"),
            make_family_signal("Sofacy"),
        ];
        let results = engine.score(&signals);
        assert!(!results.is_empty());
        assert_eq!(results[0].actor_id, "APT28");
        assert!((results[0].score - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_score_no_match() {
        let mut engine = AttributionEngine::new().with_min_score(0.0);
        engine.register(make_actor("APT28", &["T1059"], &[]));
        let signals = vec![make_ttp_signal("T9999")];
        let results = engine.score(&signals);
        assert_eq!(results[0].score, 0.0);
    }

    #[test]
    fn test_score_sorted_by_score() {
        let mut engine = AttributionEngine::new();
        engine.register(make_actor("APT28", &["T1059", "T1105"], &[]));
        engine.register(make_actor("FIN7", &["T1059"], &[]));
        let signals = vec![make_ttp_signal("T1059"), make_ttp_signal("T1105")];
        let results = engine.score(&signals);
        if results.len() >= 2 {
            assert!(results[0].score >= results[1].score);
        }
    }

    #[test]
    fn test_attribution_result_label() {
        let make_result = |score: f32| AttributionResult {
            actor_id: "x".into(),
            score,
            matched_signals: 1,
            confidence: (score * 100.0) as u8,
            breakdown: vec![],
            notes: vec![],
        };
        assert_eq!(make_result(0.8).label(), "High");
        assert_eq!(make_result(0.6).label(), "Medium");
        assert_eq!(make_result(0.3).label(), "Low");
        assert_eq!(make_result(0.1).label(), "Unlikely");
    }

    #[test]
    fn test_attribution_result_is_above_threshold() {
        let r = AttributionResult {
            actor_id: "x".into(),
            score: 0.75,
            matched_signals: 2,
            confidence: 75,
            breakdown: vec![],
            notes: vec![],
        };
        assert!(r.is_above_threshold(0.5));
        assert!(!r.is_above_threshold(0.8));
    }

    #[test]
    fn test_attribution_result_display() {
        let r = AttributionResult {
            actor_id: "APT28".into(),
            score: 0.9,
            matched_signals: 3,
            confidence: 90,
            breakdown: vec![],
            notes: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("APT28"));
        assert!(s.contains("High"));
    }

    #[test]
    fn test_score_attribution_free_fn() {
        let actors = vec![make_actor("APT28", &["T1059"], &[])];
        let signals = vec![make_ttp_signal("T1059")];
        let results = score_attribution(&actors, &signals, 0.0);
        assert!(!results.is_empty());
        assert_eq!(results[0].actor_id, "APT28");
    }

    #[test]
    fn test_threat_actor_display() {
        let actor = make_actor("APT28", &["T1059"], &["Sofacy"])
            .with_origin("Russia")
            .with_alias("Fancy Bear");
        let s = actor.to_string();
        assert!(s.contains("APT28"));
        assert!(s.contains("Russia"));
    }

    #[test]
    fn test_top_n() {
        let mut engine = AttributionEngine::new();
        engine.register(make_actor("APT28", &["T1059", "T1105"], &[]));
        engine.register(make_actor("FIN7", &["T1059"], &[]));
        engine.register(make_actor("Lazarus", &["T1078"], &[]));
        let signals = vec![make_ttp_signal("T1059"), make_ttp_signal("T1105")];
        let top = engine.top_n(&signals, 1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].actor_id, "APT28");
    }

    #[test]
    fn test_signal_from_ttp() {
        let ttp = Ttp {
            technique_id: "T1059".into(),
            name: "Command-Line Interface".into(),
            tactic: "exec".into(),
            sub_technique: None,
        };
        let sig = Signal::from_ttp(&ttp, 0.9);
        assert_eq!(sig.kind, SignalKind::Ttp);
        assert_eq!(sig.value, "T1059");
        assert!((sig.weight - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_signal_from_family() {
        let sig = Signal::from_family("Emotet", 0.8);
        assert_eq!(sig.kind, SignalKind::MalwareFamily);
        assert_eq!(sig.value, "Emotet");
    }

    #[test]
    fn test_profile_confidence_scales_score() {
        // Actor with 50% profile confidence should halve the raw score
        let mut engine = AttributionEngine::new().with_min_score(0.0);
        let mut actor = make_actor("LowConf", &["T1059"], &[]);
        actor.profile_confidence = 50;
        engine.register(actor);
        let signals = vec![make_ttp_signal("T1059")];
        let results = engine.score(&signals);
        assert!(!results.is_empty());
        // Raw score = 1.0, scaled = 0.5
        assert!((results[0].score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_engine_no_actors() {
        let engine = AttributionEngine::new();
        let signals = vec![make_ttp_signal("T1059")];
        let results = engine.score(&signals);
        assert!(results.is_empty());
    }
}
