//! Maps MISP galaxies and clusters to MITRE ATT&CK techniques and other
//! threat intelligence taxonomies.
//!
//! Provides `MispGalaxyMapper`, `Galaxy`, `GalaxyCluster`, and the
//! `mitre_technique_id()` lookup used by enrichment pipelines.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── GalaxyType ────────────────────────────────────────────────────────────────

/// High-level category of a MISP galaxy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GalaxyType {
    /// MITRE ATT&CK Enterprise techniques.
    MitreAttack,
    /// MITRE ATT&CK Mobile techniques.
    MitreAttackMobile,
    /// MITRE ATT&CK ICS techniques.
    MitreAttackIcs,
    /// MITRE PRE-ATT&CK.
    MitrePreAttack,
    /// Threat actor groups (e.g. G0001).
    ThreatActor,
    /// Malware families.
    MalwareFamily,
    /// Tooling used by adversaries.
    Tool,
    /// Ransomware families.
    Ransomware,
    /// Exploits.
    Exploit,
    /// Any other galaxy type.
    Other(String),
}

impl GalaxyType {
    /// Create from the MISP `type` field.
    #[must_use]
    pub fn from_misp_type(s: &str) -> Self {
        match s {
            "mitre-attack-pattern" | "mitre-enterprise-attack-attack-pattern" => {
                Self::MitreAttack
            }
            "mitre-mobile-attack-attack-pattern" => Self::MitreAttackMobile,
            "mitre-ics-attack-attack-pattern" => Self::MitreAttackIcs,
            "mitre-pre-attack-attack-pattern" => Self::MitrePreAttack,
            "threat-actor" | "mitre-enterprise-attack-intrusion-set" => Self::ThreatActor,
            "ransomware" => Self::Ransomware,
            "exploit" => Self::Exploit,
            "rat" | "tool" | "mitre-enterprise-attack-tool" => Self::Tool,
            "malpedia" | "malware" | "mitre-enterprise-attack-malware" => Self::MalwareFamily,
            other => Self::Other(other.to_string()),
        }
    }

    /// Return whether this galaxy type maps to MITRE ATT&CK.
    #[must_use]
    pub const fn is_attack(&self) -> bool {
        matches!(
            self,
            Self::MitreAttack | Self::MitreAttackMobile | Self::MitreAttackIcs | Self::MitrePreAttack
        )
    }
}

// ── GalaxyCluster ─────────────────────────────────────────────────────────────

/// A single cluster within a MISP galaxy, representing one technique, actor,
/// tool, or malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalaxyCluster {
    /// UUID of this cluster.
    pub uuid: String,
    /// Cluster value, e.g. `"Process Injection"`.
    pub value: String,
    /// Human-readable description.
    pub description: String,
    /// Cluster type string.
    pub cluster_type: String,
    /// Key-value metadata (e.g. `external_id`, `kill_chain_phases`, …).
    pub meta: HashMap<String, serde_json::Value>,
    /// The full MISP tag name (e.g. `misp-galaxy:mitre-attack-pattern="T1055"`).
    pub tag_name: String,
}

impl GalaxyCluster {
    /// Create a minimal cluster.
    #[must_use]
    pub fn new(uuid: impl Into<String>, value: impl Into<String>, cluster_type: impl Into<String>) -> Self {
        Self {
            uuid: uuid.into(),
            value: value.into(),
            description: String::new(),
            cluster_type: cluster_type.into(),
            meta: HashMap::new(),
            tag_name: String::new(),
        }
    }

    /// Return the MITRE technique ID (e.g. `T1055`) stored in `meta.external_id`,
    /// if present.
    #[must_use]
    pub fn mitre_technique_id(&self) -> Option<&str> {
        self.meta.get("external_id").and_then(|v| v.as_str())
    }

    /// Return the MITRE technique ID extracted from the cluster value or tag
    /// name heuristically, falling back to `meta.external_id`.
    #[must_use]
    pub fn detect_technique_id(&self) -> Option<String> {
        // 1. Check meta first.
        if let Some(id) = self.mitre_technique_id()
            && (id.starts_with('T') || id.starts_with('S') || id.starts_with('G')) {
                return Some(id.to_string());
            }
        // 2. Try to parse from tag_name: `...="T1234"` or `...="T1234.001"`.
        if let Some(eq_pos) = self.tag_name.rfind('=') {
            let candidate = self.tag_name[eq_pos + 1..]
                .trim_matches('"')
                .trim();
            if looks_like_technique_id(candidate) {
                return Some(candidate.to_string());
            }
        }
        // 3. Try the value field.
        if looks_like_technique_id(&self.value) {
            return Some(self.value.clone());
        }
        None
    }

    /// Return all MITRE kill-chain phases for this cluster.
    #[must_use]
    pub fn kill_chain_phases(&self) -> Vec<String> {
        self.meta
            .get("kill_chain")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the MISP galaxy:cluster tag string (e.g. the full namespaced tag).
    #[must_use]
    pub fn misp_tag(&self) -> &str {
        &self.tag_name
    }

    /// Return whether this cluster is a sub-technique (technique ID contains `.`).
    #[must_use]
    pub fn is_sub_technique(&self) -> bool {
        self.detect_technique_id()
            .is_some_and(|id| id.contains('.'))
    }

    /// Return the parent technique ID for a sub-technique, if applicable.
    #[must_use]
    pub fn parent_technique_id(&self) -> Option<String> {
        let id = self.detect_technique_id()?;
        id.find('.').map(|dot_pos| id[..dot_pos].to_string())
    }
}

fn looks_like_technique_id(s: &str) -> bool {
    let s = s.trim();
    // Matches T\d{4}(\.\d{3})? or G\d{4} or S\d{4}
    if s.len() < 5 {
        return false;
    }
    let first = s.chars().next().unwrap_or(' ');
    if !matches!(first, 'T' | 'G' | 'S') {
        return false;
    }
    s[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
}

// ── Galaxy ────────────────────────────────────────────────────────────────────

/// A complete MISP galaxy, containing clusters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Galaxy {
    /// UUID of the galaxy.
    pub uuid: String,
    /// Display name, e.g. `"MITRE ATT&CK"`.
    pub name: String,
    /// Type string, e.g. `"mitre-attack-pattern"`.
    pub galaxy_type: String,
    /// Description of the galaxy.
    pub description: String,
    /// All clusters in this galaxy.
    pub clusters: Vec<GalaxyCluster>,
    /// Schema version.
    pub version: Option<String>,
    /// Whether this galaxy is currently enabled.
    pub enabled: bool,
}

impl Galaxy {
    /// Create a minimal galaxy.
    #[must_use]
    pub fn new(name: impl Into<String>, galaxy_type: impl Into<String>) -> Self {
        Self {
            uuid: format!("galaxy-{:016x}", rand_u64()),
            name: name.into(),
            galaxy_type: galaxy_type.into(),
            description: String::new(),
            clusters: Vec::new(),
            version: None,
            enabled: true,
        }
    }

    /// Add a cluster to this galaxy.
    pub fn add_cluster(&mut self, cluster: GalaxyCluster) {
        self.clusters.push(cluster);
    }

    /// Find a cluster by exact value match.
    #[must_use]
    pub fn find_by_value(&self, value: &str) -> Option<&GalaxyCluster> {
        self.clusters.iter().find(|c| c.value == value)
    }

    /// Find a cluster by MITRE technique ID.
    #[must_use]
    pub fn find_by_technique_id(&self, id: &str) -> Option<&GalaxyCluster> {
        self.clusters
            .iter()
            .find(|c| c.detect_technique_id().as_deref() == Some(id))
    }

    /// Return all clusters that belong to the given kill-chain phase.
    #[must_use]
    pub fn clusters_for_phase(&self, phase: &str) -> Vec<&GalaxyCluster> {
        self.clusters
            .iter()
            .filter(|c| {
                c.kill_chain_phases()
                    .iter()
                    .any(|p| p.to_lowercase().contains(&phase.to_lowercase()))
            })
            .collect()
    }

    /// Return the high-level [`GalaxyType`] for this galaxy.
    #[must_use]
    pub fn typed(&self) -> GalaxyType {
        GalaxyType::from_misp_type(&self.galaxy_type)
    }

    /// Return all sub-technique clusters in this galaxy.
    #[must_use]
    pub fn sub_techniques(&self) -> Vec<&GalaxyCluster> {
        self.clusters.iter().filter(|c| c.is_sub_technique()).collect()
    }
}

// ── AttackTechniqueInfo ───────────────────────────────────────────────────────

/// Enriched information about a mapped ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechniqueInfo {
    /// The technique ID, e.g. `T1055`.
    pub technique_id: String,
    /// The technique name.
    pub name: String,
    /// ATT&CK tactic(s) this technique belongs to.
    pub tactics: Vec<String>,
    /// Whether this is a sub-technique.
    pub is_sub_technique: bool,
    /// Parent technique ID if this is a sub-technique.
    pub parent_id: Option<String>,
    /// Full URL in the ATT&CK Navigator.
    pub navigator_url: String,
    /// MISP galaxy cluster UUID.
    pub cluster_uuid: String,
}

impl AttackTechniqueInfo {
    /// Construct from a galaxy cluster.
    #[must_use]
    pub fn from_cluster(cluster: &GalaxyCluster) -> Option<Self> {
        let technique_id = cluster.detect_technique_id()?;
        let url = format!(
            "https://attack.mitre.org/techniques/{}/",
            technique_id.replace('.', "/")
        );
        Some(Self {
            technique_id,
            name: cluster.value.clone(),
            tactics: cluster.kill_chain_phases(),
            is_sub_technique: cluster.is_sub_technique(),
            parent_id: cluster.parent_technique_id(),
            navigator_url: url,
            cluster_uuid: cluster.uuid.clone(),
        })
    }
}

// ── MispGalaxyMapper ──────────────────────────────────────────────────────────

/// Maps MISP galaxies to MITRE ATT&CK techniques and threat intelligence
/// taxonomies.
pub struct MispGalaxyMapper {
    /// All registered galaxies keyed by galaxy type string.
    galaxies: HashMap<String, Galaxy>,
    /// Technique ID → cluster UUID index for fast lookup.
    technique_index: HashMap<String, String>,
    /// Actor name → galaxy UUID.
    actor_index: HashMap<String, String>,
}

impl MispGalaxyMapper {
    /// Create a new mapper and load built-in ATT&CK galaxy data.
    #[must_use]
    pub fn new() -> Self {
        let mut mapper = Self {
            galaxies: HashMap::new(),
            technique_index: HashMap::new(),
            actor_index: HashMap::new(),
        };
        mapper.load_builtin_galaxies();
        mapper
    }

    /// Register a galaxy with the mapper.
    pub fn register_galaxy(&mut self, galaxy: Galaxy) {
        // Index clusters.
        for cluster in &galaxy.clusters {
            if let Some(tech_id) = cluster.detect_technique_id() {
                self.technique_index.insert(tech_id, cluster.uuid.clone());
            }
            if galaxy.typed() == GalaxyType::ThreatActor {
                self.actor_index
                    .insert(cluster.value.to_lowercase(), cluster.uuid.clone());
            }
        }
        self.galaxies.insert(galaxy.galaxy_type.clone(), galaxy);
    }

    /// Look up the ATT&CK technique info for a MITRE technique ID.
    #[must_use]
    pub fn technique_info(&self, technique_id: &str) -> Option<AttackTechniqueInfo> {
        let cluster_uuid = self.technique_index.get(technique_id)?;
        for galaxy in self.galaxies.values() {
            if let Some(cluster) = galaxy.clusters.iter().find(|c| &c.uuid == cluster_uuid) {
                return AttackTechniqueInfo::from_cluster(cluster);
            }
        }
        None
    }

    /// Return the MITRE technique ID for a cluster identified by UUID.
    #[must_use]
    pub fn mitre_technique_id(&self, cluster_uuid: &str) -> Option<String> {
        for galaxy in self.galaxies.values() {
            if let Some(cluster) = galaxy.clusters.iter().find(|c| c.uuid == cluster_uuid) {
                return cluster.detect_technique_id();
            }
        }
        None
    }

    /// Map a MISP tag string (e.g. `misp-galaxy:mitre-attack-pattern="T1055"`)
    /// to a technique ID.
    #[must_use]
    pub fn tag_to_technique_id(&self, tag: &str) -> Option<String> {
        // Extract the part after the last `=`.
        let value = tag.rsplit('=').next()?.trim().trim_matches('"');
        if looks_like_technique_id(value) {
            return Some(value.to_string());
        }
        // Fall back: search all clusters for matching tag.
        for galaxy in self.galaxies.values() {
            if let Some(cluster) = galaxy.clusters.iter().find(|c| c.tag_name == tag) {
                return cluster.detect_technique_id();
            }
        }
        None
    }

    /// Map a threat-actor cluster name to its known technique IDs.
    #[must_use]
    pub fn actor_techniques(&self, actor_name: &str) -> Vec<String> {
        // In a real implementation this would query a relationship database.
        // Here we return an empty vec unless the actor has known techniques stored
        // in its cluster meta.
        let lower = actor_name.to_lowercase();
        let cluster_uuid = match self.actor_index.get(&lower) {
            Some(u) => u.clone(),
            None => return vec![],
        };
        for galaxy in self.galaxies.values() {
            if let Some(cluster) = galaxy.clusters.iter().find(|c| c.uuid == cluster_uuid)
                && let Some(techs) = cluster.meta.get("techniques") {
                    return techs
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                }
        }
        vec![]
    }

    /// List all registered galaxies.
    #[must_use]
    pub fn galaxies(&self) -> Vec<&Galaxy> {
        self.galaxies.values().collect()
    }

    /// Return all ATT&CK technique IDs indexed by this mapper.
    #[must_use]
    pub fn all_technique_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.technique_index.keys().cloned().collect();
        ids.sort_unstable();
        ids
    }

    /// Return all clusters for a given ATT&CK tactic (e.g. `"execution"`).
    #[must_use]
    pub fn clusters_for_tactic(&self, tactic: &str) -> Vec<AttackTechniqueInfo> {
        let mut results = Vec::new();
        for galaxy in self.galaxies.values() {
            if !galaxy.typed().is_attack() {
                continue;
            }
            for cluster in galaxy.clusters_for_phase(tactic) {
                if let Some(info) = AttackTechniqueInfo::from_cluster(cluster) {
                    results.push(info);
                }
            }
        }
        results
    }

    /// Look up a cluster by value string across all registered galaxies.
    #[must_use]
    pub fn find_cluster_by_value(&self, value: &str) -> Option<(&Galaxy, &GalaxyCluster)> {
        for galaxy in self.galaxies.values() {
            if let Some(cluster) = galaxy.find_by_value(value) {
                return Some((galaxy, cluster));
            }
        }
        None
    }

    /// Convert a list of MISP tags to ATT&CK technique IDs.
    #[must_use]
    pub fn tags_to_technique_ids(&self, tags: &[String]) -> Vec<String> {
        tags.iter()
            .filter_map(|tag| self.tag_to_technique_id(tag))
            .collect()
    }

    /// Convert a list of MISP tags to `AttackTechniqueInfo` records.
    #[must_use]
    pub fn tags_to_technique_infos(&self, tags: &[String]) -> Vec<AttackTechniqueInfo> {
        tags.iter()
            .filter_map(|tag| {
                let id = self.tag_to_technique_id(tag)?;
                self.technique_info(&id)
            })
            .collect()
    }

    fn load_builtin_galaxies(&mut self) {
        let mut attack = Galaxy::new("MITRE ATT&CK", "mitre-attack-pattern");
        attack.description =
            "MITRE ATT&CK framework technique galaxy (Enterprise)".to_string();

        let techniques: &[(&str, &str, &str, &[&str])] = &[
            (
                "T1059",
                "Command and Scripting Interpreter",
                "execution",
                &["execution"],
            ),
            (
                "T1059.001",
                "PowerShell",
                "execution",
                &["execution"],
            ),
            (
                "T1059.003",
                "Windows Command Shell",
                "execution",
                &["execution"],
            ),
            (
                "T1055",
                "Process Injection",
                "defense-evasion",
                &["defense-evasion", "privilege-escalation"],
            ),
            (
                "T1055.001",
                "Dynamic-link Library Injection",
                "defense-evasion",
                &["defense-evasion", "privilege-escalation"],
            ),
            (
                "T1105",
                "Ingress Tool Transfer",
                "command-and-control",
                &["command-and-control"],
            ),
            (
                "T1027",
                "Obfuscated Files or Information",
                "defense-evasion",
                &["defense-evasion"],
            ),
            (
                "T1562",
                "Impair Defenses",
                "defense-evasion",
                &["defense-evasion"],
            ),
            (
                "T1082",
                "System Information Discovery",
                "discovery",
                &["discovery"],
            ),
            (
                "T1083",
                "File and Directory Discovery",
                "discovery",
                &["discovery"],
            ),
            (
                "T1486",
                "Data Encrypted for Impact",
                "impact",
                &["impact"],
            ),
            (
                "T1490",
                "Inhibit System Recovery",
                "impact",
                &["impact"],
            ),
            (
                "T1566",
                "Phishing",
                "initial-access",
                &["initial-access"],
            ),
            (
                "T1566.001",
                "Spearphishing Attachment",
                "initial-access",
                &["initial-access"],
            ),
            (
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
                &["initial-access"],
            ),
            (
                "T1078",
                "Valid Accounts",
                "initial-access",
                &["defense-evasion", "initial-access", "persistence", "privilege-escalation"],
            ),
            (
                "T1003",
                "OS Credential Dumping",
                "credential-access",
                &["credential-access"],
            ),
            (
                "T1003.001",
                "LSASS Memory",
                "credential-access",
                &["credential-access"],
            ),
            (
                "T1021",
                "Remote Services",
                "lateral-movement",
                &["lateral-movement"],
            ),
            (
                "T1021.001",
                "Remote Desktop Protocol",
                "lateral-movement",
                &["lateral-movement"],
            ),
        ];

        for (id, name, phase, phases) in techniques {
            let uuid = format!("attack-{id}");
            let tag = format!("misp-galaxy:mitre-attack-pattern=\"{id}\"");
            let mut cluster = GalaxyCluster::new(uuid, *name, "mitre-attack-pattern");
            cluster.tag_name = tag;
            cluster.meta.insert(
                "external_id".to_string(),
                serde_json::Value::String(id.to_string()),
            );
            let phases_json: Vec<serde_json::Value> = phases
                .iter()
                .map(|p| serde_json::Value::String(p.to_string()))
                .collect();
            cluster
                .meta
                .insert("kill_chain".to_string(), serde_json::Value::Array(phases_json));
            let _ = phase;
            attack.add_cluster(cluster);
        }

        self.register_galaxy(attack);

        // Threat actor galaxy (sample).
        let mut actors = Galaxy::new("Threat Actors", "threat-actor");
        actors.description = "Known threat actor groups".to_string();

        let actor_data: &[(&str, &str)] = &[
            ("APT28", "Russian state-sponsored group (Fancy Bear / Sofacy)"),
            ("APT29", "Russian state-sponsored group (Cozy Bear / The Dukes)"),
            ("Lazarus Group", "North Korean state-sponsored group"),
            ("FIN7", "Financially motivated criminal group"),
            ("Carbanak", "Banking-focused criminal group"),
        ];

        for (name, desc) in actor_data {
            let uuid = format!("actor-{}", name.to_lowercase().replace(' ', "-"));
            let mut cluster = GalaxyCluster::new(uuid, *name, "threat-actor");
            cluster.description = desc.to_string();
            cluster.tag_name = format!("misp-galaxy:threat-actor=\"{name}\"");
            actors.add_cluster(cluster);
        }

        self.register_galaxy(actors);
    }
}

impl Default for MispGalaxyMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rand_u64() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    h.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper() -> MispGalaxyMapper {
        MispGalaxyMapper::new()
    }

    #[test]
    fn test_mapper_has_galaxies() {
        let m = mapper();
        assert!(!m.galaxies().is_empty());
    }

    #[test]
    fn test_technique_ids_non_empty() {
        let m = mapper();
        assert!(!m.all_technique_ids().is_empty());
    }

    #[test]
    fn test_technique_ids_sorted() {
        let m = mapper();
        let ids = m.all_technique_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn test_technique_info_t1055() {
        let m = mapper();
        let info = m.technique_info("T1055").unwrap();
        assert_eq!(info.technique_id, "T1055");
        assert!(!info.name.is_empty());
        assert!(!info.tactics.is_empty());
    }

    #[test]
    fn test_technique_info_subtechnique() {
        let m = mapper();
        let info = m.technique_info("T1055.001").unwrap();
        assert!(info.is_sub_technique);
        assert_eq!(info.parent_id.as_deref(), Some("T1055"));
    }

    #[test]
    fn test_technique_info_t1059_powershell() {
        let m = mapper();
        let info = m.technique_info("T1059.001").unwrap();
        assert_eq!(info.technique_id, "T1059.001");
        assert!(info.navigator_url.contains("T1059"));
    }

    #[test]
    fn test_technique_info_unknown_returns_none() {
        let m = mapper();
        assert!(m.technique_info("T9999").is_none());
    }

    #[test]
    fn test_tag_to_technique_id_format() {
        let m = mapper();
        let tag = "misp-galaxy:mitre-attack-pattern=\"T1055\"";
        assert_eq!(m.tag_to_technique_id(tag).as_deref(), Some("T1055"));
    }

    #[test]
    fn test_tag_to_technique_id_subtechnique() {
        let m = mapper();
        let tag = "misp-galaxy:mitre-attack-pattern=\"T1055.001\"";
        assert_eq!(m.tag_to_technique_id(tag).as_deref(), Some("T1055.001"));
    }

    #[test]
    fn test_tag_to_technique_id_no_match() {
        let m = mapper();
        assert!(m.tag_to_technique_id("not-a-galaxy-tag").is_none());
    }

    #[test]
    fn test_tags_to_technique_ids() {
        let m = mapper();
        let tags = vec![
            "misp-galaxy:mitre-attack-pattern=\"T1059\"".to_string(),
            "misp-galaxy:mitre-attack-pattern=\"T1055\"".to_string(),
        ];
        let ids = m.tags_to_technique_ids(&tags);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"T1059".to_string()));
        assert!(ids.contains(&"T1055".to_string()));
    }

    #[test]
    fn test_clusters_for_tactic_execution() {
        let m = mapper();
        let techs = m.clusters_for_tactic("execution");
        assert!(!techs.is_empty());
        for t in &techs {
            assert!(t.tactics.iter().any(|t2| t2.contains("execution")));
        }
    }

    #[test]
    fn test_find_cluster_by_value_process_injection() {
        let m = mapper();
        let result = m.find_cluster_by_value("Process Injection");
        assert!(result.is_some());
        let (_, cluster) = result.unwrap();
        assert_eq!(cluster.value, "Process Injection");
    }

    #[test]
    fn test_find_cluster_by_value_unknown() {
        let m = mapper();
        assert!(m.find_cluster_by_value("NonexistentTechnique").is_none());
    }

    #[test]
    fn test_galaxy_find_by_technique_id() {
        let m = mapper();
        let galaxy = m.galaxies.get("mitre-attack-pattern").unwrap();
        let cluster = galaxy.find_by_technique_id("T1486").unwrap();
        assert_eq!(cluster.detect_technique_id().as_deref(), Some("T1486"));
    }

    #[test]
    fn test_galaxy_sub_techniques() {
        let m = mapper();
        let galaxy = m.galaxies.get("mitre-attack-pattern").unwrap();
        let subs = galaxy.sub_techniques();
        assert!(!subs.is_empty());
        for s in subs {
            assert!(s.detect_technique_id().unwrap().contains('.'));
        }
    }

    #[test]
    fn test_galaxy_type_is_attack() {
        assert!(GalaxyType::MitreAttack.is_attack());
        assert!(GalaxyType::MitreAttackMobile.is_attack());
        assert!(!GalaxyType::ThreatActor.is_attack());
        assert!(!GalaxyType::MalwareFamily.is_attack());
    }

    #[test]
    fn test_galaxy_type_from_misp_type() {
        assert_eq!(
            GalaxyType::from_misp_type("mitre-attack-pattern"),
            GalaxyType::MitreAttack
        );
        assert_eq!(
            GalaxyType::from_misp_type("threat-actor"),
            GalaxyType::ThreatActor
        );
    }

    #[test]
    fn test_cluster_parent_technique_id() {
        let m = mapper();
        let info = m.technique_info("T1003.001").unwrap();
        assert_eq!(info.parent_id.as_deref(), Some("T1003"));
    }

    #[test]
    fn test_cluster_is_not_sub_technique() {
        let m = mapper();
        let info = m.technique_info("T1003").unwrap();
        assert!(!info.is_sub_technique);
        assert!(info.parent_id.is_none());
    }

    #[test]
    fn test_actor_galaxy_registered() {
        let m = mapper();
        assert!(m.galaxies.contains_key("threat-actor"));
    }

    #[test]
    fn test_navigator_url_format() {
        let m = mapper();
        let info = m.technique_info("T1566.001").unwrap();
        assert!(info.navigator_url.contains("T1566"));
        assert!(info.navigator_url.contains("001"));
    }

    #[test]
    fn test_looks_like_technique_id_true() {
        assert!(looks_like_technique_id("T1055"));
        assert!(looks_like_technique_id("T1055.001"));
        assert!(looks_like_technique_id("G0001"));
        assert!(looks_like_technique_id("S0154"));
    }

    #[test]
    fn test_looks_like_technique_id_false() {
        assert!(!looks_like_technique_id("notanid"));
        assert!(!looks_like_technique_id("X1234"));
        assert!(!looks_like_technique_id("T12")); // too short
    }

    #[test]
    fn test_cluster_new_defaults() {
        let c = GalaxyCluster::new("uuid1", "Process Injection", "mitre-attack-pattern");
        assert_eq!(c.value, "Process Injection");
        assert!(c.description.is_empty());
        assert!(c.meta.is_empty());
    }
}
