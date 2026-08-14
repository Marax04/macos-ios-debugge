//! Malware family database: 100+ family entries, relationships, timelines,
//! TTP mappings, and full-text search.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── MalwareFamily ────────────────────────────────────────────────────────────

/// A malware family entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareFamily {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub category: MalwareCategory,
    pub platform: Vec<String>,
    pub first_seen_year: u16,
    pub last_seen_year: Option<u16>,
    pub description: String,
    pub attributed_actors: Vec<String>,
    pub ttp_ids: Vec<String>,
    pub yara_rule_names: Vec<String>,
    pub language: String,
    pub packer: Option<String>,
    pub c2_protocols: Vec<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub is_active: bool,
}

impl MalwareFamily {
    /// Create a minimal family entry.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: MalwareCategory,
        platform: &[&str],
        first_seen_year: u16,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            aliases: vec![],
            category,
            platform: platform.iter().map(std::string::ToString::to_string).collect(),
            first_seen_year,
            last_seen_year: None,
            description: String::new(),
            attributed_actors: vec![],
            ttp_ids: vec![],
            yara_rule_names: vec![],
            language: String::new(),
            packer: None,
            c2_protocols: vec![],
            tags: vec![],
            references: vec![],
            is_active: true,
        }
    }

    /// Returns `true` if this family has any alias matching the given name.
    #[must_use]
    pub fn matches_alias(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.name.to_ascii_lowercase().contains(&lower)
            || self
                .aliases
                .iter()
                .any(|a| a.to_ascii_lowercase().contains(&lower))
    }

    /// Returns `true` if this family has the given TTP.
    #[must_use]
    pub fn has_ttp(&self, ttp: &str) -> bool {
        self.ttp_ids.contains(&ttp.to_string())
    }

    /// Add a TTP.
    pub fn add_ttp(&mut self, ttp: impl Into<String>) {
        self.ttp_ids.push(ttp.into());
    }
    /// Add an alias.
    pub fn add_alias(&mut self, alias: impl Into<String>) {
        self.aliases.push(alias.into());
    }
    /// Add a YARA rule name.
    pub fn add_yara(&mut self, rule: impl Into<String>) {
        self.yara_rule_names.push(rule.into());
    }
    /// Add a C2 protocol.
    pub fn add_c2(&mut self, proto: impl Into<String>) {
        self.c2_protocols.push(proto.into());
    }
    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }
}

/// High-level malware category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MalwareCategory {
    Ransomware,
    Trojan,
    Rat,
    Loader,
    Dropper,
    Worm,
    Rootkit,
    Bootkit,
    Spyware,
    Keylogger,
    Banker,
    Stealer,
    Botnet,
    Backdoor,
    Implant,
    Cryptominer,
    Exploit,
    Framework,
    Other(String),
}

impl fmt::Display for MalwareCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ransomware => "ransomware",
            Self::Trojan => "trojan",
            Self::Rat => "rat",
            Self::Loader => "loader",
            Self::Dropper => "dropper",
            Self::Worm => "worm",
            Self::Rootkit => "rootkit",
            Self::Bootkit => "bootkit",
            Self::Spyware => "spyware",
            Self::Keylogger => "keylogger",
            Self::Banker => "banker",
            Self::Stealer => "stealer",
            Self::Botnet => "botnet",
            Self::Backdoor => "backdoor",
            Self::Implant => "implant",
            Self::Cryptominer => "cryptominer",
            Self::Exploit => "exploit",
            Self::Framework => "framework",
            Self::Other(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// ─── FamilyRelationship ───────────────────────────────────────────────────────

/// A relationship between two malware families.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyRelationship {
    pub from_id: String,
    pub to_id: String,
    pub relationship_type: RelationshipType,
    pub confidence: u8,
    pub notes: String,
}

/// Type of family relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipType {
    /// Direct code fork/evolution.
    Variant,
    /// Shares significant code.
    CodeSharing,
    /// Uses the other as a loader/dropper.
    LoadedBy,
    /// Used together in the same campaign.
    CampaignBuddy,
    /// Part of the same malware-as-a-service ecosystem.
    Maas,
    /// Successor (next generation).
    Successor,
    /// Predecessor.
    Predecessor,
}

impl fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Variant => write!(f, "variant"),
            Self::CodeSharing => write!(f, "code_sharing"),
            Self::LoadedBy => write!(f, "loaded_by"),
            Self::CampaignBuddy => write!(f, "campaign_buddy"),
            Self::Maas => write!(f, "maas"),
            Self::Successor => write!(f, "successor"),
            Self::Predecessor => write!(f, "predecessor"),
        }
    }
}

impl FamilyRelationship {
    /// Create a new relationship.
    #[must_use]
    pub fn new(
        from_id: impl Into<String>,
        to_id: impl Into<String>,
        relationship_type: RelationshipType,
        confidence: u8,
    ) -> Self {
        Self {
            from_id: from_id.into(),
            to_id: to_id.into(),
            relationship_type,
            confidence: confidence.min(100),
            notes: String::new(),
        }
    }
}

// ─── FamilyTimeline ───────────────────────────────────────────────────────────

/// A timeline of events for a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyTimeline {
    pub family_id: String,
    pub events: Vec<FamilyTimelineEvent>,
}

/// A single event in a family's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyTimelineEvent {
    pub year: u16,
    pub month: Option<u8>,
    pub event_type: FamilyEventType,
    pub description: String,
}

/// Type of family event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FamilyEventType {
    FirstAppearance,
    MajorVersion,
    NewCapability,
    CampaignActivity,
    DisruptionOperation,
    InfrastructureTakedown,
    SourceCodeLeak,
    Rebrand,
    Retirement,
}

impl fmt::Display for FamilyEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstAppearance => write!(f, "first_appearance"),
            Self::MajorVersion => write!(f, "major_version"),
            Self::NewCapability => write!(f, "new_capability"),
            Self::CampaignActivity => write!(f, "campaign_activity"),
            Self::DisruptionOperation => write!(f, "disruption_operation"),
            Self::InfrastructureTakedown => write!(f, "infra_takedown"),
            Self::SourceCodeLeak => write!(f, "source_code_leak"),
            Self::Rebrand => write!(f, "rebrand"),
            Self::Retirement => write!(f, "retirement"),
        }
    }
}

impl FamilyTimeline {
    /// Create a new timeline.
    #[must_use]
    pub fn new(family_id: impl Into<String>) -> Self {
        Self {
            family_id: family_id.into(),
            events: vec![],
        }
    }

    /// Add an event.
    pub fn add_event(
        &mut self,
        year: u16,
        event_type: FamilyEventType,
        description: impl Into<String>,
    ) {
        self.events.push(FamilyTimelineEvent {
            year,
            month: None,
            event_type,
            description: description.into(),
        });
    }

    /// Sort events by year.
    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.year);
    }

    /// Events in a year range.
    #[must_use]
    pub fn in_range(&self, start: u16, end: u16) -> Vec<&FamilyTimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.year >= start && e.year <= end)
            .collect()
    }

    /// Returns `true` if still active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self
            .events
            .iter()
            .any(|e| e.event_type == FamilyEventType::Retirement)
    }
}

// ─── FamilyTtp ────────────────────────────────────────────────────────────────

/// TTP mapping for a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyTtp {
    pub family_id: String,
    pub technique_id: String,
    pub tactic: String,
    pub description: String,
    pub confidence: u8,
    pub observed_in_wild: bool,
}

impl FamilyTtp {
    /// Create a new TTP mapping.
    #[must_use]
    pub fn new(
        family_id: impl Into<String>,
        technique_id: impl Into<String>,
        tactic: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            family_id: family_id.into(),
            technique_id: technique_id.into(),
            tactic: tactic.into(),
            description: String::new(),
            confidence: confidence.min(100),
            observed_in_wild: true,
        }
    }
}

// ─── FamilySearch ─────────────────────────────────────────────────────────────

/// Full-text search over the family database.
#[derive(Debug, Clone, Default)]
pub struct FamilySearch;

impl FamilySearch {
    /// Search families by name, alias, description, or tags.
    #[must_use]
    pub fn search<'a>(query: &str, families: &'a [MalwareFamily]) -> Vec<&'a MalwareFamily> {
        let q = query.to_ascii_lowercase();
        families
            .iter()
            .filter(|f| {
                f.name.to_ascii_lowercase().contains(&q)
                    || f.aliases
                        .iter()
                        .any(|a| a.to_ascii_lowercase().contains(&q))
                    || f.description.to_ascii_lowercase().contains(&q)
                    || f.tags.iter().any(|t| t.to_ascii_lowercase().contains(&q))
                    || f.attributed_actors
                        .iter()
                        .any(|a| a.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    /// Filter by category.
    #[must_use]
    pub fn by_category<'a>(
        cat: &MalwareCategory,
        families: &'a [MalwareFamily],
    ) -> Vec<&'a MalwareFamily> {
        families.iter().filter(|f| &f.category == cat).collect()
    }

    /// Filter by actor.
    #[must_use]
    pub fn by_actor<'a>(actor: &str, families: &'a [MalwareFamily]) -> Vec<&'a MalwareFamily> {
        let lower = actor.to_ascii_lowercase();
        families
            .iter()
            .filter(|f| {
                f.attributed_actors
                    .iter()
                    .any(|a| a.to_ascii_lowercase().contains(&lower))
            })
            .collect()
    }

    /// Filter by TTP.
    #[must_use]
    pub fn by_ttp<'a>(ttp: &str, families: &'a [MalwareFamily]) -> Vec<&'a MalwareFamily> {
        families.iter().filter(|f| f.has_ttp(ttp)).collect()
    }

    /// Filter by platform.
    #[must_use]
    pub fn by_platform<'a>(
        platform: &str,
        families: &'a [MalwareFamily],
    ) -> Vec<&'a MalwareFamily> {
        let lower = platform.to_ascii_lowercase();
        families
            .iter()
            .filter(|f| {
                f.platform
                    .iter()
                    .any(|p| p.to_ascii_lowercase().contains(&lower))
            })
            .collect()
    }
}

// ─── FamilyDatabase ───────────────────────────────────────────────────────────

/// The main malware family database with 100+ entries.
pub struct FamilyDatabase {
    pub families: Vec<MalwareFamily>,
    pub relationships: Vec<FamilyRelationship>,
    pub timelines: HashMap<String, FamilyTimeline>,
    pub ttp_mappings: Vec<FamilyTtp>,
    index: HashMap<String, usize>,
}

impl FamilyDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: vec![],
            relationships: vec![],
            timelines: HashMap::new(),
            ttp_mappings: vec![],
            index: HashMap::new(),
        }
    }

    /// Add a family entry.
    pub fn add(&mut self, family: MalwareFamily) {
        self.index.insert(family.id.clone(), self.families.len());
        self.families.push(family);
    }

    /// Get a family by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&MalwareFamily> {
        self.index.get(id).and_then(|&i| self.families.get(i))
    }

    /// Search by name/alias/description.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&MalwareFamily> {
        FamilySearch::search(query, &self.families)
    }

    /// All families in a category.
    #[must_use]
    pub fn by_category(&self, cat: &MalwareCategory) -> Vec<&MalwareFamily> {
        FamilySearch::by_category(cat, &self.families)
    }

    /// All families for an actor.
    #[must_use]
    pub fn by_actor(&self, actor: &str) -> Vec<&MalwareFamily> {
        FamilySearch::by_actor(actor, &self.families)
    }

    /// Total family count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.families.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    /// Add a relationship.
    pub fn add_relationship(&mut self, rel: FamilyRelationship) {
        self.relationships.push(rel);
    }

    /// Get all relationships for a family.
    #[must_use]
    pub fn relationships_for(&self, id: &str) -> Vec<&FamilyRelationship> {
        self.relationships
            .iter()
            .filter(|r| r.from_id == id || r.to_id == id)
            .collect()
    }

    /// Add a TTP mapping.
    pub fn add_ttp_mapping(&mut self, ttp: FamilyTtp) {
        self.ttp_mappings.push(ttp);
    }

    /// Build the full database with 100+ families.
    #[must_use]
    pub fn build() -> Self {
        let mut db = Self::new();
        Self::add_ransomware(&mut db);
        Self::add_rats_backdoors(&mut db);
        Self::add_loaders(&mut db);
        Self::add_rootkits(&mut db);
        Self::add_worms(&mut db);
        Self::add_apt_implants(&mut db);
        Self::add_relationships(&mut db);
        Self::add_timelines(&mut db);
        db
    }

    fn add_ransomware(db: &mut Self) {
        let rw_families: &[(&str, &str, &[&str], u16)] = &[
            (
                "MAL-001",
                "WannaCry",
                &["WCry", "WannaCrypt", "WanaCrypt0r"],
                2017,
            ),
            (
                "MAL-002",
                "NotPetya",
                &["Petya", "ExPetr", "GoldenEye"],
                2017,
            ),
            ("MAL-003", "REvil", &["Sodinokibi", "Sodin"], 2019),
            (
                "MAL-004",
                "LockBit",
                &["ABCD", "LockBit 2.0", "LockBit 3.0"],
                2019,
            ),
            ("MAL-005", "DarkSide", &["BlackMatter"], 2020),
            ("MAL-006", "Conti", &["Ryuk variant"], 2020),
            ("MAL-007", "BlackCat", &["ALPHV", "Noberus"], 2021),
            ("MAL-008", "Hive", &["Hive v5"], 2021),
            ("MAL-009", "Ryuk", &["Hermes"], 2018),
            ("MAL-010", "Maze", &["ChaCha"], 2019),
            ("MAL-011", "Dharma", &["Crisis", "Phobos"], 2016),
            ("MAL-012", "Cl0p", &["Clop", "TA505"], 2019),
            ("MAL-013", "Ragnar Locker", &["RagnarLocker"], 2020),
            ("MAL-014", "BlackBasta", &["Black Basta"], 2022),
            ("MAL-015", "Play", &["PlayCrypt"], 2022),
            ("MAL-016", "Royal", &["Zeon"], 2022),
            ("MAL-017", "Quantum", &["MountLocker"], 2021),
            ("MAL-018", "Egregor", &["Sekhmet"], 2020),
            ("MAL-019", "NetWalker", &["Mailto", "Kokoklock"], 2019),
            ("MAL-020", "Avaddon", &["AES Ransomware"], 2020),
            ("MAL-021", "Zeppelin", &["Vega", "VegaLocker"], 2019),
            ("MAL-022", "Phobos", &["Phobos v2"], 2019),
            ("MAL-023", "MedusaLocker", &["Medusa Locker"], 2019),
            ("MAL-024", "CryptoLocker", &["Zbot loader"], 2013),
            ("MAL-025", "Locky", &["Zepto", "Odin", "Thor"], 2016),
        ];
        for (id, name, aliases, year) in rw_families {
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                MalwareCategory::Ransomware,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            f.add_ttp("T1486");
            f.add_ttp("T1490");
            f.tag("ransomware");
            db.add(f);
        }
    }

    fn add_rats_backdoors(db: &mut Self) {
        let rat_families: &[(&str, &str, &[&str], u16, &str)] = &[
            (
                "MAL-101",
                "Cobalt Strike",
                &["CS", "CobaltStrike Beacon"],
                2012,
                "Framework",
            ),
            ("MAL-102", "Metasploit", &["Meterpreter"], 2003, "Framework"),
            (
                "MAL-103",
                "AgentTesla",
                &["Agent Tesla", "OriginLogger"],
                2014,
                "Stealer",
            ),
            ("MAL-104", "AsyncRAT", &["Async", "HVNC"], 2019, "Rat"),
            ("MAL-105", "RemcosRAT", &["Remcos"], 2016, "Rat"),
            ("MAL-106", "NjRAT", &["Njw0rm", "Bladabindi"], 2013, "Rat"),
            ("MAL-107", "QuasarRAT", &["Quasar"], 2014, "Rat"),
            ("MAL-108", "DarkComet", &["DCraton"], 2008, "Rat"),
            ("MAL-109", "Emotet", &["Heodo", "Geodo"], 2014, "Trojan"),
            (
                "MAL-110",
                "Trickbot",
                &["TrickLoader", "TrickStealer"],
                2016,
                "Trojan",
            ),
            (
                "MAL-111",
                "Qakbot",
                &["QBot", "Pinkslipbot"],
                2008,
                "Trojan",
            ),
            ("MAL-112", "IcedID", &["BokBot"], 2017, "Trojan"),
            ("MAL-113", "Ursnif", &["Gozi", "ISFB"], 2006, "Banker"),
            ("MAL-114", "Dridex", &["Bugat", "Cridex"], 2011, "Banker"),
            ("MAL-115", "Formbook", &["xLoader"], 2016, "Stealer"),
            ("MAL-116", "Lumma", &["LummaC", "LummaC2"], 2022, "Stealer"),
            ("MAL-117", "RedLine", &["RedLine Stealer"], 2020, "Stealer"),
            ("MAL-118", "Vidar", &["Arkei variant"], 2018, "Stealer"),
            (
                "MAL-119",
                "Raccoon Stealer",
                &["Raccoon", "LeafPhp"],
                2019,
                "Stealer",
            ),
            ("MAL-120", "Mars Stealer", &["Mars"], 2021, "Stealer"),
            ("MAL-121", "AZORult", &["AZORult Stealer"], 2016, "Stealer"),
            (
                "MAL-122",
                "SolarMarker",
                &["Jupyter", "Yellow Cockatoo"],
                2020,
                "Backdoor",
            ),
            (
                "MAL-123",
                "Sliver",
                &["BishopFox Sliver"],
                2019,
                "Framework",
            ),
            ("MAL-124", "Havoc", &["HavocFramework"], 2022, "Framework"),
            ("MAL-125", "Brute Ratel", &["BRC4"], 2021, "Framework"),
        ];
        for (id, name, aliases, year, cat_str) in rat_families {
            let cat = match *cat_str {
                "Framework" => MalwareCategory::Framework,
                "Stealer" => MalwareCategory::Stealer,
                "Rat" => MalwareCategory::Rat,
                "Trojan" => MalwareCategory::Trojan,
                "Banker" => MalwareCategory::Banker,
                "Backdoor" => MalwareCategory::Backdoor,
                _ => MalwareCategory::Other(cat_str.to_string()),
            };
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                cat,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            f.add_ttp("T1071.001");
            db.add(f);
        }
    }

    fn add_loaders(db: &mut Self) {
        let loader_families: &[(&str, &str, &[&str], u16)] = &[
            (
                "MAL-201",
                "BazarLoader",
                &["BazarBackdoor", "BazaLoader"],
                2020,
            ),
            ("MAL-202", "GuLoader", &["CloudEyE"], 2019),
            ("MAL-203", "SmokeLoader", &["Smoke", "Dofoil"], 2011),
            ("MAL-204", "GootLoader", &["GootKit", "Goot"], 2014),
            ("MAL-205", "SystemBC", &["Coroxy"], 2019),
            ("MAL-206", "Pikabot", &["PikaBot"], 2023),
            ("MAL-207", "DarkGate", &["DarkGate Loader"], 2018),
            ("MAL-208", "PrivateLoader", &["PrivateLoader.B"], 2021),
            ("MAL-209", "DBatLoader", &["ModiLoader"], 2020),
            ("MAL-210", "IceSword", &["IceSword Rootkit"], 2006),
            ("MAL-211", "GraceWire", &["LuckCat"], 2020),
            ("MAL-212", "Bumblebee", &["BumbleBee Loader"], 2022),
            ("MAL-213", "NetsupRAT", &["Netsup"], 2017),
            ("MAL-214", "Latrodectus", &["IceNova", "Unidentified"], 2023),
            ("MAL-215", "XLoader", &["MoqHao"], 2015),
        ];
        for (id, name, aliases, year) in loader_families {
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                MalwareCategory::Loader,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            f.add_ttp("T1055");
            f.tag("loader");
            db.add(f);
        }
    }

    fn add_rootkits(db: &mut Self) {
        let rootkit_families: &[(&str, &str, &[&str], u16)] = &[
            ("MAL-301", "BlackEnergy", &["BE2", "Sandworm"], 2007),
            ("MAL-302", "Winnti", &["PortReuse", "HIGHNOON"], 2010),
            ("MAL-303", "TDL4", &["Rovnix", "TDSS"], 2010),
            ("MAL-304", "Necurs", &["Necurs rootkit"], 2012),
            ("MAL-305", "Turla", &["Uroburos", "Snake"], 2014),
            ("MAL-306", "MosaicRegressor", &["VectorEDK"], 2020),
            ("MAL-307", "CosmicStrand", &["CosmicStrand UEFI"], 2022),
            ("MAL-308", "MoonBounce", &["Tianhe"], 2021),
            ("MAL-309", "FinFisher", &["FinSpy", "WingBird"], 2011),
            ("MAL-310", "Derusbi", &["Derusbi kernel"], 2008),
        ];
        for (id, name, aliases, year) in rootkit_families {
            let cat = if year >= &2020 {
                MalwareCategory::Bootkit
            } else {
                MalwareCategory::Rootkit
            };
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                cat,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            f.tag("rootkit");
            db.add(f);
        }
    }

    fn add_worms(db: &mut Self) {
        let worm_families: &[(&str, &str, &[&str], u16)] = &[
            ("MAL-401", "Conficker", &["Downadup", "Kido"], 2008),
            ("MAL-402", "Mirai", &["Mirai botnet"], 2016),
            ("MAL-403", "Mydoom", &["Novarg", "Mimail.R"], 2004),
            ("MAL-404", "Sality", &["Sality infector"], 2003),
            ("MAL-405", "Zeus", &["Zbot", "KINS"], 2007),
            ("MAL-406", "Necurs2", &["Necurs botnet"], 2012),
            ("MAL-407", "Mirai2", &["Reaper", "IoT Reaper"], 2017),
            ("MAL-408", "Emotet2", &["Emotet botnet"], 2014),
            ("MAL-409", "Phorpiex", &["Trik"], 2016),
            ("MAL-410", "Qakbot2", &["Qbot botnet"], 2008),
        ];
        for (id, name, aliases, year) in worm_families {
            let cat = if name.contains("botnet") || id == &"MAL-402" || id == &"MAL-407" {
                MalwareCategory::Botnet
            } else {
                MalwareCategory::Worm
            };
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                cat,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            db.add(f);
        }
    }

    fn add_apt_implants(db: &mut Self) {
        let apt_families: &[(&str, &str, &[&str], u16, &str)] = &[
            (
                "MAL-501",
                "SUNBURST",
                &["Solarigate", "SolarWinds backdoor"],
                2020,
                "APT29",
            ),
            ("MAL-502", "SUNSPOT", &["StellarParticle"], 2020, "APT29"),
            ("MAL-503", "GoldMax", &["SUNSHUTTLE"], 2021, "APT29"),
            ("MAL-504", "PlugX", &["Korplug", "SOGU"], 2012, "APT41"),
            ("MAL-505", "Winnti2", &["PoisonIvy variant"], 2010, "APT41"),
            ("MAL-506", "Poison Ivy", &["PIVY"], 2005, "APT10"),
            (
                "MAL-507",
                "CHOPSTICK",
                &["X-Agent", "Sofacy"],
                2007,
                "APT28",
            ),
            ("MAL-508", "CORESHELL", &["Gamefish v2"], 2016, "APT28"),
            ("MAL-509", "TURNEDUP", &["Derusbi variant"], 2013, "APT5"),
            ("MAL-510", "LOWBALL", &["Backdoor.LowBall"], 2015, "APT3"),
            ("MAL-511", "Regin", &["Regin platform"], 2014, "FIVEYES"),
            (
                "MAL-512",
                "Duqu",
                &["Duqu2", "Stuxnet derivative"],
                2011,
                "Equation",
            ),
            ("MAL-513", "Stuxnet", &["Stuxnet worm"], 2010, "Equation"),
            ("MAL-514", "TRITON", &["TRISIS", "HatMan"], 2017, "Sandworm"),
            (
                "MAL-515",
                "Industroyer",
                &["Crashoverride"],
                2016,
                "Sandworm",
            ),
        ];
        for (id, name, aliases, year, actor) in apt_families {
            let mut f = MalwareFamily::new(
                id.to_string(),
                name.to_string(),
                MalwareCategory::Implant,
                &["Windows"],
                *year,
            );
            for a in *aliases {
                f.add_alias(*a);
            }
            f.attributed_actors.push(actor.to_string());
            f.add_ttp("T1055");
            f.add_ttp("T1071.001");
            f.tag("apt");
            db.add(f);
        }
    }

    fn add_relationships(db: &mut Self) {
        db.add_relationship(FamilyRelationship::new(
            "MAL-001",
            "MAL-002",
            RelationshipType::CampaignBuddy,
            70,
        ));
        db.add_relationship(FamilyRelationship::new(
            "MAL-003",
            "MAL-006",
            RelationshipType::Successor,
            80,
        ));
        db.add_relationship(FamilyRelationship::new(
            "MAL-004",
            "MAL-007",
            RelationshipType::Variant,
            65,
        ));
        db.add_relationship(FamilyRelationship::new(
            "MAL-109",
            "MAL-201",
            RelationshipType::LoadedBy,
            90,
        ));
        db.add_relationship(FamilyRelationship::new(
            "MAL-110",
            "MAL-201",
            RelationshipType::LoadedBy,
            85,
        ));
    }

    fn add_timelines(db: &mut Self) {
        let mut tl = FamilyTimeline::new("MAL-001");
        tl.add_event(
            2017,
            FamilyEventType::FirstAppearance,
            "WannaCry global outbreak May 2017",
        );
        tl.add_event(
            2017,
            FamilyEventType::DisruptionOperation,
            "Kill-switch domain registered",
        );
        db.timelines.insert("MAL-001".into(), tl);

        let mut tl2 = FamilyTimeline::new("MAL-004");
        tl2.add_event(
            2019,
            FamilyEventType::FirstAppearance,
            "LockBit 1.0 first observed",
        );
        tl2.add_event(
            2021,
            FamilyEventType::MajorVersion,
            "LockBit 2.0 with StealBit",
        );
        tl2.add_event(
            2022,
            FamilyEventType::MajorVersion,
            "LockBit 3.0 / LockBit Black",
        );
        db.timelines.insert("MAL-004".into(), tl2);
    }
}

impl Default for FamilyDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> FamilyDatabase {
        FamilyDatabase::build()
    }

    // MalwareFamily
    #[test]
    fn test_family_new() {
        let f = MalwareFamily::new("M1", "Test", MalwareCategory::Trojan, &["Windows"], 2020);
        assert_eq!(f.id, "M1");
        assert_eq!(f.platform, vec!["Windows"]);
    }
    #[test]
    fn test_family_matches_alias() {
        let mut f = MalwareFamily::new(
            "M1",
            "WannaCry",
            MalwareCategory::Ransomware,
            &["Windows"],
            2017,
        );
        f.add_alias("WCry");
        assert!(f.matches_alias("wcry"));
        assert!(f.matches_alias("wannacry"));
        assert!(!f.matches_alias("lockbit"));
    }
    #[test]
    fn test_family_has_ttp() {
        let mut f = MalwareFamily::new(
            "M1",
            "Test",
            MalwareCategory::Ransomware,
            &["Windows"],
            2020,
        );
        f.add_ttp("T1486");
        assert!(f.has_ttp("T1486"));
        assert!(!f.has_ttp("T1055"));
    }
    #[test]
    fn test_family_category_display() {
        assert_eq!(MalwareCategory::Ransomware.to_string(), "ransomware");
    }
    #[test]
    fn test_family_category_other() {
        assert_eq!(
            MalwareCategory::Other("custom".into()).to_string(),
            "custom"
        );
    }

    // FamilyDatabase
    #[test]
    fn test_db_build_100_plus() {
        let d = db();
        assert!(d.len() >= 100, "count={}", d.len());
    }
    #[test]
    fn test_db_get_wannacry() {
        let d = db();
        assert!(d.get("MAL-001").is_some());
        assert_eq!(d.get("MAL-001").unwrap().name, "WannaCry");
    }
    #[test]
    fn test_db_get_none() {
        let d = db();
        assert!(d.get("NOT-EXIST").is_none());
    }
    #[test]
    fn test_db_search_ransomware() {
        let d = db();
        let results = d.search("wannacry");
        assert!(!results.is_empty());
    }
    #[test]
    fn test_db_by_category_ransomware() {
        let d = db();
        let rw = d.by_category(&MalwareCategory::Ransomware);
        assert!(rw.len() >= 20);
    }
    #[test]
    fn test_db_by_actor() {
        let d = db();
        let results = d.by_actor("APT29");
        assert!(!results.is_empty());
    }
    #[test]
    fn test_db_relationships() {
        let d = db();
        assert!(!d.relationships.is_empty());
    }
    #[test]
    fn test_db_relationships_for() {
        let d = db();
        let rels = d.relationships_for("MAL-001");
        assert!(!rels.is_empty());
    }

    // FamilyRelationship
    #[test]
    fn test_relationship_new() {
        let r = FamilyRelationship::new("A", "B", RelationshipType::Variant, 80);
        assert_eq!(r.confidence, 80);
    }
    #[test]
    fn test_relationship_type_display() {
        assert_eq!(RelationshipType::Variant.to_string(), "variant");
    }

    // FamilyTimeline
    #[test]
    fn test_timeline_add_event() {
        let mut tl = FamilyTimeline::new("M1");
        tl.add_event(2017, FamilyEventType::FirstAppearance, "first seen");
        assert_eq!(tl.events.len(), 1);
    }
    #[test]
    fn test_timeline_in_range() {
        let d = db();
        let tl = d.timelines.get("MAL-001").unwrap();
        let events = tl.in_range(2017, 2017);
        assert!(!events.is_empty());
    }
    #[test]
    fn test_timeline_is_active() {
        let tl = FamilyTimeline::new("M1");
        assert!(tl.is_active());
    }
    #[test]
    fn test_timeline_retired() {
        let mut tl = FamilyTimeline::new("M1");
        tl.add_event(2020, FamilyEventType::Retirement, "retired");
        assert!(!tl.is_active());
    }
    #[test]
    fn test_event_type_display() {
        assert_eq!(
            FamilyEventType::FirstAppearance.to_string(),
            "first_appearance"
        );
    }

    // FamilyTtp
    #[test]
    fn test_ttp_new() {
        let t = FamilyTtp::new("MAL-001", "T1486", "impact", 90);
        assert_eq!(t.family_id, "MAL-001");
        assert_eq!(t.technique_id, "T1486");
    }
    #[test]
    fn test_ttp_confidence_capped() {
        let t = FamilyTtp::new("M1", "T1", "impact", 200);
        assert_eq!(t.confidence, 100);
    }

    // FamilySearch
    #[test]
    fn test_search_by_name() {
        let d = db();
        let results = FamilySearch::search("cobalt", &d.families);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_search_by_alias() {
        let d = db();
        let results = FamilySearch::search("WCry", &d.families);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_search_no_match() {
        let d = db();
        let results = FamilySearch::search("zzz_not_exist_zzz", &d.families);
        assert!(results.is_empty());
    }
    #[test]
    fn test_by_category_loader() {
        let d = db();
        let results = FamilySearch::by_category(&MalwareCategory::Loader, &d.families);
        assert!(results.len() >= 10);
    }
    #[test]
    fn test_by_platform() {
        let d = db();
        let results = FamilySearch::by_platform("windows", &d.families);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_by_ttp() {
        let d = db();
        let results = FamilySearch::by_ttp("T1486", &d.families);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_db_timelines_wannacry() {
        let d = db();
        assert!(d.timelines.contains_key("MAL-001"));
    }
    #[test]
    fn test_db_timelines_lockbit() {
        let d = db();
        let tl = d.timelines.get("MAL-004").unwrap();
        assert!(tl.events.len() >= 3);
    }
    #[test]
    fn test_apt_families_have_actor() {
        let d = db();
        let apt = d.get("MAL-501").unwrap();
        assert!(apt.attributed_actors.contains(&"APT29".to_string()));
    }
    #[test]
    fn test_family_is_active_default() {
        let f = MalwareFamily::new("M1", "Test", MalwareCategory::Trojan, &["Windows"], 2020);
        assert!(f.is_active);
    }
    #[test]
    fn test_db_implant_category() {
        let d = db();
        let results = d.by_category(&MalwareCategory::Implant);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_db_search_actor_via_search() {
        let d = db();
        let results = FamilySearch::by_actor("Sandworm", &d.families);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_relationship_loaded_by() {
        let d = db();
        let rels = d.relationships_for("MAL-109");
        assert!(
            rels.iter()
                .any(|r| r.relationship_type == RelationshipType::LoadedBy)
        );
    }
}
