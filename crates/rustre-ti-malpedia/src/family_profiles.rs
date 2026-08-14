//! Hardcoded malware family profile database with 50+ entries.
//!
//! Provides `FamilyDb` — an in-memory store of well-known malware families —
//! and `FamilyMatch` for alias resolution and scoring.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// FamilyRecord
// ---------------------------------------------------------------------------

/// Static profile for a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyRecord {
    /// Malpedia canonical name (e.g. `win.emotet`).
    pub canonical: String,
    /// Common human-readable name.
    pub display_name: String,
    /// Alternative names / aliases (all lowercase for matching).
    pub aliases: Vec<String>,
    /// Malware type string.
    pub malware_type: String,
    /// Target platform.
    pub platform: String,
    /// Country of suspected origin (ISO code).
    pub country: Option<String>,
    /// Brief description.
    pub description: String,
    /// ATT&CK technique IDs.
    pub attack_techniques: Vec<String>,
    /// Known associated threat actors.
    pub actors: Vec<String>,
}

impl FamilyRecord {
    /// Return `true` if `name` matches any alias (case-insensitive).
    #[must_use]
    pub fn matches_alias(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        self.display_name.to_lowercase() == n
            || self.canonical.to_lowercase() == n
            || self.aliases.iter().any(|a| a == &n)
    }
}

// ---------------------------------------------------------------------------
// FamilyMatch
// ---------------------------------------------------------------------------

/// Result of a family lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyMatch {
    /// The matched family record.
    pub record: FamilyRecord,
    /// How the match was found: "canonical", "display", or "alias:<alias>".
    pub match_reason: String,
    /// Match confidence [0, 100].
    pub confidence: u8,
}

impl FamilyMatch {
    #[must_use]
    fn from_canonical(record: FamilyRecord) -> Self {
        Self {
            record,
            match_reason: "canonical".to_string(),
            confidence: 100,
        }
    }

    #[must_use]
    fn from_alias(record: FamilyRecord, alias: &str) -> Self {
        Self {
            record,
            match_reason: format!("alias:{alias}"),
            confidence: 90,
        }
    }

    #[must_use]
    fn from_partial(record: FamilyRecord, query: &str) -> Self {
        Self {
            record,
            match_reason: format!("partial:{query}"),
            confidence: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// FamilyDb
// ---------------------------------------------------------------------------

/// In-memory database of 50+ hardcoded malware family profiles.
pub struct FamilyDb {
    /// canonical name → record.
    records: HashMap<String, FamilyRecord>,
    /// alias (lowercase) → canonical name.
    alias_index: HashMap<String, String>,
}

impl FamilyDb {
    /// Create an empty database.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            records: HashMap::new(),
            alias_index: HashMap::new(),
        }
    }

    /// Create and populate the database with all built-in families.
    #[must_use]
    pub fn new() -> Self {
        let mut db = Self::empty();
        db.populate();
        db
    }

    /// Insert a family record into the database.
    pub fn insert(&mut self, record: FamilyRecord) {
        // Build alias index.
        self.alias_index
            .insert(record.display_name.to_lowercase(), record.canonical.clone());
        self.alias_index
            .insert(record.canonical.to_lowercase(), record.canonical.clone());
        for alias in &record.aliases {
            self.alias_index
                .insert(alias.to_lowercase(), record.canonical.clone());
        }
        self.records.insert(record.canonical.clone(), record);
    }

    /// Exact lookup by canonical name.
    #[must_use]
    pub fn get(&self, canonical: &str) -> Option<&FamilyRecord> {
        self.records.get(canonical)
    }

    /// Lookup by any name (canonical, display, or alias).
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<FamilyMatch> {
        let n = name.to_lowercase();

        // Try alias index first (exact match).
        if let Some(canonical) = self.alias_index.get(&n)
            && let Some(record) = self.records.get(canonical) {
                let reason = if record.canonical.to_lowercase() == n {
                    return Some(FamilyMatch::from_canonical(record.clone()));
                } else {
                    n.clone()
                };
                return Some(FamilyMatch::from_alias(record.clone(), &reason));
            }

        // Partial name search.
        for record in self.records.values() {
            if record.canonical.to_lowercase().contains(&n)
                || record.display_name.to_lowercase().contains(&n)
                || record.aliases.iter().any(|a| a.contains(&n))
            {
                return Some(FamilyMatch::from_partial(record.clone(), name));
            }
        }
        None
    }

    /// Return all family records.
    #[must_use]
    pub fn all(&self) -> Vec<&FamilyRecord> {
        let mut v: Vec<&FamilyRecord> = self.records.values().collect();
        v.sort_by(|a, b| a.canonical.cmp(&b.canonical));
        v
    }

    /// Return families matching a malware type string.
    #[must_use]
    pub fn by_type(&self, malware_type: &str) -> Vec<&FamilyRecord> {
        let t = malware_type.to_lowercase();
        self.records
            .values()
            .filter(|r| r.malware_type.to_lowercase() == t)
            .collect()
    }

    /// Return families for a given platform.
    #[must_use]
    pub fn by_platform(&self, platform: &str) -> Vec<&FamilyRecord> {
        let p = platform.to_lowercase();
        self.records
            .values()
            .filter(|r| r.platform.to_lowercase() == p)
            .collect()
    }

    /// Return families attributed to a given actor.
    #[must_use]
    pub fn by_actor(&self, actor: &str) -> Vec<&FamilyRecord> {
        let a = actor.to_lowercase();
        self.records
            .values()
            .filter(|r| r.actors.iter().any(|ac| ac.to_lowercase() == a))
            .collect()
    }

    /// Total number of families.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    // ---- Population ----

    fn populate(&mut self) {
        self.populate_batch1();
        self.populate_batch2();
        self.populate_batch3();
        self.populate_batch4();
        self.populate_batch5();
        self.populate_batch6();
        self.populate_batch7();
        self.populate_batch8();
    }

    fn populate_batch1(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            // canonical, display, aliases, malware_type, platform, country, desc, techniques, actors
            (
                "win.mirai",
                "Mirai",
                &["mirai", "okiru", "satori"],
                "botnet",
                "linux",
                None,
                "IoT botnet spreading via Telnet/SSH brute force",
                &["T1078", "T1110"],
                &[],
            ),
            (
                "win.wannacry",
                "WannaCry",
                &["wannacrypt", "wcry", "wanacrypt0r"],
                "ransomware",
                "win",
                Some("KP"),
                "Ransomware worm exploiting MS17-010 EternalBlue",
                &["T1486", "T1210"],
                &["Lazarus"],
            ),
            (
                "win.trickbot",
                "TrickBot",
                &["trickbot", "trick", "anchor"],
                "trojan",
                "win",
                Some("RU"),
                "Modular banking trojan evolved into full malware delivery platform",
                &["T1071", "T1027"],
                &["Wizard Spider"],
            ),
            (
                "win.emotet",
                "Emotet",
                &["emotet", "heodo", "geodo", "feodo"],
                "trojan",
                "win",
                None,
                "Banking trojan evolved into a major loader/botnet",
                &["T1071", "T1027", "T1105"],
                &["Mummy Spider"],
            ),
            (
                "win.cobalt_strike",
                "Cobalt Strike",
                &["cobaltstrike", "beacon", "cs"],
                "tool",
                "win",
                Some("US"),
                "Commercial post-exploitation framework, widely abused",
                &["T1055", "T1071", "T1021"],
                &[],
            ),
            (
                "win.mimikatz",
                "Mimikatz",
                &["mimikatz", "sekurlsa", "wce"],
                "tool",
                "win",
                Some("FR"),
                "Credential extraction and pass-the-hash tool",
                &["T1003", "T1550"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch2(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.meterpreter",
                "Meterpreter",
                &["meterpreter", "msf payload"],
                "tool",
                "win",
                Some("US"),
                "Metasploit Framework in-memory payload",
                &["T1055", "T1059"],
                &[],
            ),
            (
                "win.njrat",
                "NjRAT",
                &["njrat", "bladabindi"],
                "rat",
                "win",
                Some("TN"),
                "Fully featured RAT popular in Middle East",
                &["T1021", "T1056"],
                &[],
            ),
            (
                "win.asyncrat",
                "AsyncRAT",
                &["asyncrat", "async-rat"],
                "rat",
                "win",
                None,
                "Open-source .NET RAT with encryption",
                &["T1021", "T1573"],
                &[],
            ),
            (
                "win.redline",
                "RedLine",
                &["redline", "redlinestealer"],
                "stealer",
                "win",
                None,
                "Commercial credential and crypto stealer",
                &["T1555", "T1552"],
                &[],
            ),
            (
                "win.raccoon",
                "Raccoon",
                &["raccoon", "raccoon stealer"],
                "stealer",
                "win",
                None,
                "MaaS credential stealer",
                &["T1555", "T1539"],
                &[],
            ),
            (
                "win.vidar",
                "Vidar",
                &["vidar", "vidar stealer"],
                "stealer",
                "win",
                Some("RU"),
                "Infostealer with Arkei lineage",
                &["T1555", "T1056"],
                &[],
            ),
            (
                "win.formbook",
                "Formbook",
                &["formbook", "form-book", "xloader"],
                "stealer",
                "win",
                None,
                "Form-grabbing stealer used in phishing campaigns",
                &["T1056", "T1005"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch3(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.agenttesla",
                "AgentTesla",
                &["agenttesla", "agent tesla"],
                "rat",
                "win",
                None,
                ".NET RAT and keylogger",
                &["T1056", "T1041"],
                &[],
            ),
            (
                "win.remcos",
                "Remcos",
                &["remcos", "remcosrat"],
                "rat",
                "win",
                None,
                "Commercial RAT frequently observed in phishing",
                &["T1021", "T1056", "T1113"],
                &[],
            ),
            (
                "win.lokibot",
                "LokiBot",
                &["lokibot", "loki-bot"],
                "stealer",
                "win",
                None,
                "Multi-function credential stealer / keylogger",
                &["T1056", "T1555"],
                &[],
            ),
            (
                "win.qakbot",
                "QakBot",
                &["qakbot", "qbot", "quakbot"],
                "trojan",
                "win",
                None,
                "Banking trojan with worm capabilities, loader",
                &["T1071", "T1566"],
                &["Black Basta"],
            ),
            (
                "win.icedid",
                "IcedID",
                &["icedid", "bokbot"],
                "trojan",
                "win",
                None,
                "Banking trojan with modular architecture",
                &["T1071", "T1055"],
                &[],
            ),
            (
                "win.bazarloader",
                "BazarLoader",
                &["bazarloader", "bazar", "team9"],
                "loader",
                "win",
                None,
                "Loader used by Conti/Wizard Spider",
                &["T1105", "T1027"],
                &["Wizard Spider"],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch4(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.dridex",
                "Dridex",
                &["dridex", "cridex", "bugat"],
                "trojan",
                "win",
                Some("RU"),
                "Banking trojan with P2P infrastructure",
                &["T1071", "T1027"],
                &["Indrik Spider"],
            ),
            (
                "win.ryuk",
                "Ryuk",
                &["ryuk"],
                "ransomware",
                "win",
                Some("RU"),
                "Ransomware targeting enterprise networks",
                &["T1486", "T1490"],
                &["Wizard Spider"],
            ),
            (
                "win.conti",
                "Conti",
                &["conti"],
                "ransomware",
                "win",
                Some("RU"),
                "RaaS operation with aggressive extortion model",
                &["T1486", "T1490", "T1078"],
                &["Wizard Spider"],
            ),
            (
                "win.lockbit",
                "LockBit",
                &["lockbit", "lockbit2", "lockbit3"],
                "ransomware",
                "win",
                None,
                "Prolific RaaS, LockBit 2.0/3.0 variants",
                &["T1486", "T1490", "T1021"],
                &["LockBit Group"],
            ),
            (
                "win.revil",
                "REvil",
                &["revil", "sodinokibi", "sodin"],
                "ransomware",
                "win",
                Some("RU"),
                "RaaS operation targeting high-value targets",
                &["T1486", "T1490"],
                &["Gold Southfield"],
            ),
            (
                "win.darkside",
                "DarkSide",
                &["darkside"],
                "ransomware",
                "win",
                Some("RU"),
                "RaaS targeting critical infrastructure",
                &["T1486", "T1490"],
                &[],
            ),
            (
                "win.blackcat",
                "BlackCat/ALPHV",
                &["blackcat", "alphv", "noberus"],
                "ransomware",
                "win",
                None,
                "Cross-platform Rust-based RaaS",
                &["T1486", "T1490", "T1078"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch5(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.x_agent",
                "X-Agent",
                &["x-agent", "sofacy", "sednit", "fancy bear"],
                "backdoor",
                "win",
                Some("RU"),
                "APT28 primary implant",
                &["T1071", "T1082", "T1113"],
                &["APT28"],
            ),
            (
                "win.turla",
                "Turla",
                &["turla", "snake", "uroboros", "carbon"],
                "backdoor",
                "win",
                Some("RU"),
                "Sophisticated APT29/Turla backdoor",
                &["T1071", "T1027", "T1070"],
                &["Turla"],
            ),
            (
                "win.cozycar",
                "CozyDuke",
                &["cozycar", "cozy bear", "apt29", "cozy duke"],
                "backdoor",
                "win",
                Some("RU"),
                "APT29 early-stage implant",
                &["T1071", "T1566"],
                &["APT29"],
            ),
            (
                "win.notpetya",
                "NotPetya",
                &["notpetya", "petrwrap"],
                "wiper",
                "win",
                Some("RU"),
                "Destructive wiper masquerading as ransomware",
                &["T1485", "T1210"],
                &["Sandworm"],
            ),
            (
                "win.petya",
                "Petya",
                &["petya", "goldeneye"],
                "ransomware",
                "win",
                Some("RU"),
                "MBR-overwriting ransomware family",
                &["T1486", "T1561"],
                &[],
            ),
            (
                "win.lazarus_rat",
                "Lazarus RAT",
                &["lazarusrat", "destover"],
                "backdoor",
                "win",
                Some("KP"),
                "North Korean Lazarus Group malware",
                &["T1071", "T1082"],
                &["Lazarus"],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch6(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.gh0strat",
                "Gh0st RAT",
                &["gh0strat", "ghost rat"],
                "rat",
                "win",
                Some("CN"),
                "Chinese-origin RAT used by multiple threat actors",
                &["T1021", "T1056", "T1113"],
                &[],
            ),
            (
                "win.poisonivy",
                "Poison Ivy",
                &["poisonivy", "poison ivy", "pivy"],
                "rat",
                "win",
                Some("CN"),
                "Classic Chinese APT RAT",
                &["T1021", "T1056"],
                &["APT1"],
            ),
            (
                "win.darkcomet",
                "DarkComet",
                &["darkcomet", "dark comet"],
                "rat",
                "win",
                None,
                "French-origin RAT widely used by low-tier actors",
                &["T1021", "T1056"],
                &[],
            ),
            (
                "win.njw0rm",
                "njW0rm",
                &["njw0rm", "nj worm"],
                "worm",
                "win",
                None,
                "VBScript worm with RAT capabilities",
                &["T1059", "T1021"],
                &[],
            ),
            (
                "win.quasar",
                "Quasar RAT",
                &["quasarrat", "quasar"],
                "rat",
                "win",
                None,
                "Open-source .NET RAT",
                &["T1021", "T1056"],
                &[],
            ),
            (
                "win.asyncstealer",
                "AsyncStealer",
                &["asyncstealer"],
                "stealer",
                "win",
                None,
                "Stealer derived from AsyncRAT framework",
                &["T1555"],
                &[],
            ),
            (
                "win.hawkeye",
                "HawkEye",
                &["hawkeye", "hawkeye keylogger"],
                "stealer",
                "win",
                None,
                "Commercially sold keylogger / stealer",
                &["T1056", "T1555"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch7(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.azorult",
                "AZORult",
                &["azorult", "azor"],
                "stealer",
                "win",
                Some("RU"),
                "Stealer targeting browser credentials and crypto",
                &["T1555", "T1056"],
                &[],
            ),
            (
                "win.netwire",
                "NetWire",
                &["netwire", "netwire rat"],
                "rat",
                "win",
                None,
                "Multi-platform RAT sold on underground forums",
                &["T1021", "T1056", "T1113"],
                &[],
            ),
            (
                "win.nanocore",
                "NanoCore",
                &["nanocore", "nano core", "nanocore rat"],
                "rat",
                "win",
                None,
                ".NET modular RAT",
                &["T1021", "T1056"],
                &[],
            ),
            (
                "android.spynote",
                "SpyNote",
                &["spynote", "spy note"],
                "rat",
                "android",
                None,
                "Android RAT with full phone access",
                &["T1430", "T1513"],
                &[],
            ),
            (
                "android.cerberus",
                "Cerberus",
                &["cerberus", "cerberus banking"],
                "banker",
                "android",
                None,
                "Android banking trojan with overlay attacks",
                &["T1417", "T1426"],
                &[],
            ),
            (
                "android.ginp",
                "Ginp",
                &["ginp"],
                "banker",
                "android",
                None,
                "Android banking trojan targeting European banks",
                &["T1417"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }

    fn populate_batch8(&mut self) {
        type E<'a> = (
            &'a str, &'a str, &'a [&'a str], &'a str, &'a str,
            Option<&'a str>, &'a str, &'a [&'a str], &'a [&'a str],
        );
        let entries: &[E<'_>] = &[
            (
                "win.equation_doublepulsar",
                "DoublePulsar",
                &["doublepulsar"],
                "tool",
                "win",
                Some("US"),
                "NSA-linked implant used in WannaCry and others",
                &["T1055", "T1210"],
                &["Equation Group"],
            ),
            (
                "win.industroyer",
                "Industroyer",
                &["industroyer", "crashoverride"],
                "wiper",
                "win",
                Some("RU"),
                "ICS-targeting malware behind 2016 Ukraine blackout",
                &["T1485", "T1542"],
                &["Sandworm"],
            ),
            (
                "win.stuxnet",
                "Stuxnet",
                &["stuxnet"],
                "worm",
                "win",
                Some("US"),
                "ICS-targeted worm targeting Siemens PLCs",
                &["T1059", "T1210"],
                &["Equation Group"],
            ),
            (
                "win.sunburst",
                "Sunburst",
                &["sunburst", "solorigate"],
                "backdoor",
                "win",
                Some("RU"),
                "Supply-chain backdoor in SolarWinds Orion",
                &["T1195", "T1071"],
                &["APT29"],
            ),
            (
                "win.blackenergy",
                "BlackEnergy",
                &["blackenergy", "seedivy"],
                "backdoor",
                "win",
                Some("RU"),
                "Plugin-based backdoor used in Ukraine attacks",
                &["T1071", "T1082"],
                &["Sandworm"],
            ),
            (
                "win.ursnif",
                "Ursnif",
                &["ursnif", "gozi", "isfb", "dreambot"],
                "trojan",
                "win",
                Some("RU"),
                "Banking trojan with code-sharing lineage",
                &["T1071", "T1056"],
                &[],
            ),
            (
                "win.zloader",
                "ZLoader",
                &["zloader", "zbot offspring"],
                "trojan",
                "win",
                None,
                "Zeus-derived banking trojan loader",
                &["T1071", "T1566"],
                &[],
            ),
        ];
        for &(canonical, display, aliases, mt, platform, country, desc, techniques, actors) in entries {
            self.insert(FamilyRecord {
                canonical: canonical.to_string(),
                display_name: display.to_string(),
                aliases: aliases.iter().map(|a| a.to_lowercase()).collect(),
                malware_type: mt.to_string(),
                platform: platform.to_string(),
                country: country.map(str::to_string),
                description: desc.to_string(),
                attack_techniques: techniques.iter().map(std::string::ToString::to_string).collect(),
                actors: actors.iter().map(std::string::ToString::to_string).collect(),
            });
        }
    }
}

impl Default for FamilyDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> FamilyDb {
        FamilyDb::new()
    }

    // ---- Size ----

    #[test]
    fn test_db_has_at_least_50_families() {
        assert!(db().len() >= 50);
    }

    #[test]
    fn test_db_not_empty() {
        assert!(!db().is_empty());
    }

    // ---- Exact canonical lookups ----

    #[test]
    fn test_lookup_emotet_canonical() {
        let m = db().lookup("win.emotet");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.emotet");
    }

    #[test]
    fn test_lookup_wannacry_canonical() {
        let m = db().lookup("win.wannacry");
        assert!(m.is_some());
    }

    #[test]
    fn test_lookup_cobalt_strike_canonical() {
        let m = db().lookup("win.cobalt_strike");
        assert!(m.is_some());
    }

    // ---- Alias lookups ----

    #[test]
    fn test_lookup_by_display_name() {
        let m = db().lookup("Emotet");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.emotet");
    }

    #[test]
    fn test_lookup_alias_heodo() {
        let m = db().lookup("heodo");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.emotet");
    }

    #[test]
    fn test_lookup_alias_wcry() {
        let m = db().lookup("wcry");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.wannacry");
    }

    #[test]
    fn test_lookup_alias_sodinokibi() {
        let m = db().lookup("sodinokibi");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.revil");
    }

    #[test]
    fn test_lookup_alias_cobaltstrike() {
        let m = db().lookup("cobaltstrike");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.cobalt_strike");
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let m = db().lookup("EMOTET");
        assert!(m.is_some());
    }

    // ---- Not found ----

    #[test]
    fn test_lookup_unknown_returns_none_or_partial() {
        // Should not match any family.
        let m = db().lookup("xyzzy_does_not_exist_12345");
        assert!(m.is_none());
    }

    // ---- get by canonical ----

    #[test]
    fn test_get_by_canonical() {
        let db = db();
        let r = db.get("win.mimikatz");
        assert!(r.is_some());
        assert_eq!(r.unwrap().display_name, "Mimikatz");
    }

    #[test]
    fn test_get_nonexistent() {
        assert!(db().get("win.doesnotexist").is_none());
    }

    // ---- by_type ----

    #[test]
    fn test_by_type_ransomware() {
        let d = db();
        let v = d.by_type("ransomware");
        assert!(!v.is_empty());
        assert!(v.iter().all(|r| r.malware_type == "ransomware"));
    }

    #[test]
    fn test_by_type_trojan() {
        let d = db();
        let v = d.by_type("trojan");
        assert!(!v.is_empty());
    }

    #[test]
    fn test_by_type_stealer() {
        let d = db();
        let v = d.by_type("stealer");
        assert!(!v.is_empty());
    }

    // ---- by_platform ----

    #[test]
    fn test_by_platform_win() {
        let d = db();
        let v = d.by_platform("win");
        assert!(!v.is_empty());
    }

    #[test]
    fn test_by_platform_android() {
        let d = db();
        let v = d.by_platform("android");
        assert!(!v.is_empty());
    }

    #[test]
    fn test_by_platform_linux() {
        let d = db();
        let v = d.by_platform("linux");
        assert!(!v.is_empty());
    }

    // ---- by_actor ----

    #[test]
    fn test_by_actor_lazarus() {
        let d = db();
        let v = d.by_actor("Lazarus");
        assert!(!v.is_empty());
    }

    #[test]
    fn test_by_actor_sandworm() {
        let d = db();
        let v = d.by_actor("Sandworm");
        assert!(!v.is_empty());
    }

    // ---- all ----

    #[test]
    fn test_all_sorted() {
        let d = db();
        let all = d.all();
        for w in all.windows(2) {
            assert!(w[0].canonical <= w[1].canonical);
        }
    }

    // ---- FamilyRecord::matches_alias ----

    #[test]
    fn test_family_record_matches_alias() {
        let db = db();
        let r = db.get("win.emotet").unwrap();
        assert!(r.matches_alias("Emotet"));
        assert!(r.matches_alias("heodo"));
        assert!(!r.matches_alias("TrickBot"));
    }

    // ---- FamilyMatch confidence ----

    #[test]
    fn test_canonical_match_confidence_100() {
        let m = db().lookup("win.emotet").unwrap();
        assert_eq!(m.confidence, 100);
    }

    #[test]
    fn test_alias_match_confidence_90() {
        let m = db().lookup("heodo").unwrap();
        assert_eq!(m.confidence, 90);
    }

    // ---- country filtering helper ----

    #[test]
    fn test_families_with_ru_country() {
        let db = db();
        
        assert!(db
            .all()
            .into_iter().any(|r| r.country.as_deref() == Some("RU")));
    }

    // ---- attack techniques ----

    #[test]
    fn test_families_with_t1486() {
        let db = db();
        
        assert!(db
            .all()
            .into_iter().any(|r| r.attack_techniques.iter().any(|t| t == "T1486")));
    }

    // ---- Multiple alias hits don't duplicate records ----

    #[test]
    fn test_no_duplicate_records_for_same_family() {
        let db = db();
        // Both "emotet" and "heodo" should resolve to the same canonical.
        let m1 = db.lookup("emotet").unwrap();
        let m2 = db.lookup("heodo").unwrap();
        assert_eq!(m1.record.canonical, m2.record.canonical);
    }

    // ---- Serde roundtrip ----

    #[test]
    fn test_family_record_serde() {
        let db = db();
        let r = db.get("win.emotet").unwrap().clone();
        let json = serde_json::to_string(&r).unwrap();
        let r2: FamilyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.canonical, "win.emotet");
        assert!(!r2.aliases.is_empty());
    }

    #[test]
    fn test_family_match_serde() {
        let m = db().lookup("win.trickbot").unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let m2: FamilyMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.record.canonical, "win.trickbot");
    }

    // ---- FamilyDb custom insert ----

    #[test]
    fn test_db_custom_insert() {
        let mut db = FamilyDb::empty();
        db.insert(FamilyRecord {
            canonical: "win.custom_test".to_string(),
            display_name: "CustomTest".to_string(),
            aliases: vec!["ct".to_string(), "custom".to_string()],
            malware_type: "trojan".to_string(),
            platform: "win".to_string(),
            country: None,
            description: "Custom test family".to_string(),
            attack_techniques: vec!["T1059".to_string()],
            actors: vec!["TestActor".to_string()],
        });
        assert_eq!(db.len(), 1);
        assert!(db.lookup("CustomTest").is_some());
        assert!(db.lookup("ct").is_some());
    }

    // ---- Alias lookup case-insensitivity ----

    #[test]
    fn test_lookup_all_aliases_case_insensitive() {
        let db = db();
        // WannaCry aliases.
        assert!(db.lookup("WannaCry").is_some());
        assert!(db.lookup("wannacry").is_some());
        assert!(db.lookup("WANNACRY").is_some());
        assert!(db.lookup("wcry").is_some());
    }

    // ---- by_type returns correct types ----

    #[test]
    fn test_by_type_returns_only_matching_type() {
        let db = db();
        let ransomware = db.by_type("ransomware");
        let trojans = db.by_type("trojan");
        assert!(!ransomware.is_empty());
        assert!(!trojans.is_empty());
        // No overlap — ransomware records should not appear in trojan list.
        for r in &ransomware {
            assert_eq!(r.malware_type, "ransomware");
        }
        for t in &trojans {
            assert_eq!(t.malware_type, "trojan");
        }
    }

    // ---- by_platform android has entries ----

    #[test]
    fn test_by_platform_android_specific() {
        let db = db();
        let android = db.by_platform("android");
        assert!(!android.is_empty());
        for r in &android {
            assert_eq!(r.platform, "android");
        }
    }

    // ---- FamilyRecord matches_alias both ways ----

    #[test]
    fn test_family_record_matches_alias_canonical() {
        let db = db();
        let r = db.get("win.wannacry").unwrap();
        assert!(r.matches_alias("win.wannacry"));
        assert!(r.matches_alias("WannaCry"));
        assert!(r.matches_alias("wcry"));
    }

    // ---- all() contains every inserted record ----

    #[test]
    fn test_all_contains_all_inserted() {
        let db = db();
        let all = db.all();
        // Every canonical name from all() should also be retrievable via get().
        for record in &all {
            assert!(db.get(&record.canonical).is_some());
        }
    }

    // ---- actors list ----

    #[test]
    fn test_actor_list_not_empty_for_apt28() {
        let db = db();
        let r = db.get("win.x_agent").unwrap();
        assert!(r.actors.contains(&"APT28".to_string()));
    }

    // ---- lookup partial match ----

    #[test]
    fn test_lookup_partial_match() {
        let db = db();
        // "lockbit" should match win.lockbit (if the partial search hits).
        let m = db.lookup("lockbit");
        assert!(m.is_some());
    }

    // ---- by_actor case sensitivity ----

    #[test]
    fn test_by_actor_case_insensitive() {
        let db = db();
        let lower = db.by_actor("lazarus");
        let upper = db.by_actor("LAZARUS");
        let title = db.by_actor("Lazarus");
        assert_eq!(lower.len(), upper.len());
        assert_eq!(lower.len(), title.len());
    }

    // ---- FamilyDb empty() is truly empty ----

    #[test]
    fn test_empty_db_is_empty() {
        let db = FamilyDb::empty();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.all().is_empty());
    }

    // ---- FamilyMatch match_reason ----

    #[test]
    fn test_match_reason_canonical() {
        let m = db().lookup("win.emotet").unwrap();
        assert_eq!(m.match_reason, "canonical");
    }

    // ---- Multiple aliases for same family ----

    #[test]
    fn test_revil_aliases() {
        let db = db();
        let r1 = db.lookup("revil").unwrap();
        let r2 = db.lookup("sodinokibi").unwrap();
        let r3 = db.lookup("sodin").unwrap();
        assert_eq!(r1.record.canonical, r2.record.canonical);
        assert_eq!(r2.record.canonical, r3.record.canonical);
    }

    // ---- Default trait ----

    #[test]
    fn test_db_default_populated() {
        let db = FamilyDb::default();
        assert!(db.len() >= 50);
    }

    // ---- lookup IcedID / BokBot ----

    #[test]
    fn test_lookup_bokbot() {
        let db = db();
        let m = db.lookup("bokbot");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.icedid");
    }

    // ---- lookup BazarLoader aliases ----

    #[test]
    fn test_lookup_bazar() {
        let db = db();
        let m = db.lookup("bazar");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.bazarloader");
    }

    // ---- lookup Dridex aliases ----

    #[test]
    fn test_lookup_dridex_aliases() {
        let db = db();
        assert!(db.lookup("cridex").is_some());
        assert!(db.lookup("bugat").is_some());
        assert!(db.lookup("dridex").is_some());
    }

    // ---- lookup BlackEnergy ----

    #[test]
    fn test_lookup_blackenergy() {
        let db = db();
        assert!(db.lookup("blackenergy").is_some());
    }

    // ---- lookup Stuxnet ----

    #[test]
    fn test_lookup_stuxnet() {
        let db = db();
        let m = db.lookup("stuxnet");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.stuxnet");
    }

    // ---- lookup Sunburst / Solorigate ----

    #[test]
    fn test_lookup_sunburst_aliases() {
        let db = db();
        assert!(db.lookup("sunburst").is_some());
        assert!(db.lookup("solorigate").is_some());
    }

    // ---- by_type tool ----

    #[test]
    fn test_by_type_tool() {
        let db = db();
        let tools = db.by_type("tool");
        assert!(!tools.is_empty());
        // Mimikatz and CobaltStrike are tools.
        let names: Vec<&str> = tools.iter().map(|r| r.canonical.as_str()).collect();
        assert!(names.contains(&"win.mimikatz") || names.contains(&"win.cobalt_strike"));
    }

    // ---- by_type wiper ----

    #[test]
    fn test_by_type_wiper() {
        let db = db();
        let wipers = db.by_type("wiper");
        assert!(!wipers.is_empty());
        let canonical_names: Vec<&str> = wipers.iter().map(|r| r.canonical.as_str()).collect();
        assert!(
            canonical_names.contains(&"win.notpetya")
                || canonical_names.contains(&"win.industroyer")
        );
    }

    // ---- attack_technique T1486 present in ransomware families ----

    #[test]
    fn test_ransomware_families_have_t1486() {
        let db = db();
        let ransomware = db.by_type("ransomware");
        // Most ransomware should have T1486 (data encrypted for impact).
        let count_with_t1486 = ransomware
            .iter()
            .filter(|r| r.attack_techniques.iter().any(|t| t == "T1486"))
            .count();
        assert!(count_with_t1486 > 0);
    }

    // ---- lookup Ursnif / ISFB / Gozi ----

    #[test]
    fn test_lookup_ursnif_aliases() {
        let db = db();
        assert!(db.lookup("ursnif").is_some());
        assert!(db.lookup("gozi").is_some());
        assert!(db.lookup("isfb").is_some());
    }

    // ---- FamilyDb insert then get ----

    #[test]
    fn test_db_insert_then_get() {
        let mut db = FamilyDb::empty();
        db.insert(FamilyRecord {
            canonical: "win.test_malware".to_string(),
            display_name: "TestMalware".to_string(),
            aliases: vec!["tm".to_string()],
            malware_type: "backdoor".to_string(),
            platform: "win".to_string(),
            country: Some("US".to_string()),
            description: "Test backdoor for unit testing".to_string(),
            attack_techniques: vec!["T1059".to_string(), "T1071".to_string()],
            actors: vec!["TestActor".to_string()],
        });
        let r = db.get("win.test_malware").unwrap();
        assert_eq!(r.display_name, "TestMalware");
        assert_eq!(r.country.as_deref(), Some("US"));
        assert!(db.lookup("tm").is_some());
        assert_eq!(db.by_actor("TestActor").len(), 1);
    }

    // ---- FamilyRecord attack_techniques ----

    #[test]
    fn test_stuxnet_attack_techniques() {
        let db = db();
        let r = db.get("win.stuxnet").unwrap();
        assert!(!r.attack_techniques.is_empty());
    }

    // ---- all families serialise without panic ----

    #[test]
    fn test_all_families_serialise() {
        let db = db();
        for record in db.all() {
            let _ = serde_json::to_string(record).unwrap();
        }
    }

    // ---- KP-attributed families ----

    #[test]
    fn test_kp_families() {
        let db = db();
        
        assert!(db
            .all()
            .into_iter().any(|r| r.country.as_deref() == Some("KP")));
    }

    // ---- Wipers distinct from ransomware ----

    #[test]
    fn test_wipers_found_in_db() {
        let db = db();
        
        assert!(db
            .all()
            .into_iter().any(|r| r.malware_type == "wiper"));
    }

    // ---- FamilyRecord clone ----

    #[test]
    fn test_family_record_clone() {
        let db = db();
        let r = db.get("win.emotet").unwrap().clone();
        assert_eq!(r.canonical, "win.emotet");
    }

    // ---- FamilyMatch confidence for display name match ----

    #[test]
    fn test_display_name_match_confidence() {
        let m = db().lookup("WannaCry").unwrap();
        // Display name match should have high confidence.
        assert!(m.confidence >= 90);
    }

    // ---- lookup for mirai (linux platform) ----

    #[test]
    fn test_lookup_mirai() {
        let db = db();
        let m = db.lookup("mirai");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.platform, "linux");
    }

    // ---- lookup QakBot / QBot ----

    #[test]
    fn test_lookup_qakbot_aliases() {
        let db = db();
        assert!(db.lookup("qakbot").is_some());
        assert!(db.lookup("qbot").is_some());
        assert!(db.lookup("quakbot").is_some());
    }

    // ---- lookup Gh0st RAT ----

    #[test]
    fn test_lookup_gh0strat() {
        assert!(db().lookup("gh0strat").is_some());
    }

    // ---- lookup DarkComet ----

    #[test]
    fn test_lookup_darkcomet() {
        assert!(db().lookup("darkcomet").is_some());
    }

    // ---- FamilyDb by_actor APT1 ----

    #[test]
    fn test_by_actor_apt1() {
        let db = db();
        let families = db.by_actor("APT1");
        assert!(!families.is_empty());
    }

    // ---- lookup AgentTesla aliases ----

    #[test]
    fn test_lookup_agenttesla() {
        let db = db();
        assert!(db.lookup("agent tesla").is_some());
        assert!(db.lookup("agenttesla").is_some());
    }

    // ---- lookup Formbook / XLoader ----

    #[test]
    fn test_lookup_formbook_xloader() {
        let db = db();
        assert!(db.lookup("formbook").is_some());
        assert!(db.lookup("xloader").is_some());
    }

    // ---- lookup NetWire ----

    #[test]
    fn test_lookup_netwire() {
        assert!(db().lookup("netwire").is_some());
    }

    // ---- lookup NanoCore ----

    #[test]
    fn test_lookup_nanocore() {
        let db = db();
        assert!(db.lookup("nanocore").is_some());
        assert!(db.lookup("nano core").is_some());
    }

    // ---- lookup Cerberus (android banker) ----

    #[test]
    fn test_lookup_cerberus() {
        let db = db();
        let m = db.lookup("cerberus");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.platform, "android");
    }

    // ---- lookup SpyNote (android rat) ----

    #[test]
    fn test_lookup_spynote() {
        let db = db();
        let m = db.lookup("spynote");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.malware_type, "rat");
    }

    // ---- lookup DoublePulsar ----

    #[test]
    fn test_lookup_doublepulsar() {
        let db = db();
        let m = db.lookup("doublepulsar");
        assert!(m.is_some());
        assert_eq!(m.unwrap().record.canonical, "win.equation_doublepulsar");
    }

    // ---- lookup Industroyer ----

    #[test]
    fn test_lookup_industroyer() {
        let db = db();
        assert!(db.lookup("industroyer").is_some());
        assert!(db.lookup("crashoverride").is_some());
    }

    // ---- FamilyDb len matches all() len ----

    #[test]
    fn test_db_len_matches_all_len() {
        let db = db();
        assert_eq!(db.len(), db.all().len());
    }
}
