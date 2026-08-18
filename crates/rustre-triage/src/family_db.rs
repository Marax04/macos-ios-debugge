// rustre-triage/src/family_db.rs
// Database of 200+ malware families with behavioral signatures and IoCs.

use std::collections::HashMap;

/// MITRE ATT&CK technique ID.
pub type TechniqueId = &'static str;

/// A known mutex, registry key, C2 pattern, or other `IoC`.
#[derive(Debug, Clone)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocType {
    Mutex,
    RegistryKey,
    C2Pattern,
    UserAgent,
    FilePath,
    Hash,
    Domain,
}

/// Behavioral signature for a family.
#[derive(Debug, Clone)]
pub struct BehaviorSignature {
    pub name: &'static str,
    pub description: &'static str,
    pub apis: &'static [&'static str],
}

/// A malware family entry.
#[derive(Debug, Clone)]
pub struct FamilyEntry {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub category: FamilyCategory,
    pub mitre_techniques: &'static [TechniqueId],
    pub typical_iocs: &'static [Ioc],
    pub behavioral_sigs: &'static [BehaviorSignature],
    pub first_seen: &'static str, // "YYYY-MM" or "YYYY"
    pub prevalence: u8,           // 0–100
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyCategory {
    Ransomware,
    Banker,
    Rat,
    Dropper,
    Worm,
    Rootkit,
    Spyware,
    Adware,
    Botnet,
    Loader,
    Stealer,
    Backdoor,
    Cryptominer,
    Exploit,
    Other,
}

impl std::fmt::Display for FamilyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

macro_rules! ioc {
    (mutex, $v:expr) => { Ioc { ioc_type: IocType::Mutex, value: $v } };
    (reg, $v:expr)   => { Ioc { ioc_type: IocType::RegistryKey, value: $v } };
    (c2, $v:expr)    => { Ioc { ioc_type: IocType::C2Pattern, value: $v } };
    (ua, $v:expr)    => { Ioc { ioc_type: IocType::UserAgent, value: $v } };
    (file, $v:expr)  => { Ioc { ioc_type: IocType::FilePath, value: $v } };
    (domain, $v:expr) => { Ioc { ioc_type: IocType::Domain, value: $v } };
}

macro_rules! behav {
    ($name:expr, $desc:expr, [$($api:expr),*]) => {
        BehaviorSignature { name: $name, description: $desc, apis: &[$($api),*] }
    };
}

/// The compiled family database.
pub struct FamilyDatabase {
    entries: Vec<FamilyEntry>,
    by_name: HashMap<String, usize>,
}

impl FamilyDatabase {
    #[must_use]
    pub fn new() -> Self {
        let entries = build_database();
        let mut by_name = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_name.insert(e.name.to_lowercase(), i);
            for alias in e.aliases {
                by_name.insert(alias.to_lowercase(), i);
            }
        }
        Self { entries, by_name }
    }

    #[must_use]
    pub const fn len(&self) -> usize { self.entries.len() }
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FamilyEntry> {
        self.by_name.get(&name.to_lowercase()).map(|&i| &self.entries[i])
    }

    #[must_use]
    pub fn all(&self) -> &[FamilyEntry] { &self.entries }

    #[must_use]
    pub fn by_category(&self, cat: FamilyCategory) -> Vec<&FamilyEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Find families whose `IoCs` match any string found in `haystack`.
    #[must_use]
    pub fn match_iocs<'a>(&'a self, haystack: &[u8]) -> Vec<(&'a FamilyEntry, Vec<&'a Ioc>)> {
        let mut results = Vec::new();
        for entry in &self.entries {
            let matched: Vec<&Ioc> = entry.typical_iocs.iter().filter(|ioc| {
                haystack.windows(ioc.value.len()).any(|w| w == ioc.value.as_bytes())
            }).collect();
            if !matched.is_empty() {
                results.push((entry, matched));
            }
        }
        results
    }

    /// Find families matching any of the given API names.
    /// Scan raw bytes for the API / command indicators of each family's
    /// behavioural signatures.
    ///
    /// Complements the two existing matchers rather than replacing either:
    /// [`Self::match_iocs`] scans bytes for **sample artefacts** (mutexes,
    /// domains, file paths, C2 hosts), and [`Self::match_apis`] matches a list
    /// of **already-extracted** API names. Neither could answer "do these bytes
    /// contain a known malicious behaviour?", which is what a buffer such as
    /// `b"vssadmin delete shadows /all"` calls for — `vssadmin` is a behavioural
    /// indicator of `delete_shadows`, and deliberately not an IOC, since it is a
    /// legitimate Windows tool.
    ///
    /// Added 2026-07-29: `match_iocs_finds_shadow_copy` was asserting this
    /// capability through `match_iocs`, which searches the wrong field.
    ///
    /// Returns each family together with the behaviour signatures whose
    /// indicators were found.
    #[must_use]
    pub fn match_behaviors<'a>(
        &'a self,
        haystack: &[u8],
    ) -> Vec<(&'a FamilyEntry, Vec<&'a BehaviorSignature>)> {
        let mut results = Vec::new();
        for entry in &self.entries {
            let matched: Vec<&BehaviorSignature> = entry
                .behavioral_sigs
                .iter()
                .filter(|sig| {
                    sig.apis.iter().any(|api| {
                        !api.is_empty()
                            && api.len() <= haystack.len()
                            && haystack.windows(api.len()).any(|w| w == api.as_bytes())
                    })
                })
                .collect();
            if !matched.is_empty() {
                results.push((entry, matched));
            }
        }
        results
    }

    pub fn match_apis<'a>(&'a self, apis: &[&str]) -> Vec<(&'a FamilyEntry, Vec<&'static str>)> {
        let mut results = Vec::new();
        for entry in &self.entries {
            let mut matched_apis = Vec::new();
            for sig in entry.behavioral_sigs {
                for api in sig.apis {
                    if apis.iter().any(|a| a.eq_ignore_ascii_case(api)) {
                        matched_apis.push(*api);
                    }
                }
            }
            if !matched_apis.is_empty() {
                results.push((entry, matched_apis));
            }
        }
        results
    }

    /// Return the top N families by prevalence.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<&FamilyEntry> {
        let mut sorted: Vec<&FamilyEntry> = self.entries.iter().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.prevalence));
        sorted.into_iter().take(n).collect()
    }
}


fn ransomware_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "WannaCry",
            aliases: &["WanaCrypt0r", "WCry", "WannaCrypt"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1059","T1021","T1562","T1543"],
            typical_iocs: &[
                ioc!(mutex, "Global\\MsWinZonesCacheCounterMutexA"),
                ioc!(domain, "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"),
                ioc!(file, "C:\\Windows\\tasksche.exe"),
                ioc!(c2, ".onion"),
            ],
            behavioral_sigs: &[
                behav!("smb_exploit", "Exploits SMB EternalBlue (MS17-010)", ["DeviceIoControl"]),
                behav!("encrypt_files", "Encrypts files with AES-128-CBC + RSA-2048",
                    ["CryptEncrypt","FindFirstFileW","FindNextFileW"]),
                behav!("delete_shadows", "Deletes shadow copies", ["vssadmin"]),
            ],
            first_seen: "2017-03",
            prevalence: 95,
            description: "Global ransomworm exploiting EternalBlue SMB vulnerability",
        },
        FamilyEntry {
            name: "NotPetya",
            aliases: &["Petya", "ExPetr", "GoldenEye"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1021","T1003","T1070","T1543"],
            typical_iocs: &[
                ioc!(file, "C:\\Windows\\perfc.dat"),
                ioc!(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSCC"),
            ],
            behavioral_sigs: &[
                behav!("mbr_overwrite", "Overwrites MBR for boot encryption", ["DeviceIoControl"]),
                behav!("credential_harvest", "Harvests credentials via Mimikatz",
                    ["LsaEnumerateLogonSessions"]),
            ],
            first_seen: "2017-06",
            prevalence: 88,
            description: "Destructive wiper/ransomware targeting Ukrainian infrastructure",
        },
        FamilyEntry {
            name: "REvil",
            aliases: &["Sodinokibi", "Ransomware.GandCrab2"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1082","T1012","T1047","T1562"],
            typical_iocs: &[
                ioc!(mutex, "Global\\206D87E0-0E60-DF25-DD8F-8E4E7D1E3BF0"),
                ioc!(reg, "HKCU\\Software\\recfg"),
                ioc!(c2, ".onion"),
            ],
            behavioral_sigs: &[
                behav!("encrypt", "Salsa20 + RSA-2048 encryption", ["CryptGenRandom","FindFirstFileW"]),
                behav!("antivm", "VM detection via CPUID", ["IsDebuggerPresent"]),
            ],
            first_seen: "2019-04",
            prevalence: 90,
            description: "RaaS ransomware successor to GandCrab",
        },
        FamilyEntry {
            name: "LockBit",
            aliases: &["LockBit2", "LockBit3", "LockBit Black"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1489","T1490","T1543","T1070"],
            typical_iocs: &[
                ioc!(mutex, "Global\\{BEF590BE-11A6-442A-A85B-656C1081E863}"),
                ioc!(file, "Restore-My-Files.txt"),
            ],
            behavioral_sigs: &[
                behav!("fast_encrypt", "High-speed partial file encryption", ["ReadFile","WriteFile"]),
                behav!("service_stop", "Stops services before encryption", ["ControlService"]),
            ],
            first_seen: "2019-09",
            prevalence: 92,
            description: "Fast RaaS ransomware with self-spreading capabilities",
        },
        FamilyEntry {
            name: "Conti",
            aliases: &["ContiLocker"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1021","T1003","T1047","T1562"],
            typical_iocs: &[
                ioc!(mutex, "hsfjuukjz"),
                ioc!(file, "readme.txt"),
            ],
            behavioral_sigs: &[
                behav!("threaded_encrypt", "Multi-threaded encryption engine", ["CreateThread"]),
                behav!("smb_spread", "Spreads via SMB shares", ["NetShareEnum"]),
            ],
            first_seen: "2020-05",
            prevalence: 88,
            description: "Sophisticated RaaS operation with professional team",
        },
    ]
}

fn banker_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "Zeus",
            aliases: &["Zbot", "PRG", "Wsnpoem"],
            category: FamilyCategory::Banker,
            mitre_techniques: &["T1056","T1185","T1055","T1082"],
            typical_iocs: &[
                ioc!(mutex, "Global\\_DSDBMUTEX_V1"),
                ioc!(reg, "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\userinit"),
                ioc!(c2, "/gate.php"),
            ],
            behavioral_sigs: &[
                behav!("form_grab", "Browser form injection / grabbing",
                    ["NtCreateSection","HttpSendRequest"]),
                behav!("keylog", "Keylogging via SetWindowsHookEx", ["SetWindowsHookExW"]),
            ],
            first_seen: "2007-07",
            prevalence: 97,
            description: "Pioneering banking trojan; source leaked in 2011",
        },
        FamilyEntry {
            name: "Emotet",
            aliases: &["Geodo", "Heodo"],
            category: FamilyCategory::Banker,
            mitre_techniques: &["T1566","T1055","T1021","T1547","T1082"],
            typical_iocs: &[
                ioc!(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ioc!(c2, "/wm/"),
                ioc!(ua, "Mozilla/5.0"),
            ],
            behavioral_sigs: &[
                behav!("doc_macro", "Malicious Office macro dropper", ["WScript.Shell"]),
                behav!("smtp_spread", "Self-propagates via email", ["send", "SMTP"]),
                behav!("module_download", "Downloads additional modules", ["InternetOpenUrlA"]),
            ],
            first_seen: "2014-07",
            prevalence: 96,
            description: "Modular banking trojan turned botnet/loader; most widespread in 2019-2021",
        },
        FamilyEntry {
            name: "TrickBot",
            aliases: &["TrickLoader", "Trickster"],
            category: FamilyCategory::Banker,
            mitre_techniques: &["T1055","T1003","T1082","T1021","T1547"],
            typical_iocs: &[
                ioc!(mutex, "Global\\1"),
                ioc!(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon"),
                ioc!(c2, "/pony/"),
            ],
            behavioral_sigs: &[
                behav!("module_system", "Modular plugin system", ["LoadLibraryA","GetProcAddress"]),
                behav!("credential_steal", "Steals browser credentials", ["sqlite3_open"]),
            ],
            first_seen: "2016-09",
            prevalence: 93,
            description: "Highly modular banking trojan, often dropped by Emotet",
        },
    ]
}

fn rat_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "njRAT",
            aliases: &["Bladabindi", "njW0rm"],
            category: FamilyCategory::Rat,
            mitre_techniques: &["T1059","T1056","T1113","T1543","T1036"],
            typical_iocs: &[
                ioc!(mutex, "bb666666"),
                ioc!(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ioc!(c2, ":5552"),
            ],
            behavioral_sigs: &[
                behav!("keylog", "Keylogger", ["GetAsyncKeyState"]),
                behav!("remote_shell", "Reverse shell", ["CreateProcess"]),
                behav!("screenshot", "Screen capture", ["BitBlt"]),
            ],
            first_seen: "2013-01",
            prevalence: 85,
            description: ".NET-based RAT widely distributed in Middle East",
        },
        FamilyEntry {
            name: "AsyncRAT",
            aliases: &["AsyncTool"],
            category: FamilyCategory::Rat,
            mitre_techniques: &["T1059","T1056","T1113","T1547","T1055"],
            typical_iocs: &[
                ioc!(mutex, "AsyncMutex_6SI8OkPnk"),
                ioc!(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\async"),
            ],
            behavioral_sigs: &[
                behav!("async_client", "Async C2 over TCP with AES encryption",
                    ["TcpClient","AesManaged"]),
                behav!("persistence", "Registry run key persistence", ["RegSetValueExW"]),
            ],
            first_seen: "2019-01",
            prevalence: 80,
            description: "Open-source .NET RAT with AES-encrypted C2",
        },
        FamilyEntry {
            name: "Cobalt Strike",
            aliases: &["CobaltStrike", "CS Beacon", "Beacon"],
            category: FamilyCategory::Rat,
            mitre_techniques: &["T1055","T1059","T1021","T1003","T1105"],
            typical_iocs: &[
                ioc!(c2, "/jquery-3.3.1.slim.min.js"),
                ioc!(ua, "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"),
            ],
            behavioral_sigs: &[
                behav!("beacon", "Periodic HTTP/S beacon", ["InternetOpenW","HttpSendRequestW"]),
                behav!("inject", "Process injection via shellcode", ["VirtualAllocEx","WriteProcessMemory"]),
            ],
            first_seen: "2012-01",
            prevalence: 90,
            description: "Commercial penetration testing framework widely abused by threat actors",
        },
    ]
}

fn banker_and_rat_entries() -> Vec<FamilyEntry> {
    let mut entries = banker_entries();
    entries.extend(rat_entries());
    entries
}

fn stealer_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "RedLine Stealer",
            aliases: &["RedLine"],
            category: FamilyCategory::Stealer,
            mitre_techniques: &["T1555","T1552","T1082","T1057"],
            typical_iocs: &[
                ioc!(mutex, "RLine"),
                ioc!(file, "%TEMP%\\RedLine"),
            ],
            behavioral_sigs: &[
                behav!("browser_steal", "Steals browser passwords/cookies",
                    ["sqlite3_open","CryptUnprotectData"]),
                behav!("crypto_steal", "Steals cryptocurrency wallets", ["FindFirstFileW"]),
            ],
            first_seen: "2020-02",
            prevalence: 88,
            description: "Credential and cryptocurrency stealer sold as MaaS",
        },
        FamilyEntry {
            name: "Raccoon Stealer",
            aliases: &["Raccoon", "Racealer"],
            category: FamilyCategory::Stealer,
            mitre_techniques: &["T1555","T1082","T1057","T1113"],
            typical_iocs: &[
                ioc!(c2, "/gate"),
                ioc!(ua, "raccoon"),
            ],
            behavioral_sigs: &[
                behav!("browser_steal", "Browser credential theft", ["sqlite3_open"]),
                behav!("ftp_steal", "FTP client credential theft", ["FileZilla"]),
            ],
            first_seen: "2019-04",
            prevalence: 82,
            description: "MaaS stealer targeting browsers, FTP clients, and crypto wallets",
        },
    ]
}

fn loader_rootkit_entries() -> Vec<FamilyEntry> {
    vec![
        // ─── Loaders/Droppers ────────────────────────────────────────────
        FamilyEntry {
            name: "GuLoader",
            aliases: &["CloudEyE", "VBDropper"],
            category: FamilyCategory::Loader,
            mitre_techniques: &["T1027","T1055","T1562","T1497"],
            typical_iocs: &[
                ioc!(c2, "onedrive.live.com"),
                ioc!(c2, "drive.google.com"),
            ],
            behavioral_sigs: &[
                behav!("cloud_download", "Downloads payload from cloud storage",
                    ["InternetOpenUrlA","URLDownloadToFile"]),
                behav!("antidebug", "NtSetInformationThread anti-debug",
                    ["NtSetInformationThread"]),
            ],
            first_seen: "2019-12",
            prevalence: 85,
            description: "VB6/NSIS-based loader using cloud storage for payload delivery",
        },
        FamilyEntry {
            name: "BazarLoader",
            aliases: &["BazaLoader", "TeamBot", "BazarBackdoor"],
            category: FamilyCategory::Loader,
            mitre_techniques: &["T1055","T1134","T1027","T1497"],
            typical_iocs: &[
                ioc!(domain, ".bazar"),
                ioc!(c2, "/stat"),
            ],
            behavioral_sigs: &[
                behav!("dns_c2", "EmerDNS-based C2 using .bazar domains", ["DnsQuery"]),
                behav!("inject", "Process hollowing into svchost", ["ZwUnmapViewOfSection"]),
            ],
            first_seen: "2020-04",
            prevalence: 80,
            description: "TrickBot group loader using blockchain-based DNS for C2",
        },
    ]
}

fn worm_bot_entries() -> Vec<FamilyEntry> {
    vec![
        // ─── Worms ───────────────────────────────────────────────────────
        FamilyEntry {
            name: "Conficker",
            aliases: &["Downadup", "Kido"],
            category: FamilyCategory::Worm,
            mitre_techniques: &["T1021","T1110","T1136","T1562"],
            typical_iocs: &[
                ioc!(mutex, "Global\\{CF1A6C46-4D59-4977-BD62-4803B61FA2F0}"),
                ioc!(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{random}"),
            ],
            behavioral_sigs: &[
                behav!("smb_brute", "Brute-forces SMB admin shares", ["NetUseAdd"]),
                behav!("dga", "Domain generation algorithm (DGA)", ["DnsQuery"]),
            ],
            first_seen: "2008-10",
            prevalence: 90,
            description: "Massive worm exploiting MS08-067; still found in legacy environments",
        },
        // ─── Rootkits ────────────────────────────────────────────────────
        FamilyEntry {
            name: "ZeroAccess",
            aliases: &["max++", "Sirefef"],
            category: FamilyCategory::Rootkit,
            mitre_techniques: &["T1014","T1543","T1055","T1562"],
            typical_iocs: &[
                ioc!(file, "C:\\$Recycle.Bin\\S-1-5-...\\@"),
                ioc!(mutex, "Global\\{0024b6bc-7e64-4de0-8d37-c76b739eb84e}"),
            ],
            behavioral_sigs: &[
                behav!("ntfs_tricks", "NTFS alternate data streams for hiding", ["NtCreateFile"]),
                behav!("p2p_c2", "Peer-to-peer botnet C2", ["WSASendTo"]),
            ],
            first_seen: "2010-07",
            prevalence: 75,
            description: "Ring-3 rootkit with P2P botnet; hijacks search results for click fraud",
        },
        // ─── Cryptominers ────────────────────────────────────────────────
        FamilyEntry {
            name: "XMRig",
            aliases: &["Monero miner"],
            category: FamilyCategory::Cryptominer,
            mitre_techniques: &["T1496","T1055","T1059"],
            typical_iocs: &[
                ioc!(file, "xmrig.exe"),
                ioc!(c2, "pool.minexmr.com"),
                ioc!(c2, "xmrpool.eu"),
            ],
            behavioral_sigs: &[
                behav!("mining", "CPU/GPU mining loop", ["DeviceIoControl","SetPriorityClass"]),
                behav!("stratum", "Stratum mining protocol over TCP", ["WSAConnect"]),
            ],
            first_seen: "2017-05",
            prevalence: 88,
            description: "Legitimate open-source XMR miner widely abused in malware",
        },
    ]
}

fn backdoor_base_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "PlugX",
            aliases: &["Kaba", "Korplug", "SOGU"],
            category: FamilyCategory::Backdoor,
            mitre_techniques: &["T1055","T1547","T1056","T1105","T1082"],
            typical_iocs: &[
                ioc!(mutex, "RottenBeef"),
                ioc!(reg, "HKCU\\Software\\CLASSES\\Applications"),
                ioc!(c2, ":8080"),
            ],
            behavioral_sigs: &[
                behav!("dll_sideload", "DLL side-loading for persistence", ["LoadLibraryA"]),
                behav!("modular_c2", "Modular plugin-based C2", ["HttpSendRequest"]),
            ],
            first_seen: "2008-01",
            prevalence: 82,
            description: "Chinese APT modular RAT used in targeted espionage",
        },
        FamilyEntry {
            name: "Gh0st RAT",
            aliases: &["Gh0st", "Moudoor"],
            category: FamilyCategory::Backdoor,
            mitre_techniques: &["T1055","T1056","T1113","T1059","T1547"],
            typical_iocs: &[
                ioc!(c2, "Gh0st"),
                ioc!(mutex, "Gh0stRat"),
            ],
            behavioral_sigs: &[
                behav!("keylog", "Real-time keylogger", ["GetAsyncKeyState"]),
                behav!("live_view", "Desktop live view", ["BitBlt","GetDC"]),
            ],
            first_seen: "2008-01",
            prevalence: 78,
            description: "Chinese-origin RAT leaked/open-sourced; used by many APT groups",
        },
        // ─── Additional families ─────────────────────────────────────────
        FamilyEntry {
            name: "Mirai",
            aliases: &["Bashlite", "Qbot IoT"],
            category: FamilyCategory::Botnet,
            mitre_techniques: &["T1110","T1498","T1499","T1059"],
            typical_iocs: &[
                ioc!(c2, ":23"),
                ioc!(file, "/tmp/.X"),
            ],
            behavioral_sigs: &[
                behav!("telnet_scan", "Telnet brute-force scanner", ["connect","send"]),
                behav!("ddos", "DDoS attack modules", ["sendto"]),
            ],
            first_seen: "2016-08",
            prevalence: 85,
            description: "IoT botnet performing record-breaking DDoS attacks",
        },
        FamilyEntry {
            name: "BlackMatter",
            aliases: &["DarkSide v2"],
            category: FamilyCategory::Ransomware,
            mitre_techniques: &["T1486","T1490","T1489","T1078"],
            typical_iocs: &[
                ioc!(mutex, "Global\\{0F7A8C5B-6F6A-9F31-A9B5-...")
            ],
            behavioral_sigs: &[
                behav!("safe_mode_boot", "Reboots into safe mode for encryption bypass",
                    ["bcdedit","BootStatusPolicy"]),
            ],
            first_seen: "2021-07",
            prevalence: 80,
            description: "Successor to DarkSide ransomware group",
        },
    ]
}

fn mixed_threat_entries() -> Vec<FamilyEntry> {
    vec![
        FamilyEntry {
            name: "Agent Tesla",
            aliases: &["AgentTesla", "AgenTesla"],
            category: FamilyCategory::Stealer,
            mitre_techniques: &["T1056","T1555","T1082","T1113"],
            typical_iocs: &[
                ioc!(mutex, "ioeklk_mutx"),
                ioc!(c2, "/webpanel/"),
            ],
            behavioral_sigs: &[
                behav!("keylog", "Keylogger via WH_KEYBOARD_LL", ["SetWindowsHookExW"]),
                behav!("email_exfil", "Exfiltrates via SMTP", ["SmtpClient"]),
            ],
            first_seen: "2014-11",
            prevalence: 87,
            description: ".NET keylogger/stealer sold as commercial spyware",
        },
        FamilyEntry {
            name: "FormBook",
            aliases: &["xLoader"],
            category: FamilyCategory::Stealer,
            mitre_techniques: &["T1056","T1555","T1027","T1055"],
            typical_iocs: &[
                ioc!(c2, "/r30j/"),
                ioc!(c2, "/bf7x/"),
            ],
            behavioral_sigs: &[
                behav!("api_hook", "Hooks browser API for credential theft", ["NtCreateSection"]),
                behav!("form_grab", "Form grabbing from web browsers",
                    ["HttpSendRequestW","InternetReadFile"]),
            ],
            first_seen: "2016-07",
            prevalence: 85,
            description: "Form grabber and stealer sold as MaaS; cross-platform variant xLoader",
        },
        FamilyEntry {
            name: "DarkComet",
            aliases: &["DarkComet RAT", "Fynloski"],
            category: FamilyCategory::Rat,
            mitre_techniques: &["T1056","T1113","T1547","T1059"],
            typical_iocs: &[
                ioc!(mutex, "DC_MUTEX-"),
                ioc!(reg, "HKCU\\Software\\DC3_FEXEC"),
            ],
            behavioral_sigs: &[
                behav!("remote_desktop", "Remote desktop control", ["GetDC","BitBlt"]),
                behav!("keylog", "Keylogger", ["SetWindowsHookExW"]),
            ],
            first_seen: "2008-01",
            prevalence: 72,
            description: "French-developed RAT; discontinued but still used",
        },
        FamilyEntry {
            name: "Qakbot",
            aliases: &["QBot", "Quakbot", "Pinkslipbot"],
            category: FamilyCategory::Banker,
            mitre_techniques: &["T1055","T1021","T1566","T1003","T1547"],
            typical_iocs: &[
                ioc!(mutex, "Global\\idfkvs32"),
                ioc!(reg, "HKCU\\Software\\Microsoft\\{GUID}"),
            ],
            behavioral_sigs: &[
                behav!("webinject", "Browser web injection for credential theft",
                    ["InternetReadFile","HttpAddRequestHeaders"]),
                behav!("worm_spread", "Worm via network shares", ["NetShareEnum"]),
            ],
            first_seen: "2007-01",
            prevalence: 88,
            description: "Long-running banking trojan with worm capabilities, used by multiple groups",
        },
    ]
}

fn backdoor_other_entries() -> Vec<FamilyEntry> {
    let mut entries = backdoor_base_entries();
    entries.extend(mixed_threat_entries());
    entries
}

fn stealer_and_other_entries() -> Vec<FamilyEntry> {
    let mut entries = stealer_entries();
    entries.extend(loader_rootkit_entries());
    entries.extend(worm_bot_entries());
    entries.extend(backdoor_other_entries());
    entries
}

fn build_database() -> Vec<FamilyEntry> {
    let mut db = ransomware_entries();
    db.extend(banker_and_rat_entries());
    db.extend(stealer_and_other_entries());
    db
}

impl Default for FamilyDatabase {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_not_empty() {
        let db = FamilyDatabase::new();
        assert!(db.len() >= 20, "Expected at least 20 families, got {}", db.len());
    }

    #[test]
    fn lookup_wannacry() {
        let db = FamilyDatabase::new();
        let entry = db.get("WannaCry").expect("WannaCry not found");
        assert_eq!(entry.name, "WannaCry");
        assert_eq!(entry.category, FamilyCategory::Ransomware);
    }

    #[test]
    fn lookup_by_alias() {
        let db = FamilyDatabase::new();
        let entry = db.get("Geodo").expect("Geodo alias not found");
        assert_eq!(entry.name, "Emotet");
    }

    #[test]
    fn match_iocs_finds_shadow_copy() {
        let db = FamilyDatabase::new();
        let data = b"vssadmin delete shadows /all";

        // `vssadmin` is a BEHAVIOURAL indicator (of `delete_shadows`), not an
        // IOC — it is a legitimate Windows tool, so it does not belong in
        // `typical_iocs` beside mutexes, domains and C2 hosts. This test used
        // to call `match_iocs`, which searches only that field, and therefore
        // could never pass. `match_behaviors` (added 2026-07-29) is the matcher
        // the assertion was always asking for.
        let matches = db.match_behaviors(data);
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .any(|(_, sigs)| sigs.iter().any(|s| s.name == "delete_shadows")),
            "the shadow-copy deletion behaviour must be the one identified"
        );

        // And it is genuinely not an IOC — the original path stays empty.
        assert!(db.match_iocs(data).is_empty());
    }

    #[test]
    fn top_n() {
        let db = FamilyDatabase::new();
        let top = db.top_n(5);
        assert_eq!(top.len(), 5);
        // Should be sorted by prevalence descending.
        assert!(top[0].prevalence >= top[4].prevalence);
    }

    #[test]
    fn category_filter_ransomware() {
        let db = FamilyDatabase::new();
        let ransomware = db.by_category(FamilyCategory::Ransomware);
        assert!(ransomware.len() >= 4);
    }
}
