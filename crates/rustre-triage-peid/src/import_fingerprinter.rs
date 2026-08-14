//! `import_fingerprinter` — Fingerprint PE files by import table: hash
//! imported function names, cluster by similarity, detect known malware
//! import patterns, `ImportFingerprint`, `ImportCluster`.

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ─── ImportEntry ─────────────────────────────────────────────────────────────

/// A single entry in an import table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEntry {
    /// DLL name (lowercased for normalisation).
    pub dll: String,
    /// Function name (may be empty for ordinal-only imports).
    pub name: String,
    /// Import ordinal (0 if by-name only).
    pub ordinal: u16,
    /// Whether this is an ordinal-only import.
    pub by_ordinal: bool,
}

impl ImportEntry {
    /// Create a by-name import.
    #[must_use]
    pub fn by_name(dll: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            dll: dll.into().to_lowercase(),
            name: name.into(),
            ordinal: 0,
            by_ordinal: false,
        }
    }

    /// Create an ordinal-only import.
    #[must_use]
    pub fn by_ordinal(dll: impl Into<String>, ordinal: u16) -> Self {
        Self {
            dll: dll.into().to_lowercase(),
            name: String::new(),
            ordinal,
            by_ordinal: true,
        }
    }

    /// Normalised identifier: `"dll!name"` or `"dll!#ordinal"`.
    #[must_use]
    pub fn identifier(&self) -> String {
        if self.by_ordinal {
            format!("{}!#{}", self.dll, self.ordinal)
        } else {
            format!("{}!{}", self.dll, self.name)
        }
    }
}

// ─── ImportHash ───────────────────────────────────────────────────────────────

/// A compact fingerprint derived from an import table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportHash {
    /// ImpHash: MD5 of the comma-separated sorted `dll.func` list (lower-case).
    /// We use a portable 64-bit FNV-1a hash here rather than requiring MD5.
    pub imphash_fnv64: u64,
    /// Number of imports.
    pub import_count: usize,
    /// Number of distinct DLLs.
    pub dll_count: usize,
    /// The sorted `dll.func` string used to derive the hash.
    pub canonical_string: String,
}

impl ImportHash {
    /// Compute the import hash from a slice of entries.
    #[must_use]
    pub fn compute(entries: &[ImportEntry]) -> Self {
        let mut tokens: Vec<String> = entries
            .iter()
            .map(|e| {
                let dll = strip_ext(&e.dll);
                let func = if e.by_ordinal {
                    format!("ord{}", e.ordinal)
                } else {
                    e.name.to_lowercase()
                };
                format!("{dll}.{func}")
            })
            .collect();
        tokens.sort_unstable();
        tokens.dedup();

        let canonical = tokens.join(",");
        let hash = fnv1a_64(canonical.as_bytes());

        let dll_count: HashSet<&str> = entries.iter().map(|e| e.dll.as_str()).collect();

        Self {
            imphash_fnv64: hash,
            import_count: entries.len(),
            dll_count: dll_count.len(),
            canonical_string: canonical,
        }
    }
}

fn strip_ext(s: &str) -> &str {
    if let Some(pos) = s.rfind('.') {
        &s[..pos]
    } else {
        s
    }
}

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;
    let mut hash = FNV_OFFSET;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ─── ImportFingerprint ────────────────────────────────────────────────────────

/// Full import fingerprint for a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFingerprint {
    /// The computed import hash.
    pub hash: ImportHash,
    /// All import entries parsed from the PE.
    pub entries: Vec<ImportEntry>,
    /// Per-DLL import counts.
    pub dll_counts: HashMap<String, usize>,
    /// Detected malware patterns, if any.
    pub malware_patterns: Vec<MalwareImportPattern>,
    /// Source file / tag for this fingerprint.
    pub source_tag: Option<String>,
}

impl ImportFingerprint {
    /// Build an `ImportFingerprint` from a list of import entries.
    #[must_use]
    pub fn from_entries(entries: Vec<ImportEntry>) -> Self {
        let hash = ImportHash::compute(&entries);

        let mut dll_counts: HashMap<String, usize> = HashMap::new();
        for e in &entries {
            *dll_counts.entry(e.dll.clone()).or_default() += 1;
        }

        let malware_patterns = detect_malware_patterns(&entries);

        Self { hash, entries, dll_counts, malware_patterns, source_tag: None }
    }

    /// Jaccard similarity with another fingerprint based on the import sets.
    #[must_use]
    pub fn jaccard_similarity(&self, other: &Self) -> f64 {
        let set_a: HashSet<String> = self.entries.iter().map(|e| e.identifier()).collect();
        let set_b: HashSet<String> = other.entries.iter().map(|e| e.identifier()).collect();

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if union == 0 {
            1.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Imports from a specific DLL.
    #[must_use]
    pub fn imports_from_dll(&self, dll: &str) -> Vec<&ImportEntry> {
        let dll_lower = dll.to_lowercase();
        self.entries.iter().filter(|e| e.dll == dll_lower).collect()
    }

    /// All unique DLL names.
    #[must_use]
    pub fn dlls(&self) -> Vec<&str> {
        self.dll_counts.keys().map(|s| s.as_str()).collect()
    }

    /// Whether this fingerprint has any detected malware patterns.
    #[must_use]
    pub fn has_malware_patterns(&self) -> bool {
        !self.malware_patterns.is_empty()
    }
}

// ─── MalwareImportPattern ─────────────────────────────────────────────────────

/// A known malware import pattern detected in a PE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareImportPattern {
    /// Short name of the pattern.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Severity: "low", "medium", "high".
    pub severity: String,
    /// The matched function names.
    pub matched_imports: Vec<String>,
}

/// Known patterns to look for in import tables.
struct KnownPattern {
    name: &'static str,
    description: &'static str,
    severity: &'static str,
    /// Any of these functions being present triggers the pattern.
    functions: &'static [&'static str],
    /// Minimum number of functions that must match.
    min_match: usize,
}

static KNOWN_PATTERNS: &[KnownPattern] = &[
    KnownPattern {
        name: "ProcessInjection",
        description: "Imports associated with process injection techniques",
        severity: "high",
        functions: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "NetworkSockets",
        description: "Raw socket API usage indicating possible C2 communication",
        severity: "medium",
        functions: &["WSAStartup", "socket", "connect", "send", "recv", "WSASend", "WSARecv"],
        min_match: 3,
    },
    KnownPattern {
        name: "PrivilegeEscalation",
        description: "Token manipulation APIs used for privilege escalation",
        severity: "high",
        functions: &[
            "OpenProcessToken",
            "AdjustTokenPrivileges",
            "LookupPrivilegeValue",
            "ImpersonateLoggedOnUser",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "RegistryPersistence",
        description: "Registry APIs used for persistence mechanisms",
        severity: "medium",
        functions: &[
            "RegOpenKeyEx",
            "RegSetValueEx",
            "RegCreateKeyEx",
            "RegDeleteValue",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "AntiDebugging",
        description: "Anti-debugging and anti-analysis techniques",
        severity: "medium",
        functions: &[
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "GetTickCount",
            "QueryPerformanceCounter",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "CryptoAPIs",
        description: "Cryptography API usage (possible ransomware/encryption)",
        severity: "low",
        functions: &[
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenKey",
            "CryptImportKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "KeyLogging",
        description: "Input capture APIs associated with keyloggers",
        severity: "high",
        functions: &[
            "SetWindowsHookEx",
            "GetKeyState",
            "GetAsyncKeyState",
            "CallNextHookEx",
        ],
        min_match: 2,
    },
    KnownPattern {
        name: "FileSystemTraversal",
        description: "File enumeration APIs for bulk file access",
        severity: "low",
        functions: &[
            "FindFirstFile",
            "FindNextFile",
            "FindFirstFileEx",
            "GetFileAttributes",
        ],
        min_match: 2,
    },
];

fn detect_malware_patterns(entries: &[ImportEntry]) -> Vec<MalwareImportPattern> {
    let func_names: HashSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let mut detected = Vec::new();

    for pattern in KNOWN_PATTERNS {
        let matched: Vec<String> = pattern
            .functions
            .iter()
            .filter(|&&f| func_names.contains(f))
            .map(|&f| f.to_owned())
            .collect();

        if matched.len() >= pattern.min_match {
            detected.push(MalwareImportPattern {
                name: pattern.name.to_owned(),
                description: pattern.description.to_owned(),
                severity: pattern.severity.to_owned(),
                matched_imports: matched,
            });
        }
    }

    detected
}

// ─── ImportCluster ────────────────────────────────────────────────────────────

/// A cluster of PE files with similar import fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCluster {
    /// Cluster identifier (0-based).
    pub id: usize,
    /// Member fingerprint tags (source_tag or index string).
    pub members: Vec<String>,
    /// Centroid: the most representative member's hash.
    pub centroid_hash: u64,
    /// Average Jaccard similarity within the cluster.
    pub intra_similarity: f64,
    /// Imports shared by all members.
    pub common_imports: HashSet<String>,
}

impl ImportCluster {
    /// Create a new cluster with a single seed member.
    fn new_with_seed(id: usize, seed: &ImportFingerprint) -> Self {
        let imports: HashSet<String> = seed.entries.iter().map(|e| e.identifier()).collect();
        Self {
            id,
            members: vec![seed.source_tag.clone().unwrap_or_else(|| format!("fp_{id}"))],
            centroid_hash: seed.hash.imphash_fnv64,
            intra_similarity: 1.0,
            common_imports: imports,
        }
    }
}

// ─── ImportFingerprintEngine ──────────────────────────────────────────────────

/// Engine for fingerprinting and clustering PE import tables.
pub struct ImportFingerprintEngine {
    /// All fingerprints loaded.
    pub fingerprints: Vec<ImportFingerprint>,
    /// Similarity threshold for clustering [0.0, 1.0].
    pub cluster_threshold: f64,
}

impl ImportFingerprintEngine {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self { fingerprints: Vec::new(), cluster_threshold: 0.6 }
    }

    /// Add a fingerprint.
    pub fn add(&mut self, fp: ImportFingerprint) {
        self.fingerprints.push(fp);
    }

    /// Compute pairwise Jaccard similarity matrix (parallelised with rayon).
    #[must_use]
    pub fn similarity_matrix(&self) -> Vec<Vec<f64>> {
        let n = self.fingerprints.len();
        (0..n)
            .into_par_iter()
            .map(|i| {
                (0..n)
                    .map(|j| {
                        if i == j {
                            1.0
                        } else {
                            self.fingerprints[i].jaccard_similarity(&self.fingerprints[j])
                        }
                    })
                    .collect()
            })
            .collect()
    }

    /// Cluster fingerprints using greedy single-linkage clustering.
    #[must_use]
    pub fn cluster(&self) -> Vec<ImportCluster> {
        let n = self.fingerprints.len();
        if n == 0 {
            return Vec::new();
        }

        let matrix = self.similarity_matrix();
        let mut cluster_id: Vec<Option<usize>> = vec![None; n];
        let mut clusters: Vec<ImportCluster> = Vec::new();

        for i in 0..n {
            if cluster_id[i].is_some() {
                continue;
            }
            // Start a new cluster
            let cid = clusters.len();
            cluster_id[i] = Some(cid);
            let mut cluster = ImportCluster::new_with_seed(cid, &self.fingerprints[i]);

            // Greedily add similar unclustered fingerprints
            for j in (i + 1)..n {
                if cluster_id[j].is_none() && matrix[i][j] >= self.cluster_threshold {
                    cluster_id[j] = Some(cid);
                    let tag = self.fingerprints[j]
                        .source_tag
                        .clone()
                        .unwrap_or_else(|| format!("fp_{j}"));
                    cluster.members.push(tag);

                    // Intersect common imports
                    let fp_imports: HashSet<String> =
                        self.fingerprints[j].entries.iter().map(|e| e.identifier()).collect();
                    cluster.common_imports =
                        cluster.common_imports.intersection(&fp_imports).cloned().collect();
                }
            }

            // Compute intra-cluster similarity
            if cluster.members.len() > 1 {
                let member_indices: Vec<usize> = (0..n)
                    .filter(|&x| cluster_id[x] == Some(cid))
                    .collect();
                let matrix_ref = &matrix;
                let total: f64 = member_indices
                    .iter()
                    .flat_map(|&a| {
                        member_indices.iter().filter(move |&&b| b != a).map(move |&b| matrix_ref[a][b])
                    })
                    .sum();
                let pairs = (member_indices.len() * (member_indices.len() - 1)) as f64;
                cluster.intra_similarity = if pairs > 0.0 { total / pairs } else { 1.0 };
            }

            clusters.push(cluster);
        }

        clusters
    }

    /// Find all fingerprints matching a given hash (exact match).
    #[must_use]
    pub fn find_by_hash(&self, hash: u64) -> Vec<&ImportFingerprint> {
        self.fingerprints
            .iter()
            .filter(|fp| fp.hash.imphash_fnv64 == hash)
            .collect()
    }

    /// Return all fingerprints that have at least one detected malware pattern.
    #[must_use]
    pub fn flagged_fingerprints(&self) -> Vec<&ImportFingerprint> {
        self.fingerprints.iter().filter(|fp| fp.has_malware_patterns()).collect()
    }

    /// Summary statistics over all loaded fingerprints.
    #[must_use]
    pub fn summary(&self) -> FingerprintSummary {
        let total = self.fingerprints.len();
        let total_imports: usize = self.fingerprints.iter().map(|fp| fp.entries.len()).sum();
        let flagged = self.fingerprints.iter().filter(|fp| fp.has_malware_patterns()).count();
        let unique_hashes: HashSet<u64> =
            self.fingerprints.iter().map(|fp| fp.hash.imphash_fnv64).collect();

        FingerprintSummary {
            total_fingerprints: total,
            total_imports,
            flagged_count: flagged,
            unique_hash_count: unique_hashes.len(),
        }
    }
}

impl Default for ImportFingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of the fingerprint engine's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSummary {
    pub total_fingerprints: usize,
    pub total_imports: usize,
    pub flagged_count: usize,
    pub unique_hash_count: usize,
}
