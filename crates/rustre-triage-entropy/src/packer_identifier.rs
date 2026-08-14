// packer_identifier.rs — Common packer identification for rustre-triage-entropy.
//
// Identifies common PE packers: UPX, MPRESS, Themida, VMProtect, PECompact,
// ASPack, Petite, FSG, LZMA-packed; combines entropy + signature + header
// anomaly scoring into an identification result.

use std::collections::HashMap;
use std::fmt;
use crate::casts;

// ─── PackerId ─────────────────────────────────────────────────────────────────

/// Identified packer family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackerId {
    Upx,
    Mpress,
    Themida,
    VmProtect,
    PeCompact,
    AspAck,
    Petite,
    Fsg,
    LzmaPacked,
    Obsidium,
    NsPack,
    Custom(String),
    Unknown,
}

impl PackerId {
    /// Return the human-readable name of this packer.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Upx => "UPX",
            Self::Mpress => "MPRESS",
            Self::Themida => "Themida/WinLicense",
            Self::VmProtect => "VMProtect",
            Self::PeCompact => "PECompact",
            Self::AspAck => "ASPack",
            Self::Petite => "Petite",
            Self::Fsg => "FSG (Fast Small Good)",
            Self::LzmaPacked => "LZMA-packed",
            Self::Obsidium => "Obsidium",
            Self::NsPack => "NsPack",
            Self::Custom(name) => name,
            Self::Unknown => "Unknown",
        }
    }

    /// Returns `true` when packer is positively identified (not Unknown).
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl fmt::Display for PackerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── EntropySig ───────────────────────────────────────────────────────────────

/// Entropy-based signature for a packer: expected entropy range of the
/// packed section and whether entropy is sufficient on its own to flag.
#[derive(Debug, Clone)]
pub struct EntropySig {
    /// Lower bound of expected packed section entropy.
    pub entropy_low: f64,
    /// Upper bound of expected packed section entropy.
    pub entropy_high: f64,
    /// Whether high entropy alone (without other markers) is enough to flag.
    pub entropy_alone_sufficient: bool,
}

impl EntropySig {
    #[must_use]
    pub const fn new(entropy_low: f64, entropy_high: f64, entropy_alone_sufficient: bool) -> Self {
        Self {
            entropy_low,
            entropy_high,
            entropy_alone_sufficient,
        }
    }

    /// Returns `true` when `entropy` falls within the expected range.
    #[must_use]
    pub fn matches(&self, entropy: f64) -> bool {
        entropy >= self.entropy_low && entropy <= self.entropy_high
    }
}

// ─── PackerSignature ─────────────────────────────────────────────────────────

/// A composite packer signature combining section names, binary byte patterns,
/// string patterns, and entropy characteristics.
#[derive(Debug, Clone)]
pub struct PackerSignature {
    /// The packer this signature identifies.
    pub packer: PackerId,
    /// Known section names associated with this packer.
    pub section_names: Vec<&'static str>,
    /// Binary byte patterns to search for (pattern bytes, None = wildcard).
    pub byte_patterns: Vec<Vec<Option<u8>>>,
    /// String literals to search for (case-insensitive substring match).
    pub string_patterns: Vec<&'static str>,
    /// Entropy characteristics of the packed section.
    pub entropy_sig: EntropySig,
    /// Weight of each match type: (`section_name`, `byte_pattern`, `string_pattern`).
    pub weights: (f64, f64, f64),
}

impl PackerSignature {
    /// Test section names from a PE against this signature.
    ///
    /// Returns the fractional match score (0.0–1.0).
    #[must_use]
    pub fn score_section_names(&self, found_names: &[&str]) -> f64 {
        if self.section_names.is_empty() {
            return 0.0;
        }
        let matches = found_names
            .iter()
            .filter(|&&n| {
                self.section_names
                    .iter()
                    .any(|&s| s.eq_ignore_ascii_case(n))
            })
            .count();
        if matches > 0 { 1.0 } else { 0.0 }
    }

    /// Test byte patterns against a raw data buffer.
    ///
    /// Returns 1.0 if any pattern is found, 0.0 otherwise.
    #[must_use]
    pub fn score_byte_patterns(&self, data: &[u8]) -> f64 {
        for pattern in &self.byte_patterns {
            if pattern.is_empty() || data.len() < pattern.len() {
                continue;
            }
            'outer: for window in data.windows(pattern.len()) {
                for (i, pb) in pattern.iter().enumerate() {
                    if let Some(b) = pb
                        && window[i] != *b {
                            continue 'outer;
                        }
                }
                return 1.0;
            }
        }
        0.0
    }

    /// Test string patterns against a raw data buffer.
    ///
    /// Returns 1.0 if any string is found (case-insensitive), 0.0 otherwise.
    #[must_use]
    pub fn score_string_patterns(&self, data: &[u8]) -> f64 {
        if self.string_patterns.is_empty() {
            return 0.0;
        }
        // Build an ASCII-lowercased view for case-insensitive search.
        let lowered: Vec<u8> = data.iter().map(u8::to_ascii_lowercase).collect();
        for &pattern in &self.string_patterns {
            let pat_bytes = pattern.as_bytes();
            if lowered.windows(pat_bytes.len()).any(|w| w == pat_bytes) {
                return 1.0;
            }
        }
        0.0
    }

    /// Compute an aggregate match score for the given data and section names.
    ///
    /// Combines section name, byte pattern, string pattern, and entropy scores.
    #[must_use]
    pub fn match_score(
        &self,
        data: &[u8],
        section_names: &[&str],
        section_entropy: f64,
    ) -> f64 {
        let sn = self.score_section_names(section_names);
        let bp = self.score_byte_patterns(data);
        let sp = self.score_string_patterns(data);

        let (w_sn, w_bp, w_string) = self.weights;
        let weighted = sp.mul_add(w_string, sn.mul_add(w_sn, bp * w_bp));

        // Entropy factor: bonus if entropy is in the expected range.
        let entropy_factor = if self.entropy_sig.matches(section_entropy) {
            1.2_f64
        } else {
            1.0_f64
        };

        (weighted * entropy_factor).min(1.0)
    }
}

// ─── PackerMatch ──────────────────────────────────────────────────────────────

/// Result of matching a packer signature against a binary.
#[derive(Debug, Clone)]
pub struct PackerMatch {
    /// The identified packer.
    pub packer: PackerId,
    /// Match confidence in [0.0, 1.0].
    pub confidence: f64,
    /// Evidence strings describing what was found.
    pub evidence: Vec<String>,
    /// Entropy of the best-matching section.
    pub section_entropy: f64,
    /// Name of the section that produced the best match.
    pub matching_section: Option<String>,
}

impl PackerMatch {
    /// Returns `true` when confidence >= 0.5.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.5
    }

    /// Returns `true` when confidence >= 0.8.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

impl fmt::Display for PackerMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackerMatch({}, confidence={:.2}, evidence_count={})",
            self.packer,
            self.confidence,
            self.evidence.len()
        )
    }
}

// ─── Signature database ───────────────────────────────────────────────────────

/// Build the built-in packer signature database.
#[must_use]
pub fn builtin_signatures() -> Vec<PackerSignature> {
    let mut sigs = builtin_signatures_primary();
    sigs.extend(builtin_signatures_secondary());
    sigs
}

fn builtin_signatures_primary() -> Vec<PackerSignature> {
    vec![
        // UPX
        PackerSignature {
            packer: PackerId::Upx,
            section_names: vec!["UPX0", "UPX1", "UPX2"],
            byte_patterns: vec![
                vec![Some(b'U'), Some(b'P'), Some(b'X'), Some(b'!')],
                // UPX stub prologue: push esi / push edi / push ebp after UPX0 jump.
                vec![Some(0x60), Some(0xBE)],
            ],
            string_patterns: vec!["upx!", "$info: this file is packed with the upx"],
            entropy_sig: EntropySig::new(7.0, 8.0, false),
            weights: (0.5, 0.3, 0.2),
        },
        // MPRESS
        PackerSignature {
            packer: PackerId::Mpress,
            section_names: vec![".MPRESS1", ".MPRESS2"],
            byte_patterns: vec![vec![Some(b'M'), Some(b'P'), Some(b'R'), Some(b'E'), Some(b'S'), Some(b'S')]],
            string_patterns: vec!["mpress"],
            entropy_sig: EntropySig::new(7.0, 8.0, false),
            weights: (0.5, 0.3, 0.2),
        },
        // Themida / WinLicense
        PackerSignature {
            packer: PackerId::Themida,
            section_names: vec![".themida", ".winlicen"],
            byte_patterns: vec![vec![Some(0xEB), Some(0x06), Some(0x00), Some(0x00)]],
            string_patterns: vec!["themida", "winlicense", "oreans"],
            entropy_sig: EntropySig::new(7.2, 8.0, false),
            weights: (0.4, 0.2, 0.4),
        },
        // VMProtect
        PackerSignature {
            packer: PackerId::VmProtect,
            section_names: vec![".vmp0", ".vmp1", ".vmp2"],
            byte_patterns: vec![
                vec![Some(0x9C), Some(0x60), Some(0xE8), Some(0x00), Some(0x00), Some(0x00), Some(0x00)],
            ],
            string_patterns: vec!["vmprotect", "vmp"],
            entropy_sig: EntropySig::new(7.0, 8.0, false),
            weights: (0.5, 0.3, 0.2),
        },
        // PECompact
        PackerSignature {
            packer: PackerId::PeCompact,
            section_names: vec![],
            byte_patterns: vec![
                vec![Some(0xEB), Some(0x06), Some(b'P'), Some(b'E'), Some(b'C'), Some(b'o'), Some(b'm'), Some(b'p')],
            ],
            string_patterns: vec!["pecompact", "bitsum"],
            entropy_sig: EntropySig::new(6.5, 8.0, false),
            weights: (0.1, 0.5, 0.4),
        },
    ]
}

fn builtin_signatures_secondary() -> Vec<PackerSignature> {
    vec![
        // ASPack
        PackerSignature {
            packer: PackerId::AspAck,
            section_names: vec![".aspack", ".adata"],
            byte_patterns: vec![
                vec![Some(0x60), Some(0xE8), Some(0x03), Some(0x00), Some(0x00), Some(0x00)],
            ],
            string_patterns: vec!["aspack"],
            entropy_sig: EntropySig::new(6.8, 8.0, false),
            weights: (0.4, 0.3, 0.3),
        },
        // Petite
        PackerSignature {
            packer: PackerId::Petite,
            section_names: vec![".petite"],
            byte_patterns: vec![vec![Some(0xB8), None, None, None, None, Some(0x60)]],
            string_patterns: vec!["petite"],
            entropy_sig: EntropySig::new(6.5, 8.0, false),
            weights: (0.4, 0.3, 0.3),
        },
        // FSG
        PackerSignature {
            packer: PackerId::Fsg,
            section_names: vec![],
            byte_patterns: vec![
                vec![Some(0xBB), None, None, None, None, Some(0xBF), None, None, None, None, Some(0xBE)],
            ],
            string_patterns: vec!["fsg"],
            entropy_sig: EntropySig::new(7.5, 8.0, true),
            weights: (0.1, 0.6, 0.3),
        },
        // LZMA-packed
        PackerSignature {
            packer: PackerId::LzmaPacked,
            section_names: vec![],
            byte_patterns: vec![
                vec![Some(0x5D), Some(0x00), Some(0x00), Some(0x80), Some(0x00)],
            ],
            string_patterns: vec!["lzma", "7-zip"],
            entropy_sig: EntropySig::new(7.2, 8.0, false),
            weights: (0.0, 0.7, 0.3),
        },
        // Obsidium
        PackerSignature {
            packer: PackerId::Obsidium,
            section_names: vec![".obsidium"],
            byte_patterns: vec![vec![Some(0xEB), Some(0x02), Some(0xEB), Some(0xFA)]],
            string_patterns: vec!["obsidium"],
            entropy_sig: EntropySig::new(7.0, 8.0, false),
            weights: (0.4, 0.3, 0.3),
        },
        // NsPack
        PackerSignature {
            packer: PackerId::NsPack,
            section_names: vec![".nsp0", ".nsp1", ".nsp2"],
            byte_patterns: vec![],
            string_patterns: vec!["nspack", "north star"],
            entropy_sig: EntropySig::new(6.8, 8.0, false),
            weights: (0.5, 0.1, 0.4),
        },
    ]
}

// ─── PackerIdentifier ─────────────────────────────────────────────────────────

/// Identifies the packer (if any) used on a PE binary.
///
/// Combines:
/// - Section name matching against known packer section name lists.
/// - Byte-pattern matching in the first 0x10000 bytes and entry-point region.
/// - String-pattern matching for packer banners and copyright notices.
/// - Entropy analysis of executable sections.
pub struct PackerIdentifier {
    signatures: Vec<PackerSignature>,
    /// Minimum confidence to emit a `PackerMatch`.
    pub min_confidence: f64,
}

impl PackerIdentifier {
    /// Create an identifier loaded with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: builtin_signatures(),
            min_confidence: 0.25,
        }
    }

    /// Create with custom signatures.
    #[must_use]
    pub const fn with_signatures(signatures: Vec<PackerSignature>) -> Self {
        Self {
            signatures,
            min_confidence: 0.25,
        }
    }

    /// Register an additional signature at runtime.
    pub fn register(&mut self, sig: PackerSignature) {
        self.signatures.push(sig);
    }

    /// Identify packers in `data`.
    ///
    /// `section_names`: names of the PE sections (e.g. from `SectionEntropy`).
    /// `section_entropy`: entropy of the first executable section (or 0.0).
    ///
    /// Returns all matches above `min_confidence`, sorted by descending confidence.
    #[must_use]
    pub fn identify(
        &self,
        data: &[u8],
        section_names: &[&str],
        section_entropy: f64,
    ) -> Vec<PackerMatch> {
        let probe_end = data.len().min(0x20000);
        let probe = &data[..probe_end];

        let mut matches: Vec<PackerMatch> = Vec::new();

        for sig in &self.signatures {
            let mut evidence = Vec::new();

            // Section name check.
            let sn_score = sig.score_section_names(section_names);
            if sn_score > 0.0 {
                let found: Vec<&str> = section_names
                    .iter()
                    .filter(|&&n| sig.section_names.iter().any(|&s| s.eq_ignore_ascii_case(n)))
                    .copied()
                    .collect();
                evidence.push(format!("section names found: {}", found.join(", ")));
            }

            // Byte pattern check.
            let bp_score = sig.score_byte_patterns(probe);
            if bp_score > 0.0 {
                evidence.push("byte pattern matched in binary".to_string());
            }

            // String pattern check.
            let str_score = sig.score_string_patterns(probe);
            if str_score > 0.0 {
                evidence.push("string pattern matched in binary".to_string());
            }

            // Entropy check.
            if sig.entropy_sig.matches(section_entropy) {
                evidence.push(format!(
                    "section entropy {section_entropy:.3} in expected range [{:.1},{:.1}]",
                    sig.entropy_sig.entropy_low, sig.entropy_sig.entropy_high
                ));
            }

            let confidence = sig.match_score(probe, section_names, section_entropy);

            if confidence >= self.min_confidence {
                matches.push(PackerMatch {
                    packer: sig.packer.clone(),
                    confidence,
                    evidence,
                    section_entropy,
                    matching_section: section_names.first().map(|s| (*s).to_string()),
                });
            }
        }

        // Sort by confidence descending.
        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }

    /// Return the best single match, or `None` when nothing exceeds `min_confidence`.
    #[must_use]
    pub fn best_match(
        &self,
        data: &[u8],
        section_names: &[&str],
        section_entropy: f64,
    ) -> Option<PackerMatch> {
        self.identify(data, section_names, section_entropy).into_iter().next()
    }

    /// Identify directly from a flat byte slice with no section metadata.
    ///
    /// Uses the overall byte-slice entropy and no section names.
    #[must_use]
    pub fn identify_raw(&self, data: &[u8]) -> Vec<PackerMatch> {
        let entropy = compute_entropy(data);
        self.identify(data, &[], entropy)
    }

    /// Group the matches produced by [`Self::identify`] by [`PackerId`] and
    /// return a histogram. The map's value is the count of distinct
    /// signature variants that voted for each packer family, which is useful
    /// when several near-duplicate signatures all light up at once.
    #[must_use]
    pub fn family_histogram(
        &self,
        data: &[u8],
        section_names: &[&str],
        section_entropy: f64,
    ) -> HashMap<PackerId, usize> {
        let matches = self.identify(data, section_names, section_entropy);
        let mut hist: HashMap<PackerId, usize> = HashMap::new();
        for m in &matches {
            *hist.entry(m.packer.clone()).or_insert(0) += 1;
        }
        hist
    }
}

impl Default for PackerIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── HeaderAnomalyScorer ──────────────────────────────────────────────────────

/// Score PE header anomalies that are common with packed binaries.
#[derive(Debug, Clone, Default)]
pub struct HeaderAnomalyScorer;

/// Result of PE header anomaly scoring.
#[derive(Debug, Clone)]
pub struct HeaderAnomalyResult {
    /// Aggregate anomaly score in [0.0, 1.0].
    pub score: f64,
    /// Individual anomaly descriptions.
    pub anomalies: Vec<String>,
}

impl HeaderAnomalyScorer {
    /// Create a new scorer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Score PE header anomalies in `data`.
    ///
    /// Checks:
    /// - Import table absent or very small
    /// - Non-standard section alignments
    /// - Unusual section characteristics (W+X, no sections, etc.)
    /// - Overlay bytes after the last section
    /// - Suspicious entry point outside `.text`
    #[must_use]
    pub fn score(&self, data: &[u8]) -> HeaderAnomalyResult {
        const SE: usize = 40;
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        let mut anomalies = Vec::new();
        let mut raw_score = 0.0_f64;

        if data.len() < 64 {
            return HeaderAnomalyResult {
                score: 0.0,
                anomalies,
            };
        }

        // Locate PE offset.
        let e_lfanew = usize::try_from(u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]])).unwrap_or(usize::MAX);
        if e_lfanew + 24 > data.len() {
            anomalies.push("Truncated PE header (e_lfanew out of bounds)".to_string());
            return HeaderAnomalyResult { score: 0.5, anomalies };
        }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            anomalies.push("Missing PE signature".to_string());
            return HeaderAnomalyResult { score: 0.3, anomalies };
        }

        let num_sections = usize::from(u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]));
        let opt_hdr_size = usize::from(u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]));

        // Check import directory.
        let opt_off = e_lfanew + 24;
        if opt_off + 2 <= data.len() {
            let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
            let import_dir_off = match magic {
                0x10b => opt_off + 104,
                0x20b => opt_off + 120,
                _ => 0,
            };
            if import_dir_off + 8 <= data.len() {
                let import_rva = u32::from_le_bytes([
                    data[import_dir_off],
                    data[import_dir_off + 1],
                    data[import_dir_off + 2],
                    data[import_dir_off + 3],
                ]);
                if import_rva == 0 {
                    anomalies.push("Import directory RVA is 0 (no imports)".to_string());
                    raw_score += 0.3;
                }
            }
        }

        // Walk section headers.
        let section_table = e_lfanew + 24 + opt_hdr_size;
        let mut last_end = 0usize;
        let mut wx_count = 0usize;

        for i in 0..num_sections {
            let s = section_table + i * SE;
            if s + SE > data.len() {
                break;
            }
            let chars = u32::from_le_bytes([data[s + 36], data[s + 37], data[s + 38], data[s + 39]]);
            let raw_off = usize::try_from(u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]])).unwrap_or(usize::MAX);
            let raw_size = usize::try_from(u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]])).unwrap_or(usize::MAX);

            // W+X section.
            if chars & IMAGE_SCN_MEM_EXECUTE != 0 && chars & IMAGE_SCN_MEM_WRITE != 0 {
                wx_count += 1;
            }

            if raw_off + raw_size > last_end {
                last_end = raw_off + raw_size;
            }
        }

        if wx_count > 0 {
            anomalies.push(format!("{wx_count} section(s) are both writable and executable (common in packers)"));
            raw_score += 0.2 * casts::usize_to_f64(wx_count);
        }

        // Overlay check.
        if last_end > 0 && last_end < data.len() {
            let overlay = data.len() - last_end;
            anomalies.push(format!("Overlay of {overlay} bytes after last section at offset 0x{last_end:x}"));
            raw_score += 0.15;
        }

        // Zero section count is highly anomalous.
        if num_sections == 0 {
            anomalies.push("PE has 0 sections".to_string());
            raw_score += 0.4;
        }

        HeaderAnomalyResult {
            score: raw_score.clamp(0.0, 1.0),
            anomalies,
        }
    }
}

// ─── CombinedIdentificationResult ────────────────────────────────────────────

/// Full identification result combining packer matches and header anomalies.
#[derive(Debug, Clone)]
pub struct CombinedIdentificationResult {
    /// Best packer match (if any).
    pub best_packer: Option<PackerMatch>,
    /// All packer matches above threshold.
    pub all_matches: Vec<PackerMatch>,
    /// Header anomaly result.
    pub header_anomalies: HeaderAnomalyResult,
    /// Combined confidence score in [0.0, 1.0].
    pub combined_score: f64,
    /// Whether the binary is considered packed.
    pub is_packed: bool,
}

impl CombinedIdentificationResult {
    /// Produce a summary line for reports.
    #[must_use]
    pub fn summary(&self) -> String {
        self.best_packer.as_ref().map_or_else(
            || format!(
                "No packer identified, header_anomalies={}, combined={:.2}",
                self.header_anomalies.anomalies.len(),
                self.combined_score,
            ),
            |m| format!(
                "Packer: {} (confidence={:.2}), header_anomalies={}, combined={:.2}",
                m.packer,
                m.confidence,
                self.header_anomalies.anomalies.len(),
                self.combined_score,
            ),
        )
    }
}

impl fmt::Display for CombinedIdentificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Run full identification: packer signatures + header anomalies → combined result.
#[must_use]
pub fn identify_full(
    data: &[u8],
    section_names: &[&str],
    section_entropy: f64,
) -> CombinedIdentificationResult {
    let identifier = PackerIdentifier::new();
    let scorer = HeaderAnomalyScorer::new();

    let all_matches = identifier.identify(data, section_names, section_entropy);
    let best_packer = all_matches.first().cloned();
    let header_anomalies = scorer.score(data);

    let packer_confidence = best_packer.as_ref().map_or(0.0, |m| m.confidence);
    let combined_score =
        0.6f64.mul_add(packer_confidence, 0.4 * header_anomalies.score).clamp(0.0, 1.0);
    let is_packed = combined_score > 0.4 || packer_confidence >= 0.5;

    CombinedIdentificationResult {
        best_packer,
        all_matches,
        header_anomalies,
        combined_score,
        is_packed,
    }
}

// ─── compute_entropy (local helper) ──────────────────────────────────────────

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = casts::usize_to_f64(data.len());
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / n;
        p.mul_add(-p.log2(), acc)
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packer_id_name() {
        assert_eq!(PackerId::Upx.name(), "UPX");
        assert_eq!(PackerId::VmProtect.name(), "VMProtect");
        assert_eq!(PackerId::Unknown.name(), "Unknown");
        assert!(!PackerId::Unknown.is_known());
        assert!(PackerId::Upx.is_known());
    }

    #[test]
    fn packer_id_display() {
        assert_eq!(PackerId::Mpress.to_string(), "MPRESS");
        assert_eq!(
            PackerId::Custom("TestPack".to_string()).to_string(),
            "TestPack"
        );
    }

    #[test]
    fn entropy_sig_matches() {
        let sig = EntropySig::new(7.0, 8.0, false);
        assert!(sig.matches(7.5));
        assert!(!sig.matches(6.9));
        assert!(!sig.matches(8.1));
    }

    #[test]
    fn packer_signature_score_section_names_upx() {
        let sigs = builtin_signatures();
        let upx = sigs.iter().find(|s| s.packer == PackerId::Upx).unwrap();
        assert_eq!(upx.score_section_names(&["UPX0", ".text"]), 1.0);
        assert_eq!(upx.score_section_names(&[".text", ".data"]), 0.0);
    }

    #[test]
    fn packer_signature_score_byte_pattern_upx() {
        let sigs = builtin_signatures();
        let upx = sigs.iter().find(|s| s.packer == PackerId::Upx).unwrap();
        let mut data = vec![0u8; 32];
        data[10..14].copy_from_slice(b"UPX!");
        assert!((upx.score_byte_patterns(&data) - (1.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn packer_signature_score_byte_pattern_no_match() {
        let sigs = builtin_signatures();
        let upx = sigs.iter().find(|s| s.packer == PackerId::Upx).unwrap();
        let data = vec![0u8; 64];
        assert!((upx.score_byte_patterns(&data) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn packer_signature_score_string_pattern() {
        let sigs = builtin_signatures();
        let upx = sigs.iter().find(|s| s.packer == PackerId::Upx).unwrap();
        // The signature is the REAL UPX banner, which begins "$Info: ". The
        // test used to pass a paraphrase without that prefix, so it matched
        // neither of UPX's two patterns ("upx!" and the banner) and scored
        // 0.0 — the assertion asked for 1.0 and could not be satisfied.
        let text = b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $";
        assert!(
            (upx.score_string_patterns(text) - (1.0)).abs() < f64::EPSILON,
            "the real UPX banner must match, got {}",
            upx.score_string_patterns(text)
        );
        // The short marker matches too, and case must not matter.
        assert!((upx.score_string_patterns(b"\x00\x00UPX!\x00") - (1.0)).abs() < f64::EPSILON);
        // A paraphrase that carries neither marker must NOT match.
        assert!(
            (upx.score_string_patterns(b"this file is packed with the upx executable packer")
                - (0.0))
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn packer_identifier_new_has_sigs() {
        let id = PackerIdentifier::new();
        assert!(!id.signatures.is_empty());
    }

    #[test]
    fn packer_identifier_identify_upx() {
        let id = PackerIdentifier::new();
        let mut data = vec![0u8; 512];
        data[100..104].copy_from_slice(b"UPX!");
        let matches = id.identify(&data, &["UPX0", "UPX1"], 7.8);
        let upx = matches.iter().find(|m| m.packer == PackerId::Upx);
        assert!(upx.is_some());
        let m = upx.unwrap();
        assert!(m.confidence > 0.0);
    }

    #[test]
    fn packer_identifier_best_match_none_on_clean() {
        let id = PackerIdentifier::new();
        let data = vec![0x90u8; 512];
        let best = id.best_match(&data, &[".text", ".data"], 4.5);
        // Clean data should either return None or a very low-confidence match.
        if let Some(m) = best {
            assert!(m.confidence < 0.5);
        }
    }

    #[test]
    fn packer_identifier_identify_raw() {
        let id = PackerIdentifier::new();
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"UPX!");
        let matches = id.identify_raw(&data);
        // Should not panic; may or may not match depending on entropy.
        let _ = matches;
    }

    #[test]
    fn packer_identifier_register_custom() {
        let mut id = PackerIdentifier::new();
        let n_before = id.signatures.len();
        id.register(PackerSignature {
            packer: PackerId::Custom("MyPack".to_string()),
            section_names: vec![".mypack"],
            byte_patterns: vec![],
            string_patterns: vec!["mypack magic"],
            entropy_sig: EntropySig::new(7.0, 8.0, false),
            weights: (0.5, 0.0, 0.5),
        });
        assert_eq!(id.signatures.len(), n_before + 1);
    }

    #[test]
    fn header_anomaly_scorer_small_data() {
        let scorer = HeaderAnomalyScorer::new();
        let result = scorer.score(&[0u8; 32]);
        assert!((result.score - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn header_anomaly_scorer_no_pe_sig() {
        let scorer = HeaderAnomalyScorer::new();
        let mut data = vec![0u8; 256];
        // Write a fake e_lfanew = 0x40.
        data[0x3c] = 0x40;
        data[0x3d] = 0;
        data[0x3e] = 0;
        data[0x3f] = 0;
        // Don't write PE signature.
        let result = scorer.score(&data);
        assert!(result.score > 0.0);
        assert!(!result.anomalies.is_empty());
    }

    #[test]
    fn identify_full_clean() {
        let data = vec![0u8; 512];
        let result = identify_full(&data, &[".text", ".data"], 4.5);
        // No packer should be flagged at high confidence on clean data.
        if let Some(ref m) = result.best_packer {
            assert!(m.confidence < 0.8);
        }
    }

    #[test]
    fn identify_full_upx() {
        let mut data = vec![0u8; 1024];
        data[200..204].copy_from_slice(b"UPX!");
        let result = identify_full(&data, &["UPX0", "UPX1"], 7.9);
        assert!(!result.all_matches.is_empty());
    }

    #[test]
    fn combined_result_summary_no_packer() {
        let result = CombinedIdentificationResult {
            best_packer: None,
            all_matches: Vec::new(),
            header_anomalies: HeaderAnomalyResult {
                score: 0.1,
                anomalies: vec!["No imports".to_string()],
            },
            combined_score: 0.04,
            is_packed: false,
        };
        let s = result.summary();
        assert!(s.contains("No packer"));
    }

    #[test]
    fn combined_result_summary_with_packer() {
        let m = PackerMatch {
            packer: PackerId::Upx,
            confidence: 0.9,
            evidence: vec!["UPX section names".to_string()],
            section_entropy: 7.8,
            matching_section: Some("UPX0".to_string()),
        };
        let result = CombinedIdentificationResult {
            best_packer: Some(m),
            all_matches: Vec::new(),
            header_anomalies: HeaderAnomalyResult {
                score: 0.2,
                anomalies: Vec::new(),
            },
            combined_score: 0.6,
            is_packed: true,
        };
        let s = result.summary();
        assert!(s.contains("UPX"));
    }

    #[test]
    fn packer_match_confidence_flags() {
        let m = PackerMatch {
            packer: PackerId::Upx,
            confidence: 0.85,
            evidence: Vec::new(),
            section_entropy: 7.8,
            matching_section: None,
        };
        assert!(m.is_confident());
        assert!(m.is_high_confidence());

        let m2 = PackerMatch {
            packer: PackerId::Upx,
            confidence: 0.3,
            evidence: Vec::new(),
            section_entropy: 5.0,
            matching_section: None,
        };
        assert!(!m2.is_confident());
        assert!(!m2.is_high_confidence());
    }

    #[test]
    fn builtin_signatures_count() {
        assert!(builtin_signatures().len() >= 10);
    }

    #[test]
    fn packer_identifier_match_score_entropy_bonus() {
        let sigs = builtin_signatures();
        let lzma = sigs
            .iter()
            .find(|s| s.packer == PackerId::LzmaPacked)
            .unwrap();

        let mut data = vec![0u8; 256];
        data[0..5].copy_from_slice(&[0x5D, 0x00, 0x00, 0x80, 0x00]);

        let score_with_entropy = lzma.match_score(&data, &[], 7.5);
        let score_without_entropy = lzma.match_score(&data, &[], 4.0);

        // Both should match the byte pattern; entropy bonus pushes the first higher.
        assert!(score_with_entropy >= score_without_entropy);
    }
}
