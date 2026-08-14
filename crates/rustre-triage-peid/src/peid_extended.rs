//! `peid_extended` — Extended `PEiD` scanning: EP signatures, section
//! signatures, import-table signatures, signature chaining, and detailed
//! match results.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// EpSignature — entry-point byte pattern
// ---------------------------------------------------------------------------

/// Category of the matched entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureCategory {
    Compiler,
    Packer,
    Protector,
    Runtime,
    Installer,
    Obfuscator,
    Unknown,
}

impl fmt::Display for SignatureCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An entry-point byte-pattern signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpSignature {
    pub name: String,
    pub version: String,
    pub category: SignatureCategory,
    /// Pattern bytes; `None` = wildcard.
    pub pattern: Vec<Option<u8>>,
    /// Confidence score 0–100 when matched.
    pub base_confidence: u8,
    pub description: String,
}

impl EpSignature {
    /// Create a new EP signature.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        category: SignatureCategory,
        pattern: Vec<Option<u8>>,
        base_confidence: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            category,
            pattern,
            base_confidence,
            description: description.into(),
        }
    }

    /// Returns `true` if the pattern matches `data` at `offset`.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        for (i, pat_byte) in self.pattern.iter().enumerate() {
            if let Some(b) = pat_byte
                && data[offset + i] != *b {
                    return false;
                }
        }
        true
    }

    /// Confidence adjusted for pattern specificity (fewer wildcards = higher).
    #[must_use]
    pub fn effective_confidence(&self) -> u8 {
        let len = self.pattern.len();
        if len == 0 {
            return 0;
        }
        let fixed = self.pattern.iter().filter(|b| b.is_some()).count();
        let ratio = fixed as f32 / len as f32;
        ((f32::from(self.base_confidence) * 0.4f32.mul_add(ratio, 0.6)) as u8).min(100)
    }
}

impl fmt::Display for EpSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} ({}%)",
            self.category,
            self.name,
            self.version,
            self.effective_confidence()
        )
    }
}

// ---------------------------------------------------------------------------
// SectionSignature — section-name/characteristic-based detection
// ---------------------------------------------------------------------------

/// Detection logic for section-based matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionMatchMode {
    /// Section name must exactly equal the given string (null-stripped).
    ExactName,
    /// Section name contains the given substring.
    NameContains,
    /// Section has a specific combination of characteristic flags.
    CharacteristicsMatch(u32),
    /// Section entropy is above the given threshold × 10 (stored as u32).
    HighEntropy(u32),
}

/// A signature that detects software based on PE section properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSignature {
    pub name: String,
    pub version: String,
    pub category: SignatureCategory,
    pub mode: SectionMatchMode,
    pub value: String,
    pub base_confidence: u8,
    pub description: String,
}

impl SectionSignature {
    /// Match a single section: `(name, entropy, characteristics)`.
    #[must_use]
    pub fn matches_section(&self, sec_name: &str, entropy: f32, chars: u32) -> bool {
        match &self.mode {
            SectionMatchMode::ExactName => sec_name.trim_matches('\0') == self.value.as_str(),
            SectionMatchMode::NameContains => sec_name.contains(self.value.as_str()),
            SectionMatchMode::CharacteristicsMatch(mask) => (chars & mask) == *mask,
            SectionMatchMode::HighEntropy(threshold) => {
                let thresh = *threshold as f32 / 10.0;
                entropy >= thresh
            }
        }
    }
}

impl fmt::Display for SectionSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} ({}%)",
            self.category, self.name, self.version, self.base_confidence
        )
    }
}

// ---------------------------------------------------------------------------
// ImportSignature — import-table pattern detection
// ---------------------------------------------------------------------------

/// A detection based on the presence of specific imports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSignature {
    pub name: String,
    pub version: String,
    pub category: SignatureCategory,
    /// List of DLL+function pairs that must ALL be present.
    pub required_imports: Vec<(String, String)>,
    /// List of DLL+function pairs where AT LEAST ONE must be present.
    pub any_imports: Vec<(String, String)>,
    pub base_confidence: u8,
    pub description: String,
}

impl ImportSignature {
    /// Check whether the required/any import conditions are satisfied against a
    /// flat list of `(dll, function)` pairs.
    #[must_use]
    pub fn matches_imports(&self, imports: &[(String, String)]) -> bool {
        let imports_lower: Vec<(String, String)> = imports
            .iter()
            .map(|(d, f)| (d.to_lowercase(), f.to_lowercase()))
            .collect();

        let required_ok = self.required_imports.iter().all(|(dll, func)| {
            let dll_l = dll.to_lowercase();
            let func_l = func.to_lowercase();
            imports_lower
                .iter()
                .any(|(d, fn_)| d.contains(&dll_l) && fn_.contains(&func_l))
        });

        if !required_ok {
            return false;
        }

        if self.any_imports.is_empty() {
            return true;
        }

        self.any_imports.iter().any(|(dll, func)| {
            let dll_l = dll.to_lowercase();
            let func_l = func.to_lowercase();
            imports_lower
                .iter()
                .any(|(d, fn_)| d.contains(&dll_l) && fn_.contains(&func_l))
        })
    }
}

// ---------------------------------------------------------------------------
// SignatureChain — multi-stage signature combination
// ---------------------------------------------------------------------------

/// How multiple sub-signatures are combined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainLogic {
    /// All sub-signatures must match.
    All,
    /// At least one sub-signature must match.
    Any,
    /// Exactly N sub-signatures must match.
    AtLeast(usize),
}

/// A signature chain combining EP, section, and import signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureChain {
    pub name: String,
    pub version: String,
    pub category: SignatureCategory,
    pub ep_sigs: Vec<EpSignature>,
    pub section_sigs: Vec<SectionSignature>,
    pub import_sigs: Vec<ImportSignature>,
    pub ep_logic: ChainLogic,
    pub section_logic: ChainLogic,
    pub import_logic: ChainLogic,
    pub base_confidence: u8,
    pub description: String,
}

impl SignatureChain {
    /// Evaluate the chain against PE data components.
    ///
    /// `sections` is a slice of `(name, entropy, characteristics)` tuples.
    /// `imports` is a slice of `(dll, function)` pairs.
    #[must_use]
    pub fn evaluate(
        &self,
        data: &[u8],
        ep_offset: usize,
        sections: &[(String, f32, u32)],
        imports: &[(String, String)],
    ) -> bool {
        // EP check
        let ep_ok = if self.ep_sigs.is_empty() {
            true
        } else {
            let matches: usize = self
                .ep_sigs
                .iter()
                .filter(|s| s.matches_at(data, ep_offset))
                .count();
            match &self.ep_logic {
                ChainLogic::All => matches == self.ep_sigs.len(),
                ChainLogic::Any => matches >= 1,
                ChainLogic::AtLeast(n) => matches >= *n,
            }
        };

        if !ep_ok {
            return false;
        }

        // Section check
        let sec_ok = if self.section_sigs.is_empty() {
            true
        } else {
            let matches: usize = self
                .section_sigs
                .iter()
                .filter(|sig| {
                    sections
                        .iter()
                        .any(|(n, e, c)| sig.matches_section(n, *e, *c))
                })
                .count();
            match &self.section_logic {
                ChainLogic::All => matches == self.section_sigs.len(),
                ChainLogic::Any => matches >= 1,
                ChainLogic::AtLeast(n) => matches >= *n,
            }
        };

        if !sec_ok {
            return false;
        }

        // Import check
        if self.import_sigs.is_empty() {
            return true;
        }
        let matches: usize = self
            .import_sigs
            .iter()
            .filter(|s| s.matches_imports(imports))
            .count();
        match &self.import_logic {
            ChainLogic::All => matches == self.import_sigs.len(),
            ChainLogic::Any => matches >= 1,
            ChainLogic::AtLeast(n) => matches >= *n,
        }
    }
}

// ---------------------------------------------------------------------------
// PeidMatchResult — detailed match result
// ---------------------------------------------------------------------------

/// Detailed result from the extended `PEiD` scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeidMatchResult {
    pub name: String,
    pub version: String,
    pub category: SignatureCategory,
    pub confidence: u8,
    pub match_source: MatchSource,
    pub matched_at_ep: bool,
    pub offset: u64,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// The mechanism that produced this match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchSource {
    EntryPoint,
    Section,
    Import,
    Chain,
    RawScan,
}

impl fmt::Display for PeidMatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {} {} ({}%) via {:?}",
            self.category, self.name, self.version, self.confidence, self.match_source
        )
    }
}

// ---------------------------------------------------------------------------
// PeidExtended — main scanner
// ---------------------------------------------------------------------------

/// The extended `PEiD` scanner.
pub struct PeidExtended {
    ep_sigs: Vec<EpSignature>,
    section_sigs: Vec<SectionSignature>,
    import_sigs: Vec<ImportSignature>,
    chains: Vec<SignatureChain>,
}

impl PeidExtended {
    /// Create an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ep_sigs: Vec::new(),
            section_sigs: Vec::new(),
            import_sigs: Vec::new(),
            chains: Vec::new(),
        }
    }

    /// Create a scanner pre-loaded with built-in signatures.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut scanner = Self::new();
        scanner.load_builtin_ep_sigs();
        scanner.load_builtin_section_sigs();
        scanner.load_builtin_import_sigs();
        scanner.load_builtin_chains();
        scanner
    }

    /// Add an EP signature.
    pub fn add_ep_sig(&mut self, sig: EpSignature) {
        self.ep_sigs.push(sig);
    }

    /// Add a section signature.
    pub fn add_section_sig(&mut self, sig: SectionSignature) {
        self.section_sigs.push(sig);
    }

    /// Add an import signature.
    pub fn add_import_sig(&mut self, sig: ImportSignature) {
        self.import_sigs.push(sig);
    }

    /// Add a signature chain.
    pub fn add_chain(&mut self, chain: SignatureChain) {
        self.chains.push(chain);
    }

    /// Scan raw PE bytes.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<PeidMatchResult> {
        let ep_offset = get_ep_offset(data).unwrap_or(0);
        let sections = get_sections(data);
        let imports = get_imports_flat(data);
        let mut results = Vec::new();

        // EP signature matching
        for sig in &self.ep_sigs {
            if sig.matches_at(data, ep_offset) {
                results.push(PeidMatchResult {
                    name: sig.name.clone(),
                    version: sig.version.clone(),
                    category: sig.category.clone(),
                    confidence: sig.effective_confidence(),
                    match_source: MatchSource::EntryPoint,
                    matched_at_ep: true,
                    offset: ep_offset as u64,
                    description: sig.description.clone(),
                    metadata: HashMap::new(),
                });
            }
        }

        // Section signature matching
        for sig in &self.section_sigs {
            for (sec_name, ent, chars) in &sections {
                if sig.matches_section(sec_name, *ent, *chars) {
                    results.push(PeidMatchResult {
                        name: sig.name.clone(),
                        version: sig.version.clone(),
                        category: sig.category.clone(),
                        confidence: sig.base_confidence,
                        match_source: MatchSource::Section,
                        matched_at_ep: false,
                        offset: 0,
                        description: sig.description.clone(),
                        metadata: HashMap::new(),
                    });
                    break;
                }
            }
        }

        // Import signature matching
        for sig in &self.import_sigs {
            if sig.matches_imports(&imports) {
                results.push(PeidMatchResult {
                    name: sig.name.clone(),
                    version: sig.version.clone(),
                    category: sig.category.clone(),
                    confidence: sig.base_confidence,
                    match_source: MatchSource::Import,
                    matched_at_ep: false,
                    offset: 0,
                    description: sig.description.clone(),
                    metadata: HashMap::new(),
                });
            }
        }

        // Chain matching
        for chain in &self.chains {
            if chain.evaluate(data, ep_offset, &sections, &imports) {
                results.push(PeidMatchResult {
                    name: chain.name.clone(),
                    version: chain.version.clone(),
                    category: chain.category.clone(),
                    confidence: chain.base_confidence,
                    match_source: MatchSource::Chain,
                    matched_at_ep: false,
                    offset: 0,
                    description: chain.description.clone(),
                    metadata: HashMap::new(),
                });
            }
        }

        // Sort by confidence descending
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    fn load_builtin_ep_sigs(&mut self) {
        // UPX 3.x
        self.add_ep_sig(EpSignature::new(
            "UPX",
            "3.x",
            SignatureCategory::Packer,
            vec![
                Some(0x60),
                Some(0xBE),
                None,
                None,
                None,
                None,
                Some(0x8D),
                Some(0xBE),
            ],
            95,
            "UPX packer entry point",
        ));

        // MSVC x86 push ebp / mov ebp, esp
        self.add_ep_sig(EpSignature::new(
            "MSVC",
            "x86",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x8B), Some(0xEC)],
            70,
            "MSVC x86 standard prolog",
        ));

        // MSVC x64 sub rsp
        self.add_ep_sig(EpSignature::new(
            "MSVC",
            "x64",
            SignatureCategory::Compiler,
            vec![Some(0x48), Some(0x83), Some(0xEC)],
            72,
            "MSVC x64 stack frame",
        ));

        // GCC push rbp / mov rbp, rsp
        self.add_ep_sig(EpSignature::new(
            "GCC",
            "x64",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            75,
            "GCC x64 standard prolog",
        ));

        // ASPack 2.12
        self.add_ep_sig(EpSignature::new(
            "ASPack",
            "2.12",
            SignatureCategory::Packer,
            vec![
                Some(0x60),
                Some(0xE8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x5D),
            ],
            92,
            "ASPack packer stub",
        ));

        // Themida
        self.add_ep_sig(EpSignature::new(
            "Themida",
            "2.x",
            SignatureCategory::Protector,
            vec![
                Some(0xE8),
                None,
                None,
                None,
                None,
                Some(0x45),
                Some(0x72),
                Some(0x72),
            ],
            88,
            "Themida protector stub",
        ));
    }

    fn load_builtin_section_sigs(&mut self) {
        self.add_section_sig(SectionSignature {
            name: "UPX".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::NameContains,
            value: "UPX".to_string(),
            base_confidence: 95,
            description: "UPX packer section".to_string(),
        });

        self.add_section_sig(SectionSignature {
            name: "VMProtect".to_string(),
            version: "2.x+".to_string(),
            category: SignatureCategory::Protector,
            mode: SectionMatchMode::NameContains,
            value: ".vmp".to_string(),
            base_confidence: 93,
            description: "VMProtect section".to_string(),
        });

        self.add_section_sig(SectionSignature {
            name: "Themida".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Protector,
            mode: SectionMatchMode::ExactName,
            value: ".themida".to_string(),
            base_confidence: 93,
            description: "Themida section".to_string(),
        });

        self.add_section_sig(SectionSignature {
            name: "HighEntropy".to_string(),
            version: "any".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::HighEntropy(72), // 7.2
            value: String::new(),
            base_confidence: 60,
            description: "High-entropy section (possibly packed)".to_string(),
        });
    }

    fn load_builtin_import_sigs(&mut self) {
        self.add_import_sig(ImportSignature {
            name: "ProcessInjection".to_string(),
            version: "generic".to_string(),
            category: SignatureCategory::Unknown,
            required_imports: vec![
                ("kernel32.dll".to_string(), "VirtualAllocEx".to_string()),
                ("kernel32.dll".to_string(), "WriteProcessMemory".to_string()),
            ],
            any_imports: vec![("kernel32.dll".to_string(), "CreateRemoteThread".to_string())],
            base_confidence: 75,
            description: "Process injection imports".to_string(),
        });

        self.add_import_sig(ImportSignature {
            name: "NetworkActivity".to_string(),
            version: "generic".to_string(),
            category: SignatureCategory::Unknown,
            required_imports: vec![],
            any_imports: vec![
                ("ws2_32.dll".to_string(), "connect".to_string()),
                ("ws2_32.dll".to_string(), "WSAStartup".to_string()),
            ],
            base_confidence: 50,
            description: "Network activity via Winsock".to_string(),
        });
    }

    fn load_builtin_chains(&mut self) {
        // UPX full chain: EP + section
        let upx_ep = EpSignature::new(
            "UPX_EP",
            "3.x",
            SignatureCategory::Packer,
            vec![
                Some(0x60),
                Some(0xBE),
                None,
                None,
                None,
                None,
                Some(0x8D),
                Some(0xBE),
            ],
            95,
            "UPX EP",
        );
        let upx_sec = SectionSignature {
            name: "UPX_SEC".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::NameContains,
            value: "UPX".to_string(),
            base_confidence: 95,
            description: "UPX section".to_string(),
        };
        self.add_chain(SignatureChain {
            name: "UPX".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Packer,
            ep_sigs: vec![upx_ep],
            section_sigs: vec![upx_sec],
            import_sigs: vec![],
            ep_logic: ChainLogic::Any,
            section_logic: ChainLogic::Any,
            import_logic: ChainLogic::Any,
            base_confidence: 97,
            description: "UPX packer (EP + section chain)".to_string(),
        });
    }
}

impl Default for PeidExtended {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PE parsing helpers
// ---------------------------------------------------------------------------

fn get_ep_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_off + 24 > data.len() {
        return None;
    }
    let opt_off = pe_off + 24;
    let ep_rva = u32::from_le_bytes([
        data[opt_off + 16],
        data[opt_off + 17],
        data[opt_off + 18],
        data[opt_off + 19],
    ]);
    let opt_size = u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]) as usize;
    let n_sec = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let sec_tbl = opt_off + opt_size;
    for i in 0..n_sec {
        let s = sec_tbl + i * 40;
        if s + 24 > data.len() {
            break;
        }
        let va = u32::from_le_bytes([data[s + 12], data[s + 13], data[s + 14], data[s + 15]]);
        let vs = u32::from_le_bytes([data[s + 8], data[s + 9], data[s + 10], data[s + 11]]);
        let raw = u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]);
        if ep_rva >= va && ep_rva < va + vs.max(1) {
            return Some(raw as usize + (ep_rva - va) as usize);
        }
    }
    None
}

fn get_sections(data: &[u8]) -> Vec<(String, f32, u32)> {
    let mut sections = Vec::new();
    if data.len() < 0x40 {
        return sections;
    }
    if &data[0..2] != b"MZ" {
        return sections;
    }
    let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_off + 24 > data.len() {
        return sections;
    }
    let opt_off = pe_off + 24;
    let n_sec = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]) as usize;
    let sec_tbl = opt_off + opt_size;
    for i in 0..n_sec {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let name_bytes = &data[s..s + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let raw_size =
            u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]]) as usize;
        let raw_off =
            u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]) as usize;
        let chars = u32::from_le_bytes([data[s + 36], data[s + 37], data[s + 38], data[s + 39]]);
        let ent = if raw_off + raw_size <= data.len() && raw_size > 0 {
            entropy_f32(&data[raw_off..raw_off + raw_size])
        } else {
            0.0
        };
        sections.push((name, ent, chars));
    }
    sections
}

fn get_imports_flat(data: &[u8]) -> Vec<(String, String)> {
    // Simplified: scan for null-terminated strings starting with common DLL names
    let mut imports = Vec::new();
    let dll_patterns: &[&[u8]] = &[
        b"kernel32.dll",
        b"ntdll.dll",
        b"ws2_32.dll",
        b"advapi32.dll",
    ];
    for pat in dll_patterns {
        if data.windows(pat.len()).any(|w| w.eq_ignore_ascii_case(pat)) {
            imports.push((String::from_utf8_lossy(pat).into_owned(), String::new()));
        }
    }
    // Look for known function names in the raw bytes
    let func_patterns: &[(&[u8], &str)] = &[
        (b"VirtualAllocEx", "kernel32.dll"),
        (b"WriteProcessMemory", "kernel32.dll"),
        (b"CreateRemoteThread", "kernel32.dll"),
        (b"WSAStartup", "ws2_32.dll"),
        (b"connect", "ws2_32.dll"),
        (b"RegSetValueEx", "advapi32.dll"),
    ];
    for (func, dll) in func_patterns {
        if data.windows(func.len()).any(|w| w == *func) {
            imports.push((dll.to_string(), String::from_utf8_lossy(func).into_owned()));
        }
    }
    imports
}

fn entropy_f32(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut h = 0.0f32;
    for &f in &freq {
        if f > 0 {
            let p = f as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ep_sig_matches_at_exact() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x8B), Some(0xEC)],
            80,
            "test",
        );
        assert!(sig.matches_at(&[0x55, 0x8B, 0xEC, 0x00], 0));
    }

    #[test]
    fn test_ep_sig_matches_at_wildcard() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Packer,
            vec![Some(0x60), None, None, Some(0xBE)],
            80,
            "test",
        );
        assert!(sig.matches_at(&[0x60, 0xAB, 0xCD, 0xBE], 0));
    }

    #[test]
    fn test_ep_sig_no_match() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x8B)],
            80,
            "test",
        );
        assert!(!sig.matches_at(&[0x48, 0x83], 0));
    }

    #[test]
    fn test_ep_sig_out_of_bounds() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x8B), Some(0xEC)],
            80,
            "test",
        );
        assert!(!sig.matches_at(&[0x55], 0));
    }

    #[test]
    fn test_ep_sig_effective_confidence_all_fixed() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Compiler,
            vec![Some(0x55), Some(0x8B), Some(0xEC), Some(0x10)],
            80,
            "test",
        );
        assert_eq!(sig.effective_confidence(), 80);
    }

    #[test]
    fn test_ep_sig_effective_confidence_wildcards() {
        let sig = EpSignature::new(
            "Test",
            "1.0",
            SignatureCategory::Packer,
            vec![Some(0x60), None, None, None],
            80,
            "test",
        );
        // 1/4 fixed → lower confidence
        assert!(sig.effective_confidence() < 80);
    }

    #[test]
    fn test_ep_sig_display() {
        let sig = EpSignature::new(
            "UPX",
            "3.x",
            SignatureCategory::Packer,
            vec![Some(0x60)],
            95,
            "test",
        );
        let s = sig.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("Packer"));
    }

    #[test]
    fn test_section_sig_exact_name_match() {
        let sig = SectionSignature {
            name: "UPX".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::ExactName,
            value: "UPX0".to_string(),
            base_confidence: 95,
            description: String::new(),
        };
        assert!(sig.matches_section("UPX0", 7.5, 0));
        assert!(!sig.matches_section(".text", 5.0, 0));
    }

    #[test]
    fn test_section_sig_name_contains() {
        let sig = SectionSignature {
            name: "VMProtect".to_string(),
            version: "2.x".to_string(),
            category: SignatureCategory::Protector,
            mode: SectionMatchMode::NameContains,
            value: ".vmp".to_string(),
            base_confidence: 93,
            description: String::new(),
        };
        assert!(sig.matches_section(".vmp0", 6.0, 0));
        assert!(!sig.matches_section(".text", 5.0, 0));
    }

    #[test]
    fn test_section_sig_high_entropy() {
        let sig = SectionSignature {
            name: "HighEnt".to_string(),
            version: "any".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::HighEntropy(72),
            value: String::new(),
            base_confidence: 60,
            description: String::new(),
        };
        assert!(sig.matches_section(".text", 7.5, 0));
        assert!(!sig.matches_section(".text", 5.0, 0));
    }

    #[test]
    fn test_section_sig_characteristics() {
        let sig = SectionSignature {
            name: "WX".to_string(),
            version: "any".to_string(),
            category: SignatureCategory::Packer,
            mode: SectionMatchMode::CharacteristicsMatch(0x80000020),
            value: String::new(),
            base_confidence: 80,
            description: String::new(),
        };
        assert!(sig.matches_section(".text", 5.0, 0x80000020));
        assert!(!sig.matches_section(".text", 5.0, 0x40000020));
    }

    #[test]
    fn test_import_sig_matches() {
        let sig = ImportSignature {
            name: "Injection".to_string(),
            version: "any".to_string(),
            category: SignatureCategory::Unknown,
            required_imports: vec![("kernel32.dll".to_string(), "VirtualAllocEx".to_string())],
            any_imports: vec![],
            base_confidence: 75,
            description: String::new(),
        };
        let imports = vec![("kernel32.dll".to_string(), "VirtualAllocEx".to_string())];
        assert!(sig.matches_imports(&imports));
    }

    #[test]
    fn test_import_sig_no_match() {
        let sig = ImportSignature {
            name: "Injection".to_string(),
            version: "any".to_string(),
            category: SignatureCategory::Unknown,
            required_imports: vec![("kernel32.dll".to_string(), "VirtualAllocEx".to_string())],
            any_imports: vec![],
            base_confidence: 75,
            description: String::new(),
        };
        let imports = vec![("ntdll.dll".to_string(), "NtClose".to_string())];
        assert!(!sig.matches_imports(&imports));
    }

    #[test]
    fn test_peid_extended_with_builtins_no_panic() {
        let scanner = PeidExtended::with_builtins();
        let data = b"MZ not a real PE but should not panic";
        let _ = scanner.scan(data);
    }

    #[test]
    fn test_peid_extended_scan_upx_pattern() {
        let scanner = PeidExtended::with_builtins();
        // Craft a tiny buffer with UPX EP bytes at offset 0
        let mut data = vec![0u8; 64];
        data[0] = 0x60;
        data[1] = 0xBE;
        data[2] = 0x00;
        data[3] = 0x10;
        data[4] = 0x40;
        data[5] = 0x00;
        data[6] = 0x8D;
        data[7] = 0xBE;
        // EP is at offset 0 for this tiny buffer
        let results = scanner.ep_sigs[0].matches_at(&data, 0);
        assert!(results);
    }

    #[test]
    fn test_peid_match_result_display() {
        let m = PeidMatchResult {
            name: "UPX".to_string(),
            version: "3.x".to_string(),
            category: SignatureCategory::Packer,
            confidence: 95,
            match_source: MatchSource::EntryPoint,
            matched_at_ep: true,
            offset: 0x1000,
            description: "UPX packer".to_string(),
            metadata: HashMap::new(),
        };
        let s = m.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("EntryPoint"));
    }

    #[test]
    fn test_chain_logic_all() {
        let chain = SignatureChain {
            name: "Test".to_string(),
            version: "1.0".to_string(),
            category: SignatureCategory::Packer,
            ep_sigs: vec![],
            section_sigs: vec![SectionSignature {
                name: "s".to_string(),
                version: "v".to_string(),
                category: SignatureCategory::Packer,
                mode: SectionMatchMode::NameContains,
                value: "UPX".to_string(),
                base_confidence: 90,
                description: String::new(),
            }],
            import_sigs: vec![],
            ep_logic: ChainLogic::Any,
            section_logic: ChainLogic::All,
            import_logic: ChainLogic::Any,
            base_confidence: 90,
            description: String::new(),
        };
        let sections = vec![("UPX0".to_string(), 5.0f32, 0u32)];
        assert!(chain.evaluate(&[], 0, &sections, &[]));
        let no_match_sections = vec![(".text".to_string(), 5.0f32, 0u32)];
        assert!(!chain.evaluate(&[], 0, &no_match_sections, &[]));
    }

    #[test]
    fn test_signature_category_display() {
        assert_eq!(SignatureCategory::Compiler.to_string(), "Compiler");
        assert_eq!(SignatureCategory::Packer.to_string(), "Packer");
    }

    #[test]
    fn test_entropy_f32_uniform() {
        let data = vec![0xABu8; 256];
        let e = entropy_f32(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_entropy_f32_max() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = entropy_f32(&data);
        assert!(e > 7.9);
    }
}
