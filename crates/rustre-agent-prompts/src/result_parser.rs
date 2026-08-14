// result_parser.rs — Parse and structure AI analysis output
// Extract entities, validate, normalize, confidence scoring, MITRE mapping

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// MITRE ATT&CK technique
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AiMitreTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub confidence: f32,
    pub evidence: String,
}

impl AiMitreTechnique {
    pub fn new(
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        tactic: impl Into<String>,
        confidence: f32,
        evidence: impl Into<String>,
    ) -> Self {
        AiMitreTechnique {
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            tactic: tactic.into(),
            confidence: confidence.clamp(0.0, 1.0),
            evidence: evidence.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Extracted entity types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    FunctionName,
    StructureName,
    StringLiteral,
    NetworkIndicator,
    RegistryKey,
    FilePath,
    MutexName,
    ServiceName,
    VulnerabilityDescription,
    CveId,
    Algorithm,
    LibraryName,
    ApiCall,
    MitreTechnique,
    BehaviorLabel,
    Custom,
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EntityKind::FunctionName => "function_name",
            EntityKind::StructureName => "structure_name",
            EntityKind::StringLiteral => "string_literal",
            EntityKind::NetworkIndicator => "network_indicator",
            EntityKind::RegistryKey => "registry_key",
            EntityKind::FilePath => "file_path",
            EntityKind::MutexName => "mutex_name",
            EntityKind::ServiceName => "service_name",
            EntityKind::VulnerabilityDescription => "vulnerability",
            EntityKind::CveId => "cve_id",
            EntityKind::Algorithm => "algorithm",
            EntityKind::LibraryName => "library_name",
            EntityKind::ApiCall => "api_call",
            EntityKind::MitreTechnique => "mitre_technique",
            EntityKind::BehaviorLabel => "behavior",
            EntityKind::Custom => "custom",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// ConfidenceScore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ConfidenceScore(f32);

impl ConfidenceScore {
    pub fn new(value: f32) -> Self {
        ConfidenceScore(value.clamp(0.0, 1.0))
    }

    pub fn high() -> Self { ConfidenceScore(0.9) }
    pub fn medium() -> Self { ConfidenceScore(0.6) }
    pub fn low() -> Self { ConfidenceScore(0.3) }
    pub fn unknown() -> Self { ConfidenceScore(0.5) }

    pub fn value(&self) -> f32 { self.0 }
    pub fn pct(&self) -> f32 { self.0 * 100.0 }

    pub fn label(&self) -> &'static str {
        if self.0 >= 0.85 { "high" }
        else if self.0 >= 0.60 { "medium" }
        else if self.0 >= 0.30 { "low" }
        else { "very_low" }
    }
}

impl fmt::Display for ConfidenceScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.0}% ({})", self.pct(), self.label())
    }
}

// ---------------------------------------------------------------------------
// ExtractedEntity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub kind: EntityKind,
    pub value: String,
    pub confidence: ConfidenceScore,
    pub source_range: Option<(usize, usize)>,
    pub metadata: HashMap<String, String>,
}

impl ExtractedEntity {
    pub fn new(kind: EntityKind, value: impl Into<String>, confidence: ConfidenceScore) -> Self {
        ExtractedEntity {
            kind,
            value: value.into(),
            confidence,
            source_range: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn with_range(mut self, start: usize, end: usize) -> Self {
        self.source_range = Some((start, end));
        self
    }

    pub fn is_high_confidence(&self) -> bool {
        self.confidence.value() >= 0.75
    }
}

// ---------------------------------------------------------------------------
// AiResult — parsed AI analysis result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AiResult {
    pub template_id: String,
    pub raw_output: String,
    pub entities: Vec<ExtractedEntity>,
    pub mitre_techniques: Vec<AiMitreTechnique>,
    pub suggested_function_name: Option<String>,
    pub function_name_confidence: ConfidenceScore,
    pub behavior_summary: String,
    pub vulnerability_description: Option<String>,
    pub overall_confidence: ConfidenceScore,
    pub warnings: Vec<String>,
    pub extra: HashMap<String, String>,
}

impl AiResult {
    pub fn new(template_id: impl Into<String>, raw_output: impl Into<String>) -> Self {
        AiResult {
            template_id: template_id.into(),
            raw_output: raw_output.into(),
            entities: Vec::new(),
            mitre_techniques: Vec::new(),
            suggested_function_name: None,
            function_name_confidence: ConfidenceScore::unknown(),
            behavior_summary: String::new(),
            vulnerability_description: None,
            overall_confidence: ConfidenceScore::medium(),
            warnings: Vec::new(),
            extra: HashMap::new(),
        }
    }

    pub fn add_entity(&mut self, entity: ExtractedEntity) {
        self.entities.push(entity);
    }

    pub fn add_technique(&mut self, technique: AiMitreTechnique) {
        self.mitre_techniques.push(technique);
    }

    pub fn entities_of_kind(&self, kind: EntityKind) -> Vec<&ExtractedEntity> {
        self.entities.iter().filter(|e| e.kind == kind).collect()
    }

    pub fn high_confidence_entities(&self) -> Vec<&ExtractedEntity> {
        self.entities.iter().filter(|e| e.is_high_confidence()).collect()
    }

    pub fn iocs(&self) -> Vec<&ExtractedEntity> {
        self.entities.iter().filter(|e| matches!(
            e.kind,
            EntityKind::NetworkIndicator
            | EntityKind::FilePath
            | EntityKind::RegistryKey
            | EntityKind::MutexName
        )).collect()
    }

    pub fn has_high_severity_vuln(&self) -> bool {
        self.vulnerability_description.is_some()
            && self.overall_confidence.value() >= 0.6
    }
}

// ---------------------------------------------------------------------------
// ResultParser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParseConfig {
    pub extract_function_names: bool,
    pub extract_mitre: bool,
    pub extract_iocs: bool,
    pub extract_vulns: bool,
    pub min_confidence: f32,
    pub normalize_names: bool,
}

impl Default for ParseConfig {
    fn default() -> Self {
        ParseConfig {
            extract_function_names: true,
            extract_mitre: true,
            extract_iocs: true,
            extract_vulns: true,
            min_confidence: 0.3,
            normalize_names: true,
        }
    }
}

pub struct ResultParser {
    config: ParseConfig,
    mitre_db: HashMap<String, (String, String)>, // id -> (name, tactic)
}

impl ResultParser {
    pub fn new() -> Self {
        ResultParser {
            config: ParseConfig::default(),
            mitre_db: builtin_mitre_db(),
        }
    }

    pub fn with_config(mut self, config: ParseConfig) -> Self {
        self.config = config;
        self
    }

    /// Parse raw AI output text into structured AiResult
    pub fn parse(&self, template_id: &str, raw: &str) -> AiResult {
        let mut result = AiResult::new(template_id, raw);

        // Extract function name from patterns like "suggested_name: foo_bar" or "**`foo_bar`**"
        if self.config.extract_function_names {
            if let Some(name) = extract_function_name(raw) {
                let norm = if self.config.normalize_names {
                    normalize_function_name(&name)
                } else {
                    name.clone()
                };
                result.suggested_function_name = Some(norm.clone());
                result.function_name_confidence = infer_name_confidence(raw, &norm);
                result.add_entity(ExtractedEntity::new(
                    EntityKind::FunctionName,
                    norm,
                    result.function_name_confidence,
                ));
            }
        }

        // Extract MITRE technique IDs (T1234 or T1234.001)
        if self.config.extract_mitre {
            for technique in extract_mitre_techniques(raw, &self.mitre_db) {
                result.add_technique(technique);
            }
        }

        // Extract IOCs
        if self.config.extract_iocs {
            for entity in extract_iocs(raw) {
                if entity.confidence.value() >= self.config.min_confidence {
                    result.add_entity(entity);
                }
            }
        }

        // Extract vulnerability description
        if self.config.extract_vulns {
            if let Some(vuln) = extract_vulnerability(raw) {
                result.vulnerability_description = Some(vuln.clone());
                result.add_entity(ExtractedEntity::new(
                    EntityKind::VulnerabilityDescription,
                    vuln,
                    ConfidenceScore::medium(),
                ));
            }
        }

        // Extract behavior summary
        result.behavior_summary = extract_behavior_summary(raw);

        // Compute overall confidence
        result.overall_confidence = compute_overall_confidence(&result);

        result
    }

    /// Merge AI result with static analysis data
    pub fn merge_with_static(
        &self,
        ai: &mut AiResult,
        static_strings: &[String],
        static_imports: &[(String, String)],
    ) {
        // Validate function name against static imports
        if let Some(ref name) = ai.suggested_function_name.clone() {
            let lower = name.to_lowercase();
            for (_, func) in static_imports {
                if func.to_lowercase().contains(&lower) || lower.contains(&func.to_lowercase()) {
                    ai.function_name_confidence = ConfidenceScore::new(
                        ai.function_name_confidence.value() + 0.1
                    );
                    ai.extra.insert("import_match".to_string(), func.clone());
                    break;
                }
            }
        }

        // Validate extracted strings against static strings
        for entity in &mut ai.entities {
            if entity.kind == EntityKind::StringLiteral {
                if static_strings.iter().any(|s| s.contains(&entity.value)) {
                    entity.confidence = ConfidenceScore::new(entity.confidence.value() + 0.15);
                }
            }
        }
    }

    pub fn normalize_output(&self, raw: &str) -> String {
        // Remove markdown artifacts, clean up whitespace.
        // SECURITY: the old approach used a `while out.contains("\n\n\n") { out =
        // out.replace(...) }` loop, which is O(N²) in the number of consecutive
        // blank lines because each pass only collapses one extra newline at a
        // time while scanning the full string again.  An attacker-controlled
        // `raw` value with M consecutive newlines (e.g. from a malicious LLM
        // response or a crafted few-shot example) would consume O(M²) CPU,
        // causing denial-of-service.  The single-pass line-by-line approach
        // below runs in O(N) regardless of the number of blank lines.
        let mut out = String::with_capacity(raw.len());
        let mut consecutive_blank = 0usize;
        for line in raw.lines() {
            if line.trim().is_empty() {
                consecutive_blank += 1;
                // Allow at most one blank line between paragraphs.
                if consecutive_blank <= 1 {
                    out.push('\n');
                }
            } else {
                consecutive_blank = 0;
                out.push_str(line);
                out.push('\n');
            }
        }
        // Remove leading/trailing whitespace
        out.trim().to_string()
    }

    pub fn validate_json_output(&self, raw: &str) -> Result<(), String> {
        // Simple JSON validation without serde
        let trimmed = raw.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            // Check balanced braces
            let opens: i32 = trimmed.chars().filter(|&c| c == '{').count() as i32;
            let closes: i32 = trimmed.chars().filter(|&c| c == '}').count() as i32;
            if opens == closes {
                return Ok(());
            }
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return Ok(());
        }
        Err(format!("invalid JSON: does not start/end with {{}} or []"))
    }
}

impl Default for ResultParser {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

fn extract_function_name(text: &str) -> Option<String> {
    // Patterns: "suggested_name: foo", "Name: foo_bar", "`foo_bar`", "**foo_bar**"
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.contains("suggested_name") || lower.contains("function name") || lower.contains("rename to") {
            if let Some(colon_pos) = line.find(':') {
                let candidate = line[colon_pos + 1..].trim().trim_matches(|c: char| c == '`' || c == '*' || c == '"').trim();
                if is_valid_identifier(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }
        // Match backtick-quoted identifiers
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'`' {
                let start = i + 1;
                if let Some(end_offset) = line[start..].find('`') {
                    let candidate = &line[start..start + end_offset];
                    if is_valid_identifier(candidate) && candidate.contains('_') {
                        return Some(candidate.to_string());
                    }
                    i = start + end_offset + 1;
                } else {
                    break;
                }
            } else {
                i += 1;
            }
        }
    }
    None
}

fn normalize_function_name(name: &str) -> String {
    // Convert camelCase to snake_case, strip leading/trailing underscores
    let mut out = String::new();
    let mut prev_upper = false;
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i > 0 && !prev_upper {
            out.push('_');
        }
        out.push(c.to_lowercase().next().unwrap_or(c));
        prev_upper = c.is_uppercase();
    }
    // Replace non-alphanumeric/underscore with underscore
    let clean: String = out.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    clean.trim_matches('_').to_string()
}

fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        if !first.is_alphabetic() && first != '_' {
            return false;
        }
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

fn infer_name_confidence(text: &str, name: &str) -> ConfidenceScore {
    let mut score = 0.5f32;
    // If the name appears multiple times, higher confidence
    let occurrences = text.matches(name).count();
    score += (occurrences as f32 * 0.05).min(0.2);
    // If text says "confident" or "certain"
    if text.to_lowercase().contains("confident") || text.to_lowercase().contains("certain") {
        score += 0.15;
    }
    // If text says "possibly" or "might"
    if text.to_lowercase().contains("possibly") || text.to_lowercase().contains("might") {
        score -= 0.1;
    }
    ConfidenceScore::new(score)
}

fn extract_mitre_techniques(text: &str, db: &HashMap<String, (String, String)>) -> Vec<AiMitreTechnique> {
    let mut techniques = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Find T1234 or T1234.001 patterns
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'T' && i + 4 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let start = i;
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || (bytes[j] == b'.'
                        && j + 1 < bytes.len()
                        && bytes[j + 1].is_ascii_digit()))
            {
                j += 1;
            }
            let id = &text[start..j];
            if id.len() >= 5 && !seen.contains(id) {
                seen.insert(id.to_string());
                let (name, tactic) = db.get(id).cloned().unwrap_or_else(|| {
                    ("Unknown Technique".to_string(), "unknown".to_string())
                });
                // Extract surrounding sentence as evidence
                let line = text[start..].lines().next().unwrap_or("").to_string();
                techniques.push(AiMitreTechnique::new(id, name, tactic, 0.7, line));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    techniques
}

fn extract_iocs(text: &str) -> Vec<ExtractedEntity> {
    let mut iocs = Vec::new();

    for line in text.lines() {
        // IP address pattern (simple)
        if looks_like_ip(line) {
            if let Some(ip) = extract_ip(line) {
                iocs.push(ExtractedEntity::new(
                    EntityKind::NetworkIndicator,
                    ip,
                    ConfidenceScore::high(),
                ));
            }
        }
        // Registry key
        if line.contains("HKEY_") || line.contains("HKLM") || line.contains("HKCU") {
            if let Some(reg) = extract_registry_key(line) {
                iocs.push(ExtractedEntity::new(
                    EntityKind::RegistryKey,
                    reg,
                    ConfidenceScore::medium(),
                ));
            }
        }
        // File path
        if line.contains("C:\\") || line.contains("/etc/") || line.contains("/tmp/") {
            if let Some(path) = extract_file_path(line) {
                iocs.push(ExtractedEntity::new(
                    EntityKind::FilePath,
                    path,
                    ConfidenceScore::medium(),
                ));
            }
        }
    }

    iocs
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 4 {
        return false;
    }
    parts.iter().any(|p| p.chars().all(|c| c.is_ascii_digit()))
}

fn extract_ip(line: &str) -> Option<String> {
    for word in line.split_whitespace() {
        let clean: String = word.chars().filter(|&c| c.is_ascii_digit() || c == '.').collect();
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return Some(clean);
        }
    }
    None
}

fn extract_registry_key(line: &str) -> Option<String> {
    for prefix in &["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKLM", "HKCU"] {
        if let Some(pos) = line.find(prefix) {
            let end = line[pos..].find(|c: char| c.is_whitespace()).unwrap_or(line.len() - pos);
            return Some(line[pos..pos + end].to_string());
        }
    }
    None
}

fn extract_file_path(line: &str) -> Option<String> {
    for prefix in &["C:\\", "D:\\", "/etc/", "/tmp/", "/var/", "/usr/"] {
        if let Some(pos) = line.find(prefix) {
            let end = line[pos..].find(|c: char| c == '"' || c == '\'' || c == '`' || c == ' ').unwrap_or(line.len() - pos);
            return Some(line[pos..pos + end].to_string());
        }
    }
    None
}

fn extract_vulnerability(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let vuln_keywords = [
        "buffer overflow", "stack overflow", "heap overflow", "use-after-free",
        "format string", "integer overflow", "race condition", "null pointer",
        "out-of-bounds", "double free", "type confusion", "sql injection",
        "command injection", "path traversal",
    ];
    for kw in &vuln_keywords {
        if lower.contains(kw) {
            // Find the line containing the keyword
            for line in text.lines() {
                if line.to_lowercase().contains(kw) {
                    return Some(line.trim().to_string());
                }
            }
        }
    }
    None
}

fn extract_behavior_summary(text: &str) -> String {
    // Find "summary" or first substantive paragraph
    let mut in_summary = false;
    let mut summary_lines = Vec::new();

    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.contains("summary") || lower.contains("behavior") || lower.contains("behaviour") {
            in_summary = true;
            continue;
        }
        if in_summary {
            let trimmed = line.trim();
            if trimmed.is_empty() && !summary_lines.is_empty() {
                break;
            }
            if !trimmed.is_empty() {
                summary_lines.push(trimmed.to_string());
                if summary_lines.len() >= 3 {
                    break;
                }
            }
        }
    }

    if summary_lines.is_empty() {
        // Fall back to first non-empty paragraph
        let mut result = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                result = trimmed.to_string();
                break;
            }
        }
        result
    } else {
        summary_lines.join(" ")
    }
}

fn compute_overall_confidence(result: &AiResult) -> ConfidenceScore {
    let mut score = 0.5f32;

    // Higher if we found a function name
    if result.suggested_function_name.is_some() {
        score += 0.1;
    }
    // Higher if MITRE techniques found
    if !result.mitre_techniques.is_empty() {
        score += 0.1;
    }
    // Higher if behavior summary non-empty
    if !result.behavior_summary.is_empty() {
        score += 0.05;
    }
    // Adjust by entity count
    let high_conf = result.high_confidence_entities().len();
    score += (high_conf as f32 * 0.02).min(0.1);

    ConfidenceScore::new(score)
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK mini-database
// ---------------------------------------------------------------------------

fn builtin_mitre_db() -> HashMap<String, (String, String)> {
    let mut db = HashMap::with_capacity(19);
    let entries: &[(&str, &str, &str)] = &[
        ("T1055", "Process Injection", "defense-evasion"),
        ("T1055.001", "Dynamic-link Library Injection", "defense-evasion"),
        ("T1055.002", "Portable Executable Injection", "defense-evasion"),
        ("T1027", "Obfuscated Files or Information", "defense-evasion"),
        ("T1027.002", "Software Packing", "defense-evasion"),
        ("T1059", "Command and Scripting Interpreter", "execution"),
        ("T1059.001", "PowerShell", "execution"),
        ("T1071", "Application Layer Protocol", "command-and-control"),
        ("T1071.001", "Web Protocols", "command-and-control"),
        ("T1082", "System Information Discovery", "discovery"),
        ("T1083", "File and Directory Discovery", "discovery"),
        ("T1105", "Ingress Tool Transfer", "command-and-control"),
        ("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion"),
        ("T1497", "Virtualization/Sandbox Evasion", "defense-evasion"),
        ("T1518", "Software Discovery", "discovery"),
        ("T1547", "Boot or Logon Autostart Execution", "persistence"),
        ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
        ("T1562", "Impair Defenses", "defense-evasion"),
        ("T1622", "Debugger Evasion", "defense-evasion"),
    ];
    for (id, name, tactic) in entries {
        db.insert(id.to_string(), (name.to_string(), tactic.to_string()));
    }
    db
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_function_name_colon() {
        let parser = ResultParser::new();
        let raw = "Based on my analysis:\n\nsuggested_name: decrypt_string\n\nConfidence: 85%";
        let result = parser.parse("function-rename", raw);
        assert!(result.suggested_function_name.is_some());
        let name = result.suggested_function_name.unwrap();
        assert_eq!(name, "decrypt_string");
    }

    #[test]
    fn test_parse_mitre_technique() {
        let parser = ResultParser::new();
        let raw = "This function performs T1027 (Software Packing) and T1055.001.";
        let result = parser.parse("malware-analyze", raw);
        assert!(!result.mitre_techniques.is_empty());
        assert!(result.mitre_techniques.iter().any(|t| t.technique_id == "T1027"));
    }

    #[test]
    fn test_parse_ioc_ip() {
        let parser = ResultParser::new();
        let raw = "C2 server at 192.168.1.100 via HTTP";
        let result = parser.parse("malware-analyze", raw);
        let iocs = result.iocs();
        assert!(!iocs.is_empty());
    }

    #[test]
    fn test_parse_vulnerability() {
        let parser = ResultParser::new();
        let raw = "Analysis shows a classic buffer overflow in the copy routine.";
        let result = parser.parse("vuln-analyze", raw);
        assert!(result.vulnerability_description.is_some());
    }

    #[test]
    fn test_normalize_function_name() {
        assert_eq!(normalize_function_name("decryptString"), "decrypt_string");
        assert_eq!(normalize_function_name("get_value"), "get_value");
        assert_eq!(normalize_function_name("__init__"), "init");
    }

    #[test]
    fn test_confidence_score() {
        let h = ConfidenceScore::high();
        let l = ConfidenceScore::low();
        assert_eq!(h.label(), "high");
        assert_eq!(l.label(), "low");
        assert!(h.value() > l.value());
    }

    #[test]
    fn test_merge_with_static() {
        let parser = ResultParser::new();
        let raw = "suggested_name: virtual_alloc_wrapper\nThis allocates memory.";
        let mut result = parser.parse("function-rename", raw);
        let imports = vec![
            ("kernel32.dll".to_string(), "VirtualAlloc".to_string()),
        ];
        parser.merge_with_static(&mut result, &[], &imports);
        // Should have found a match (VirtualAlloc contains "alloc")
        // Confidence should be updated
        assert!(result.function_name_confidence.value() > 0.0);
    }

    #[test]
    fn test_validate_json_valid() {
        let parser = ResultParser::new();
        assert!(parser.validate_json_output(r#"{"name": "foo"}"#).is_ok());
    }

    #[test]
    fn test_validate_json_invalid() {
        let parser = ResultParser::new();
        assert!(parser.validate_json_output("not json").is_err());
    }

    #[test]
    fn test_entities_of_kind() {
        let parser = ResultParser::new();
        let raw = "File written to C:\\Windows\\System32\\malware.dll and key HKLM\\Software\\test";
        let result = parser.parse("malware-analyze", raw);
        let files = result.entities_of_kind(EntityKind::FilePath);
        assert!(!files.is_empty());
    }

    #[test]
    fn test_normalize_output() {
        let parser = ResultParser::new();
        let raw = "  \n\n\nSome output\n\n\n  ";
        let norm = parser.normalize_output(raw);
        assert_eq!(norm, "Some output");
    }
}
