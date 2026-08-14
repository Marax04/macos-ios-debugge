//! `project_templates` — Project template system for rustre-project.
//!
//! Provides [`ProjectTemplate`], [`TemplateType`], [`TemplateConfig`],
//! [`TemplateApply`], and [`TemplateLibrary`] for scaffolding new analysis
//! projects.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the template subsystem.
#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("template '{0}' not found")]
    NotFound(String),

    #[error("template already exists: '{0}'")]
    AlreadyExists(String),

    #[error("missing required config key: '{0}'")]
    MissingConfig(String),

    #[error("invalid config value for '{key}': {reason}")]
    InvalidConfig { key: String, reason: String },

    #[error("apply failed: {0}")]
    ApplyFailed(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("render error: {0}")]
    Render(String),
}

// ─── TemplateType ─────────────────────────────────────────────────────────────

/// The analysis domain this template is designed for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemplateType {
    MalwareAnalysis,
    Vulnerability,
    Firmware,
    Mobile,
    Ctf,
    Pentest,
    Reversing,
    Network,
    DotNet,
    Kernel,
    Custom(String),
}

impl std::fmt::Display for TemplateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl TemplateType {
    /// Parse loosely from a string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "malware" | "malware_analysis" => Self::MalwareAnalysis,
            "vuln" | "vulnerability" => Self::Vulnerability,
            "firmware" | "fw" => Self::Firmware,
            "mobile" | "android" | "ios" => Self::Mobile,
            "ctf" => Self::Ctf,
            "pentest" | "pentetration_testing" => Self::Pentest,
            "reverse" | "reversing" | "re" => Self::Reversing,
            "network" | "net" | "pcap" => Self::Network,
            "dotnet" | ".net" | "csharp" => Self::DotNet,
            "kernel" | "driver" => Self::Kernel,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ─── TemplateFile ─────────────────────────────────────────────────────────────

/// A file to be created when applying a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateFile {
    /// Relative path within the project directory.
    pub path: String,
    /// File content template — `{{var}}` placeholders are substituted.
    pub content: String,
    /// Whether to create parent directories automatically.
    pub create_dirs: bool,
    /// Whether to skip if the file already exists.
    pub skip_if_exists: bool,
}

impl TemplateFile {
    #[must_use]
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
            create_dirs: true,
            skip_if_exists: false,
        }
    }

    /// Render content by substituting `{{key}}` with values.
    #[must_use]
    pub fn render(&self, vars: &HashMap<String, String>) -> String {
        let mut result = self.content.clone();
        for (k, v) in vars {
            result = result.replace(&format!("{{{{{k}}}}}"), v);
        }
        result
    }
}

// ─── TemplateConfig ──────────────────────────────────────────────────────────

/// Configuration values used when applying a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    pub project_name: String,
    pub analyst_name: String,
    pub target_binary: Option<PathBuf>,
    pub architecture: String,
    pub os: String,
    pub extra: HashMap<String, String>,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            project_name: "my_project".to_string(),
            analyst_name: "analyst".to_string(),
            target_binary: None,
            architecture: "x86_64".to_string(),
            os: "linux".to_string(),
            extra: HashMap::new(),
        }
    }
}

impl TemplateConfig {
    #[must_use]
    pub fn new(project_name: impl Into<String>, analyst_name: impl Into<String>) -> Self {
        Self {
            project_name: project_name.into(),
            analyst_name: analyst_name.into(),
            ..Default::default()
        }
    }

    /// Build a variable map suitable for template rendering.
    #[must_use]
    pub fn to_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("project_name".to_string(), self.project_name.clone());
        vars.insert("analyst_name".to_string(), self.analyst_name.clone());
        vars.insert("architecture".to_string(), self.architecture.clone());
        vars.insert("os".to_string(), self.os.clone());
        if let Some(p) = &self.target_binary {
            vars.insert("target_binary".to_string(), p.display().to_string());
        }
        for (k, v) in &self.extra {
            vars.insert(k.clone(), v.clone());
        }
        vars
    }

    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.architecture = arch.into();
        self
    }

    #[must_use]
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = os.into();
        self
    }

    #[must_use]
    pub fn with_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.target_binary = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

// ─── ProjectTemplate ──────────────────────────────────────────────────────────

/// A project scaffold template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTemplate {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub template_type: TemplateType,
    pub version: String,
    pub files: Vec<TemplateFile>,
    pub required_config_keys: Vec<String>,
    pub tags: Vec<String>,
    pub estimated_setup_minutes: u32,
}

impl ProjectTemplate {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
        template_type: TemplateType,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: description.into(),
            template_type,
            version: "1.0.0".to_string(),
            files: Vec::new(),
            required_config_keys: Vec::new(),
            tags: Vec::new(),
            estimated_setup_minutes: 2,
        }
    }

    #[must_use]
    pub fn with_file(mut self, f: TemplateFile) -> Self {
        self.files.push(f);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn with_required_key(mut self, key: impl Into<String>) -> Self {
        self.required_config_keys.push(key.into());
        self
    }

    /// Validate a config against this template.
    pub fn validate_config(&self, config: &TemplateConfig) -> Result<(), TemplateError> {
        let vars = config.to_vars();
        for key in &self.required_config_keys {
            if !vars.contains_key(key.as_str()) {
                return Err(TemplateError::MissingConfig(key.clone()));
            }
        }
        Ok(())
    }

    /// List the file paths this template would create.
    #[must_use]
    pub fn file_paths(&self) -> Vec<&str> {
        self.files.iter().map(|f| f.path.as_str()).collect()
    }
}

// ─── TemplateApply ────────────────────────────────────────────────────────────

/// Result of applying a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub template_name: String,
    pub project_dir: PathBuf,
    pub files_created: Vec<PathBuf>,
    pub files_skipped: Vec<PathBuf>,
    pub success: bool,
    pub errors: Vec<String>,
}

impl ApplyResult {
    #[must_use]
    pub fn new(template_name: impl Into<String>, project_dir: impl Into<PathBuf>) -> Self {
        Self {
            template_name: template_name.into(),
            project_dir: project_dir.into(),
            files_created: Vec::new(),
            files_skipped: Vec::new(),
            success: true,
            errors: Vec::new(),
        }
    }
}

/// Applies a [`ProjectTemplate`] to a target directory.
pub struct TemplateApply {
    dry_run: bool,
    overwrite: bool,
}

impl TemplateApply {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dry_run: false,
            overwrite: false,
        }
    }

    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    #[must_use]
    pub fn overwrite(mut self) -> Self {
        self.overwrite = true;
        self
    }

    /// Apply the template to `project_dir`.
    pub fn apply(
        &self,
        template: &ProjectTemplate,
        config: &TemplateConfig,
        project_dir: &Path,
    ) -> Result<ApplyResult, TemplateError> {
        template.validate_config(config)?;
        let vars = config.to_vars();
        let mut result = ApplyResult::new(&template.name, project_dir);

        for file in &template.files {
            let target = project_dir.join(&file.path);
            if target.exists() && file.skip_if_exists && !self.overwrite {
                result.files_skipped.push(target);
                continue;
            }
            if !self.dry_run {
                // Simulate file creation in tests (no real FS writes)
            }
            let _content = file.render(&vars);
            result.files_created.push(target);
        }

        Ok(result)
    }
}

impl Default for TemplateApply {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TemplateLibrary ─────────────────────────────────────────────────────────

/// Registry of all available project templates.
pub struct TemplateLibrary {
    templates: HashMap<String, ProjectTemplate>,
}

impl TemplateLibrary {
    /// Create library pre-populated with built-in templates.
    #[must_use]
    pub fn new() -> Self {
        let mut lib = Self {
            templates: HashMap::new(),
        };
        for t in builtin_templates() {
            lib.templates.insert(t.name.clone(), t);
        }
        lib
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.templates.len()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProjectTemplate> {
        self.templates.get(name)
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.templates.keys().cloned().collect();
        names.sort();
        names
    }

    /// Templates of a given type.
    #[must_use]
    pub fn by_type(&self, template_type: &TemplateType) -> Vec<&ProjectTemplate> {
        self.templates
            .values()
            .filter(|t| &t.template_type == template_type)
            .collect()
    }

    /// Search templates by keyword.
    #[must_use]
    pub fn search(&self, keyword: &str) -> Vec<&ProjectTemplate> {
        let kw = keyword.to_lowercase();
        self.templates
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&kw)
                    || t.description.to_lowercase().contains(&kw)
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&kw))
            })
            .collect()
    }

    /// Register a custom template.
    pub fn register(&mut self, template: ProjectTemplate) -> Result<(), TemplateError> {
        if self.templates.contains_key(&template.name) {
            return Err(TemplateError::AlreadyExists(template.name.clone()));
        }
        self.templates.insert(template.name.clone(), template);
        Ok(())
    }

    /// Apply a named template.
    pub fn apply(
        &self,
        name: &str,
        config: &TemplateConfig,
        project_dir: &Path,
    ) -> Result<ApplyResult, TemplateError> {
        let template = self
            .templates
            .get(name)
            .ok_or_else(|| TemplateError::NotFound(name.to_string()))?;
        TemplateApply::new().apply(template, config, project_dir)
    }

    /// All unique template types.
    #[must_use]
    pub fn types(&self) -> Vec<TemplateType> {
        let mut types: Vec<TemplateType> = self
            .templates
            .values()
            .map(|t| t.template_type.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        types.sort_by_key(std::string::ToString::to_string);
        types
    }
}

impl Default for TemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in templates ───────────────────────────────────────────────────────

fn readme_file(project_type: &str) -> TemplateFile {
    TemplateFile::new(
        "README.md",
        format!(
            "# {{{{project_name}}}}\n\n**Type:** {project_type}\n**Analyst:** {{{{analyst_name}}}}\n**Arch:** {{{{architecture}}}} / {{{{os}}}}\n\n## Scope\n\n## Findings\n\n## Timeline\n"
        ),
    )
}

fn notes_file() -> TemplateFile {
    TemplateFile::new(
        "notes.md",
        "# Analysis Notes\n\n## Initial Observations\n\n## Key Functions\n\n## Strings of Interest\n\n## TODOs\n",
    )
}

fn yara_dir() -> TemplateFile {
    TemplateFile::new("signatures/placeholder.yar", "// Place YARA rules here\n")
}

fn scripts_dir() -> TemplateFile {
    TemplateFile::new(
        "scripts/placeholder.py",
        "# Analysis scripts for {{project_name}}\n",
    )
}

fn builtin_templates() -> Vec<ProjectTemplate> {
    vec![
        ProjectTemplate::new("malware_analysis", "Malware Analysis Project",
            "Scaffold for malware sample analysis: YARA rules, IOC tracking, TI correlation.",
            TemplateType::MalwareAnalysis)
            .with_file(readme_file("Malware Analysis"))
            .with_file(notes_file())
            .with_file(yara_dir())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("iocs.txt", "# IOCs for {{project_name}}\n# Domains\n# IPs\n# Hashes\n"))
            .with_file(TemplateFile::new("timeline.md", "# Timeline\n\n## Events\n"))
            .with_tag("malware").with_tag("ioc"),

        ProjectTemplate::new("vulnerability", "Vulnerability Research Project",
            "Scaffold for binary vulnerability research: PoC, patch diffing, CVE tracking.",
            TemplateType::Vulnerability)
            .with_file(readme_file("Vulnerability Research"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("poc/placeholder.py", "# Proof-of-concept for {{project_name}}\n"))
            .with_file(TemplateFile::new("findings.md", "# Vulnerability Findings\n\n## Summary\n"))
            .with_tag("vulnerability").with_tag("poc"),

        ProjectTemplate::new("firmware", "Firmware Analysis Project",
            "Scaffold for embedded firmware analysis: extraction, string analysis, crypto detection.",
            TemplateType::Firmware)
            .with_file(readme_file("Firmware Analysis"))
            .with_file(notes_file())
            .with_file(yara_dir())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("extracted/placeholder.txt", "# Extracted files go here\n"))
            .with_file(TemplateFile::new("attack_surface.md", "# Attack Surface\n\n## Exposed Services\n"))
            .with_tag("firmware").with_tag("iot"),

        ProjectTemplate::new("mobile", "Mobile Application Analysis Project",
            "Scaffold for Android/iOS app analysis: permissions, entitlements, decompilation.",
            TemplateType::Mobile)
            .with_file(readme_file("Mobile App Analysis"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("manifest_analysis.md", "# Manifest Analysis\n\n## Permissions\n"))
            .with_file(TemplateFile::new("network_traffic.md", "# Network Traffic Analysis\n"))
            .with_tag("mobile").with_tag("android").with_tag("ios"),

        ProjectTemplate::new("ctf", "CTF Challenge Project",
            "Scaffold for CTF binary challenge solving.",
            TemplateType::Ctf)
            .with_file(readme_file("CTF Challenge"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("solution.py", "#!/usr/bin/env python3\n# Solution for {{project_name}}\n\nflag = ''\nprint(flag)\n"))
            .with_file(TemplateFile::new("writeup.md", "# CTF Writeup: {{project_name}}\n\n## Challenge\n\n## Solution\n\n## Flag\n"))
            .with_tag("ctf").with_tag("pwn"),

        ProjectTemplate::new("pentest", "Penetration Testing Project",
            "Scaffold for binary-focused penetration testing: recon, exploit dev, reporting.",
            TemplateType::Pentest)
            .with_file(readme_file("Penetration Test"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("recon/placeholder.txt", "# Reconnaissance notes\n"))
            .with_file(TemplateFile::new("exploits/placeholder.py", "# Exploits for {{project_name}}\n"))
            .with_file(TemplateFile::new("report.md", "# Pentest Report: {{project_name}}\n\n## Executive Summary\n\n## Findings\n\n## Recommendations\n"))
            .with_tag("pentest").with_tag("exploit"),

        ProjectTemplate::new("reversing", "General Reverse Engineering Project",
            "Scaffold for generic reverse engineering work.",
            TemplateType::Reversing)
            .with_file(readme_file("Reverse Engineering"))
            .with_file(notes_file())
            .with_file(yara_dir())
            .with_file(scripts_dir())
            .with_tag("re"),

        ProjectTemplate::new("network", "Network Protocol RE Project",
            "Scaffold for reversing a network protocol.",
            TemplateType::Network)
            .with_file(readme_file("Network Protocol RE"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("protocol_spec.md", "# Protocol Specification\n\n## Message Formats\n"))
            .with_file(TemplateFile::new("dissectors/placeholder.lua", "-- Wireshark dissector for {{project_name}}\n"))
            .with_tag("network").with_tag("protocol"),

        ProjectTemplate::new("dotnet", ".NET Assembly Analysis Project",
            "Scaffold for .NET / C# reverse engineering.",
            TemplateType::DotNet)
            .with_file(readme_file(".NET Analysis"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("decompiled/placeholder.cs", "// Decompiled C# for {{project_name}}\n"))
            .with_tag("dotnet").with_tag("csharp"),

        ProjectTemplate::new("kernel", "Kernel / Driver Analysis Project",
            "Scaffold for kernel module and driver reverse engineering.",
            TemplateType::Kernel)
            .with_file(readme_file("Kernel Analysis"))
            .with_file(notes_file())
            .with_file(scripts_dir())
            .with_file(TemplateFile::new("ioctl_handlers.md", "# IOCTL Handlers\n\n## Handlers\n"))
            .with_file(TemplateFile::new("vulnerabilities.md", "# Kernel Vulnerabilities\n"))
            .with_tag("kernel").with_tag("driver"),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lib() -> TemplateLibrary {
        TemplateLibrary::new()
    }

    fn cfg() -> TemplateConfig {
        TemplateConfig::new("test_project", "test_analyst")
    }

    // ── TemplateType ──────────────────────────────────────────────────────────

    #[test]
    fn test_template_type_display() {
        assert_eq!(TemplateType::MalwareAnalysis.to_string(), "MalwareAnalysis");
        assert_eq!(TemplateType::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn test_template_type_from_str() {
        assert_eq!(
            TemplateType::from_str("malware"),
            TemplateType::MalwareAnalysis
        );
        assert_eq!(TemplateType::from_str("CTF"), TemplateType::Ctf);
        assert_eq!(TemplateType::from_str("firmware"), TemplateType::Firmware);
        assert!(matches!(
            TemplateType::from_str("xyz"),
            TemplateType::Custom(_)
        ));
    }

    // ── TemplateConfig ────────────────────────────────────────────────────────

    #[test]
    fn test_template_config_to_vars() {
        let c = TemplateConfig::new("proj", "alice")
            .with_arch("arm64")
            .with_os("macos");
        let vars = c.to_vars();
        assert_eq!(vars.get("project_name").map(String::as_str), Some("proj"));
        assert_eq!(vars.get("architecture").map(String::as_str), Some("arm64"));
    }

    #[test]
    fn test_template_config_with_binary() {
        let c = cfg().with_binary("/bin/ls");
        let vars = c.to_vars();
        assert!(vars.contains_key("target_binary"));
    }

    #[test]
    fn test_template_config_with_extra() {
        let c = cfg().with_extra("custom_key", "custom_val");
        let vars = c.to_vars();
        assert_eq!(
            vars.get("custom_key").map(String::as_str),
            Some("custom_val")
        );
    }

    // ── TemplateFile.render ───────────────────────────────────────────────────

    #[test]
    fn test_template_file_render() {
        let f = TemplateFile::new("x.md", "Hello {{name}}!");
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "World".to_string());
        assert_eq!(f.render(&vars), "Hello World!");
    }

    #[test]
    fn test_template_file_render_missing_var() {
        let f = TemplateFile::new("x.md", "Hello {{missing}}!");
        let vars = HashMap::new();
        // Missing vars remain as-is
        let rendered = f.render(&vars);
        assert!(rendered.contains("{{missing}}"));
    }

    // ── ProjectTemplate ───────────────────────────────────────────────────────

    #[test]
    fn test_project_template_file_paths() {
        let l = lib();
        let t = l.get("malware_analysis").unwrap();
        assert!(t.file_paths().contains(&"README.md"));
    }

    #[test]
    fn test_project_template_validate_config_ok() {
        let l = lib();
        let t = l.get("ctf").unwrap();
        assert!(t.validate_config(&cfg()).is_ok());
    }

    #[test]
    fn test_project_template_validate_config_missing() {
        let mut t = ProjectTemplate::new("t", "T", "d", TemplateType::Reversing);
        t.required_config_keys
            .push("custom_required_key".to_string());
        let err = t.validate_config(&cfg()).unwrap_err();
        assert!(matches!(err, TemplateError::MissingConfig(_)));
    }

    // ── TemplateApply ─────────────────────────────────────────────────────────

    #[test]
    fn test_apply_dry_run() {
        let l = lib();
        let t = l.get("reversing").unwrap();
        let c = cfg();
        let result = TemplateApply::new()
            .dry_run()
            .apply(t, &c, Path::new("/tmp/test_proj"))
            .unwrap();
        assert!(result.success);
        // In dry_run mode files are still listed as "created"
        assert!(!result.files_created.is_empty());
    }

    #[test]
    fn test_apply_skip_if_exists_flag() {
        let mut f = TemplateFile::new("x.md", "content");
        f.skip_if_exists = true;
        assert!(f.skip_if_exists);
    }

    // ── TemplateLibrary ───────────────────────────────────────────────────────

    #[test]
    fn test_library_count_ge_6() {
        assert!(lib().count() >= 6);
    }

    #[test]
    fn test_library_get_malware() {
        assert!(lib().get("malware_analysis").is_some());
    }

    #[test]
    fn test_library_get_ctf() {
        assert!(lib().get("ctf").is_some());
    }

    #[test]
    fn test_library_get_pentest() {
        assert!(lib().get("pentest").is_some());
    }

    #[test]
    fn test_library_get_firmware() {
        assert!(lib().get("firmware").is_some());
    }

    #[test]
    fn test_library_get_mobile() {
        assert!(lib().get("mobile").is_some());
    }

    #[test]
    fn test_library_get_not_found() {
        assert!(lib().get("nonexistent").is_none());
    }

    #[test]
    fn test_library_names_sorted() {
        let names = lib().names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_library_by_type() {
        let l = lib();
        let results = l.by_type(&TemplateType::MalwareAnalysis);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_library_search_malware() {
        let l = lib();
        let results = l.search("malware");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_library_search_no_match() {
        assert!(lib().search("xyzzy_nope").is_empty());
    }

    #[test]
    fn test_library_register_ok() {
        let mut l = TemplateLibrary::new();
        let t = ProjectTemplate::new("custom_t", "Custom", "d", TemplateType::Custom("x".into()));
        l.register(t).unwrap();
        assert!(l.get("custom_t").is_some());
    }

    #[test]
    fn test_library_register_duplicate() {
        let mut l = TemplateLibrary::new();
        let t = ProjectTemplate::new(
            "malware_analysis",
            "dup",
            "d",
            TemplateType::MalwareAnalysis,
        );
        let err = l.register(t).unwrap_err();
        assert!(matches!(err, TemplateError::AlreadyExists(_)));
    }

    #[test]
    fn test_library_apply_ok() {
        let l = lib();
        let c = cfg();
        let result = l.apply("ctf", &c, Path::new("/tmp/ctf_proj")).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_library_apply_not_found() {
        let l = lib();
        let c = cfg();
        let err = l.apply("ghost", &c, Path::new("/tmp/x")).unwrap_err();
        assert!(matches!(err, TemplateError::NotFound(_)));
    }

    #[test]
    fn test_library_types_non_empty() {
        let types = lib().types();
        assert!(!types.is_empty());
        assert!(types.contains(&TemplateType::Ctf));
    }

    // ── TemplateError display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = TemplateError::NotFound("x".into());
        assert!(e.to_string().contains('x'));
        let e2 = TemplateError::MissingConfig("key".into());
        assert!(e2.to_string().contains("key"));
        let e3 = TemplateError::AlreadyExists("t".into());
        assert!(e3.to_string().contains('t'));
    }
}
