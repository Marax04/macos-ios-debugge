//! MISP event builder — fluent API for constructing MISP events programmatically.
//!
//! Supports adding attributes, structured objects (network-connection, file,
//! domain-ip, url), tags, distribution, and threat level.  Also provides
//! bulk import from IOC lists.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Re-use types defined in the parent crate / module
// ---------------------------------------------------------------------------

use crate::{
    MispAttributeFull, MispDistributionLevel, MispEventFull, MispObjectFull, MispTagSpec,
    MispThreatLevelId, uuid_v4_mock,
};

// ---------------------------------------------------------------------------
// MispObjectTemplate (builder-specific template names)
// ---------------------------------------------------------------------------

/// Predefined MISP object template names used by the event builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MispObjectTemplateName {
    NetworkConnection,
    File,
    DomainIp,
    Url,
    Email,
    Process,
    RegistryKey,
    Custom(String),
}

impl MispObjectTemplateName {
    /// Return the MISP object template name string.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::NetworkConnection => "network-connection",
            Self::File => "file",
            Self::DomainIp => "domain-ip",
            Self::Url => "url",
            Self::Email => "email",
            Self::Process => "process",
            Self::RegistryKey => "registry-key",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// IocEntry (raw IOC for bulk import)
// ---------------------------------------------------------------------------

/// A single IOC entry for bulk import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    /// MISP attribute type string.
    pub attr_type: String,
    /// Attribute value.
    pub value: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Whether to enable IDS forwarding.
    pub to_ids: bool,
    /// Tags to attach.
    pub tags: Vec<String>,
}

impl IocEntry {
    /// Create a minimal IOC entry.
    #[must_use]
    pub fn new(attr_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            attr_type: attr_type.into(),
            value: value.into(),
            comment: None,
            to_ids: false,
            tags: Vec::new(),
        }
    }

    /// Mark this entry for IDS.
    #[must_use]
    pub const fn with_ids(mut self) -> Self {
        self.to_ids = true;
        self
    }

    /// Add a comment.
    #[must_use]
    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = Some(c.into());
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }
}

// ---------------------------------------------------------------------------
// MispObject (builder convenience type)
// ---------------------------------------------------------------------------

/// A structured MISP object created by the builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispBuilderObject {
    /// UUID.
    pub uuid: String,
    /// Template name.
    pub name: String,
    /// Meta-category.
    pub meta_category: String,
    /// Attribute key-value pairs (attribute type → value).
    pub attributes: HashMap<String, String>,
    /// Tags attached to this object.
    pub tags: Vec<String>,
}

impl MispBuilderObject {
    fn new(template: &MispObjectTemplateName, meta_category: impl Into<String>) -> Self {
        Self {
            uuid: uuid_v4_mock(),
            name: template.as_str().to_string(),
            meta_category: meta_category.into(),
            attributes: HashMap::new(),
            tags: Vec::new(),
        }
    }

    /// Convert to a [`MispObjectFull`] for use in events.
    #[must_use]
    pub fn to_object_full(&self) -> MispObjectFull {
        let mut obj = MispObjectFull::new(self.name.clone(), self.meta_category.clone());
        obj.uuid.clone_from(&self.uuid);
        for (attr_type, value) in &self.attributes {
            let mut attr = MispAttributeFull::new(0, attr_type.clone(), value.clone());
            attr.uuid = uuid_v4_mock();
            obj.add_attribute(attr);
        }
        obj
    }
}

// ---------------------------------------------------------------------------
// MispEventBuilder — the fluent builder
// ---------------------------------------------------------------------------

/// Fluent builder for `MispEventFull`.
///
/// # Example
/// ```rust,ignore
/// let event = MispEventBuilder::new("Emotet phishing campaign")
///     .threat_level(MispThreatLevelId::High)
///     .distribution(MispDistributionLevel::Community)
///     .add_ioc("sha256", "deadbeef...", true)
///     .add_tag("tlp:amber", "#FFC000")
///     .add_network_connection("192.0.2.1", "4444", "tcp")
///     .build();
/// ```
pub struct MispEventBuilder {
    info: String,
    threat_level: MispThreatLevelId,
    distribution: MispDistributionLevel,
    attributes: Vec<MispAttributeFull>,
    objects: Vec<MispObjectFull>,
    tags: Vec<MispTagSpec>,
    date: Option<String>,
    published: bool,
}

impl MispEventBuilder {
    /// Create a new builder with the event title.
    #[must_use]
    pub fn new(info: impl Into<String>) -> Self {
        Self {
            info: info.into(),
            threat_level: MispThreatLevelId::Undefined,
            distribution: MispDistributionLevel::Community,
            attributes: Vec::new(),
            objects: Vec::new(),
            tags: Vec::new(),
            date: None,
            published: false,
        }
    }

    /// Set the threat level.
    #[must_use]
    pub const fn threat_level(mut self, level: MispThreatLevelId) -> Self {
        self.threat_level = level;
        self
    }

    /// Set the distribution level.
    #[must_use]
    pub const fn distribution(mut self, dist: MispDistributionLevel) -> Self {
        self.distribution = dist;
        self
    }

    /// Set the event date (YYYY-MM-DD).
    #[must_use]
    pub fn date(mut self, d: impl Into<String>) -> Self {
        self.date = Some(d.into());
        self
    }

    /// Mark the event as published.
    #[must_use]
    pub const fn publish(mut self) -> Self {
        self.published = true;
        self
    }

    /// Add a raw attribute.
    #[must_use]
    pub fn add_attribute(mut self, attr: MispAttributeFull) -> Self {
        self.attributes.push(attr);
        self
    }

    /// Add an IOC attribute by type and value.
    #[must_use]
    pub fn add_ioc(
        mut self,
        attr_type: impl Into<String>,
        value: impl Into<String>,
        to_ids: bool,
    ) -> Self {
        let id = self.attributes.len() as u64 + 1;
        let mut attr = MispAttributeFull::new(id, attr_type.into(), value.into());
        attr.to_ids = to_ids;
        self.attributes.push(attr);
        self
    }

    /// Add an IOC attribute with an optional comment.
    #[must_use]
    pub fn add_ioc_with_comment(
        mut self,
        attr_type: impl Into<String>,
        value: impl Into<String>,
        comment: impl Into<String>,
        to_ids: bool,
    ) -> Self {
        let id = self.attributes.len() as u64 + 1;
        let mut attr = MispAttributeFull::new(id, attr_type.into(), value.into());
        attr.to_ids = to_ids;
        attr.comment = Some(comment.into());
        self.attributes.push(attr);
        self
    }

    /// Add a tag by name and colour.
    #[must_use]
    pub fn add_tag(mut self, name: impl Into<String>, colour: impl Into<String>) -> Self {
        self.tags.push(MispTagSpec::new(name.into(), colour.into()));
        self
    }

    /// Add a TLP tag.
    #[must_use]
    pub fn tlp(self, level: &str) -> Self {
        let colour = match level.to_lowercase().as_str() {
            "white" | "clear" => "#FFFFFF",
            "green" => "#33FF00",
            "amber" => "#FFC000",
            "amber+strict" => "#FFC000",
            "red" => "#FF0000",
            _ => "#CCCCCC",
        };
        self.add_tag(format!("tlp:{level}"), colour)
    }

    /// Add a MISP galaxy cluster tag.
    #[must_use]
    pub fn galaxy_cluster(self, galaxy: &str, cluster: &str) -> Self {
        self.add_tag(format!("misp-galaxy:{galaxy}=\"{cluster}\""), "#0088CC")
    }

    /// Add a structured MISP object.
    #[must_use]
    pub fn add_object(mut self, obj: MispObjectFull) -> Self {
        self.objects.push(obj);
        self
    }

    // ---- Pre-built object helpers ----

    /// Add a `network-connection` object.
    #[must_use]
    pub fn add_network_connection(
        mut self,
        dst_ip: impl Into<String>,
        dst_port: impl Into<String>,
        protocol: impl Into<String>,
    ) -> Self {
        let mut bo = MispBuilderObject::new(&MispObjectTemplateName::NetworkConnection, "network");
        bo.attributes.insert("ip-dst".to_string(), dst_ip.into());
        bo.attributes
            .insert("dst-port".to_string(), dst_port.into());
        bo.attributes
            .insert("protocol".to_string(), protocol.into());
        self.objects.push(bo.to_object_full());
        self
    }

    /// Add a `file` object.
    #[must_use]
    pub fn add_file_object(
        mut self,
        filename: impl Into<String>,
        sha256: Option<impl Into<String>>,
        size: Option<u64>,
    ) -> Self {
        let mut bo = MispBuilderObject::new(&MispObjectTemplateName::File, "file");
        bo.attributes
            .insert("filename".to_string(), filename.into());
        if let Some(h) = sha256 {
            bo.attributes.insert("sha256".to_string(), h.into());
        }
        if let Some(s) = size {
            bo.attributes
                .insert("size-in-bytes".to_string(), s.to_string());
        }
        self.objects.push(bo.to_object_full());
        self
    }

    /// Add a `domain-ip` object.
    #[must_use]
    pub fn add_domain_ip(mut self, domain: impl Into<String>, ip: impl Into<String>) -> Self {
        let mut bo = MispBuilderObject::new(&MispObjectTemplateName::DomainIp, "network");
        bo.attributes.insert("domain".to_string(), domain.into());
        bo.attributes.insert("ip".to_string(), ip.into());
        self.objects.push(bo.to_object_full());
        self
    }

    /// Add a `url` object.
    #[must_use]
    pub fn add_url_object(
        mut self,
        url: impl Into<String>,
        text: Option<impl Into<String>>,
    ) -> Self {
        let mut bo = MispBuilderObject::new(&MispObjectTemplateName::Url, "network");
        bo.attributes.insert("url".to_string(), url.into());
        if let Some(t) = text {
            bo.attributes.insert("text".to_string(), t.into());
        }
        self.objects.push(bo.to_object_full());
        self
    }

    // ---- Bulk import ----

    /// Import multiple IOC entries at once.
    #[must_use]
    pub fn bulk_import_iocs(mut self, entries: &[IocEntry]) -> Self {
        for (i, entry) in entries.iter().enumerate() {
            let id = self.attributes.len() as u64 + i as u64 + 1;
            let mut attr = MispAttributeFull::new(id, entry.attr_type.clone(), entry.value.clone());
            attr.to_ids = entry.to_ids;
            attr.comment.clone_from(&entry.comment);
            for tag_name in &entry.tags {
                attr.tags
                    .push(MispTagSpec::new(tag_name.clone(), "#CCCCCC".to_string()));
            }
            self.attributes.push(attr);
        }
        self
    }

    /// Import IOCs from a newline-delimited text string.
    ///
    /// Each non-empty line is treated as a raw IOC value.  The type is guessed
    /// from the value format.
    #[must_use]
    pub fn bulk_import_text(self, text: &str, default_type: &str) -> Self {
        let entries: Vec<IocEntry> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|line| IocEntry::new(guess_type(line, default_type), line))
            .collect();
        self.bulk_import_iocs(&entries)
    }

    /// Consume the builder and produce a `MispEventFull`.
    #[must_use]
    pub fn build(self) -> MispEventFull {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut event = MispEventFull::new(self.info);
        event.threat_level_id = self.threat_level.value();
        event.distribution = self.distribution;
        event.published = self.published;
        event.timestamp = now;

        if let Some(d) = self.date {
            event.date = d;
        }

        for attr in self.attributes {
            event.add_attribute(attr);
        }
        for obj in self.objects {
            event.add_object(obj);
        }
        for tag in self.tags {
            event.add_tag(tag);
        }

        event
    }
}

// ---------------------------------------------------------------------------
// Type guessing helper
// ---------------------------------------------------------------------------

/// Guess a MISP attribute type from the value string.
fn guess_type(value: &str, default: &str) -> String {
    // IPv4 / IPv6
    if value.parse::<std::net::IpAddr>().is_ok() {
        return "ip-dst".to_string();
    }
    // URL
    if value.starts_with("http://") || value.starts_with("https://") {
        return "url".to_string();
    }
    // MD5 (32 hex chars)
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5".to_string();
    }
    // SHA-1 (40 hex chars)
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha1".to_string();
    }
    // SHA-256 (64 hex chars)
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256".to_string();
    }
    // Domain (contains dot, no spaces, no slashes)
    if value.contains('.') && !value.contains(' ') && !value.contains('/') {
        return "domain".to_string();
    }
    default.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- guess_type ----

    #[test]
    fn test_guess_ip() {
        assert_eq!(guess_type("192.168.1.1", "other"), "ip-dst");
    }

    #[test]
    fn test_guess_url() {
        assert_eq!(guess_type("https://example.com/path", "other"), "url");
    }

    #[test]
    fn test_guess_md5() {
        assert_eq!(guess_type(&"a".repeat(32), "other"), "md5");
    }

    #[test]
    fn test_guess_sha1() {
        assert_eq!(guess_type(&"b".repeat(40), "other"), "sha1");
    }

    #[test]
    fn test_guess_sha256() {
        assert_eq!(guess_type(&"c".repeat(64), "other"), "sha256");
    }

    #[test]
    fn test_guess_domain() {
        assert_eq!(guess_type("evil.example.com", "other"), "domain");
    }

    #[test]
    fn test_guess_default() {
        assert_eq!(guess_type("random text", "comment"), "comment");
    }

    // ---- IocEntry ----

    #[test]
    fn test_ioc_entry_new() {
        let e = IocEntry::new("sha256", "abc");
        assert_eq!(e.attr_type, "sha256");
        assert!(!e.to_ids);
    }

    #[test]
    fn test_ioc_entry_with_ids() {
        let e = IocEntry::new("sha256", "abc").with_ids();
        assert!(e.to_ids);
    }

    #[test]
    fn test_ioc_entry_with_comment() {
        let e = IocEntry::new("url", "http://x.com").with_comment("c2");
        assert_eq!(e.comment.as_deref(), Some("c2"));
    }

    #[test]
    fn test_ioc_entry_with_tag() {
        let e = IocEntry::new("ip-dst", "1.2.3.4").with_tag("malware");
        assert!(e.tags.contains(&"malware".to_string()));
    }

    // ---- MispObjectTemplateName ----

    #[test]
    fn test_template_name_as_str() {
        assert_eq!(
            MispObjectTemplateName::NetworkConnection.as_str(),
            "network-connection"
        );
        assert_eq!(MispObjectTemplateName::File.as_str(), "file");
        assert_eq!(MispObjectTemplateName::DomainIp.as_str(), "domain-ip");
        assert_eq!(MispObjectTemplateName::Url.as_str(), "url");
    }

    #[test]
    fn test_template_name_custom() {
        let t = MispObjectTemplateName::Custom("my-template".to_string());
        assert_eq!(t.as_str(), "my-template");
    }

    // ---- MispEventBuilder ----

    #[test]
    fn test_builder_basic() {
        let event = MispEventBuilder::new("Test Event").build();
        assert_eq!(event.info, "Test Event");
        assert!(!event.published);
    }

    #[test]
    fn test_builder_threat_level() {
        let event = MispEventBuilder::new("T")
            .threat_level(MispThreatLevelId::High)
            .build();
        assert_eq!(event.threat_level_id, 1);
    }

    #[test]
    fn test_builder_distribution() {
        let event = MispEventBuilder::new("T")
            .distribution(MispDistributionLevel::AllCommunities)
            .build();
        assert_eq!(event.distribution, MispDistributionLevel::AllCommunities);
    }

    #[test]
    fn test_builder_add_ioc() {
        let event = MispEventBuilder::new("T")
            .add_ioc("sha256", "deadbeef", true)
            .build();
        assert_eq!(event.attributes.len(), 1);
        assert!(event.attributes[0].to_ids);
    }

    #[test]
    fn test_builder_add_ioc_with_comment() {
        let event = MispEventBuilder::new("T")
            .add_ioc_with_comment("sha256", "abc", "note", false)
            .build();
        assert_eq!(event.attributes[0].comment.as_deref(), Some("note"));
    }

    #[test]
    fn test_builder_add_tag() {
        let event = MispEventBuilder::new("T")
            .add_tag("tlp:green", "#33FF00")
            .build();
        assert!(event.tags.iter().any(|t| t.name == "tlp:green"));
    }

    #[test]
    fn test_builder_tlp() {
        let event = MispEventBuilder::new("T").tlp("amber").build();
        assert!(event.tags.iter().any(|t| t.name == "tlp:amber"));
    }

    #[test]
    fn test_builder_galaxy_cluster() {
        let event = MispEventBuilder::new("T")
            .galaxy_cluster("ransomware", "WannaCry")
            .build();
        assert!(event.tags.iter().any(|t| t.name.contains("WannaCry")));
    }

    #[test]
    fn test_builder_publish() {
        let event = MispEventBuilder::new("T").publish().build();
        assert!(event.published);
    }

    #[test]
    fn test_builder_date() {
        let event = MispEventBuilder::new("T").date("2024-06-01").build();
        assert_eq!(event.date, "2024-06-01");
    }

    #[test]
    fn test_builder_network_connection() {
        let event = MispEventBuilder::new("T")
            .add_network_connection("10.0.0.1", "4444", "tcp")
            .build();
        assert_eq!(event.objects.len(), 1);
        assert_eq!(event.objects[0].name, "network-connection");
    }

    #[test]
    fn test_builder_file_object() {
        let event = MispEventBuilder::new("T")
            .add_file_object("malware.exe", Some("deadbeef".repeat(8)), Some(102400))
            .build();
        assert_eq!(event.objects.len(), 1);
        assert_eq!(event.objects[0].name, "file");
    }

    #[test]
    fn test_builder_domain_ip() {
        let event = MispEventBuilder::new("T")
            .add_domain_ip("evil.example.com", "203.0.113.1")
            .build();
        assert_eq!(event.objects.len(), 1);
        assert_eq!(event.objects[0].name, "domain-ip");
    }

    #[test]
    fn test_builder_url_object() {
        let event = MispEventBuilder::new("T")
            .add_url_object("https://evil.com/gate.php", Some("C2 URL"))
            .build();
        assert_eq!(event.objects.len(), 1);
        assert_eq!(event.objects[0].name, "url");
    }

    #[test]
    fn test_builder_bulk_import_iocs() {
        let entries = vec![
            IocEntry::new("sha256", "aaa"),
            IocEntry::new("ip-dst", "1.2.3.4"),
            IocEntry::new("domain", "evil.com"),
        ];
        let event = MispEventBuilder::new("T")
            .bulk_import_iocs(&entries)
            .build();
        assert_eq!(event.attributes.len(), 3);
    }

    #[test]
    fn test_builder_bulk_import_text() {
        let text = r"
# comment
192.168.1.100
evil.example.com
aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
";
        let event = MispEventBuilder::new("T")
            .bulk_import_text(text, "other")
            .build();
        // 3 non-empty, non-comment lines.
        assert_eq!(event.attributes.len(), 3);
    }

    #[test]
    fn test_builder_bulk_import_text_type_guessing() {
        let text = "192.168.1.1";
        let event = MispEventBuilder::new("T")
            .bulk_import_text(text, "other")
            .build();
        assert_eq!(event.attributes[0].type_, "ip-dst");
    }

    #[test]
    fn test_builder_chained_full() {
        let event = MispEventBuilder::new("Emotet phishing")
            .threat_level(MispThreatLevelId::High)
            .distribution(MispDistributionLevel::Community)
            .tlp("amber")
            .add_ioc("sha256", "e".repeat(64), true)
            .add_ioc("domain", "evil.example.com", true)
            .add_network_connection("203.0.113.1", "443", "tcp")
            .add_domain_ip("c2.example.com", "203.0.113.1")
            .publish()
            .build();

        assert_eq!(event.info, "Emotet phishing");
        assert_eq!(event.threat_level_id, 1);
        assert!(event.published);
        assert_eq!(event.attributes.len(), 2);
        assert_eq!(event.objects.len(), 2);
        assert!(event.tags.iter().any(|t| t.name.contains("amber")));
    }

    #[test]
    fn test_builder_ioc_count() {
        let event = MispEventBuilder::new("T")
            .add_ioc("sha256", "a".repeat(64), false)
            .add_ioc("ip-dst", "1.2.3.4", true)
            .build();
        assert_eq!(event.ioc_count(), 2);
    }

    #[test]
    fn test_builder_has_ids_after_add() {
        let event = MispEventBuilder::new("T")
            .add_ioc("sha256", "abc", true)
            .build();
        assert!(event.has_ids_attributes());
    }

    #[test]
    fn test_builder_no_ids_when_all_false() {
        let event = MispEventBuilder::new("T")
            .add_ioc("sha256", "abc", false)
            .build();
        assert!(!event.has_ids_attributes());
    }

    // ---- Multiple objects of different types ----

    #[test]
    fn test_builder_multiple_objects() {
        let event = MispEventBuilder::new("Multi-object test")
            .add_network_connection("10.0.0.1", "443", "tcp")
            .add_file_object("evil.exe", Some("a".repeat(64)), Some(4096))
            .add_domain_ip("c2.example.com", "10.0.0.1")
            .add_url_object("https://c2.example.com/gate", None::<&str>)
            .build();
        assert_eq!(event.objects.len(), 4);
        let names: Vec<&str> = event.objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"network-connection"));
        assert!(names.contains(&"file"));
        assert!(names.contains(&"domain-ip"));
        assert!(names.contains(&"url"));
    }

    // ---- Tags interaction ----

    #[test]
    fn test_builder_multiple_tags() {
        let event = MispEventBuilder::new("T")
            .add_tag("tlp:green", "#33FF00")
            .add_tag("misp-galaxy:ransomware=\"WannaCry\"", "#FF0000")
            .add_tag("type:OSINT", "#0000FF")
            .build();
        assert_eq!(event.tags.len(), 3);
    }

    // ---- Bulk import skips blank lines and comments ----

    #[test]
    fn test_bulk_import_text_skips_comments_and_blanks() {
        let text = "# header\n\n8.8.8.8\n# another comment\n1.1.1.1\n";
        let event = MispEventBuilder::new("T")
            .bulk_import_text(text, "ip-dst")
            .build();
        assert_eq!(event.attributes.len(), 2);
    }

    // ---- add_attribute raw ----

    #[test]
    fn test_builder_add_raw_attribute() {
        let mut attr =
            MispAttributeFull::new(99, "url".to_string(), "https://example.com".to_string());
        attr.comment = Some("manual attribute".to_string());
        let event = MispEventBuilder::new("T").add_attribute(attr).build();
        assert_eq!(event.attributes.len(), 1);
        assert_eq!(
            event.attributes[0].comment.as_deref(),
            Some("manual attribute")
        );
    }

    // ---- Distribution NoDistribution ----

    #[test]
    fn test_builder_no_distribution() {
        let event = MispEventBuilder::new("T")
            .distribution(MispDistributionLevel::NoDistribution)
            .build();
        assert_eq!(event.distribution, MispDistributionLevel::NoDistribution);
    }

    // ---- TLP red ----

    #[test]
    fn test_builder_tlp_red() {
        let event = MispEventBuilder::new("T").tlp("red").build();
        let tag = event.tags.iter().find(|t| t.name == "tlp:red").unwrap();
        assert_eq!(tag.colour, "#FF0000");
    }

    // ---- IocEntry serde ----

    #[test]
    fn test_ioc_entry_serde() {
        let e = IocEntry::new("sha256", "deadbeef")
            .with_ids()
            .with_comment("test")
            .with_tag("malware");
        let json = serde_json::to_string(&e).unwrap();
        let e2: IocEntry = serde_json::from_str(&json).unwrap();
        assert!(e2.to_ids);
        assert_eq!(e2.comment.as_deref(), Some("test"));
        assert!(e2.tags.contains(&"malware".to_string()));
    }

    // ---- guess_type edge cases ----

    #[test]
    fn test_guess_type_ipv6() {
        // IPv6 should resolve as ip-dst.
        assert_eq!(guess_type("::1", "other"), "ip-dst");
    }

    #[test]
    fn test_guess_type_short_string_skipped_by_extractor() {
        // Very short strings are OK for guess_type.
        let t = guess_type("x", "other");
        assert_eq!(t, "other");
    }

    // ---- Threat level Medium ----

    #[test]
    fn test_builder_threat_level_medium() {
        let event = MispEventBuilder::new("T")
            .threat_level(MispThreatLevelId::Medium)
            .build();
        assert_eq!(event.threat_level_id, 2);
    }

    // ---- MispObjectTemplateName serde ----

    #[test]
    fn test_template_name_serde() {
        let t = MispObjectTemplateName::Email;
        let json = serde_json::to_string(&t).unwrap();
        let t2: MispObjectTemplateName = serde_json::from_str(&json).unwrap();
        assert_eq!(t2, MispObjectTemplateName::Email);
    }

    // ---- All template names have non-empty as_str ----

    #[test]
    fn test_all_template_names_non_empty() {
        let templates = [
            MispObjectTemplateName::NetworkConnection,
            MispObjectTemplateName::File,
            MispObjectTemplateName::DomainIp,
            MispObjectTemplateName::Url,
            MispObjectTemplateName::Email,
            MispObjectTemplateName::Process,
            MispObjectTemplateName::RegistryKey,
        ];
        for t in &templates {
            assert!(!t.as_str().is_empty());
        }
    }

    // ---- bulk_import_iocs preserves ids ----

    #[test]
    fn test_bulk_import_ids_are_to_ids() {
        let entries = vec![
            IocEntry::new("sha256", "a").with_ids(),
            IocEntry::new("sha256", "b"),
        ];
        let event = MispEventBuilder::new("T")
            .bulk_import_iocs(&entries)
            .build();
        assert!(event.attributes[0].to_ids);
        assert!(!event.attributes[1].to_ids);
    }

    // ---- guess_type for http url ----

    #[test]
    fn test_guess_type_http() {
        assert_eq!(guess_type("http://example.com", "other"), "url");
    }

    // ---- MispBuilderObject uuid is set ----

    #[test]
    fn test_builder_object_uuid_set() {
        let event = MispEventBuilder::new("T")
            .add_network_connection("1.2.3.4", "80", "tcp")
            .build();
        assert!(!event.objects[0].uuid.is_empty());
    }

    // ---- add_object raw MispObjectFull ----

    #[test]
    fn test_builder_add_object_full() {
        let obj = MispObjectFull::new("custom-template".to_string(), "network".to_string());
        let event = MispEventBuilder::new("T").add_object(obj).build();
        assert_eq!(event.objects.len(), 1);
        assert_eq!(event.objects[0].name, "custom-template");
    }

    // ---- event timestamp is set ----

    #[test]
    fn test_builder_timestamp_set() {
        let event = MispEventBuilder::new("T").build();
        assert!(event.timestamp > 0);
    }

    // ---- galaxy cluster tag format ----

    #[test]
    fn test_galaxy_cluster_tag_format() {
        let event = MispEventBuilder::new("T")
            .galaxy_cluster("mitre-attack", "T1055")
            .build();
        let tag = event
            .tags
            .iter()
            .find(|t| t.name.contains("T1055"))
            .unwrap();
        assert!(tag.name.contains("mitre-attack"));
    }

    // ---- TLP white ----

    #[test]
    fn test_builder_tlp_white() {
        let event = MispEventBuilder::new("T").tlp("white").build();
        let tag = event
            .tags
            .iter()
            .find(|t| t.name.contains("white"))
            .unwrap();
        assert_eq!(tag.colour, "#FFFFFF");
    }

    // ---- TLP green ----

    #[test]
    fn test_builder_tlp_green_colour() {
        let event = MispEventBuilder::new("T").tlp("green").build();
        let tag = event
            .tags
            .iter()
            .find(|t| t.name.contains("green"))
            .unwrap();
        assert_eq!(tag.colour, "#33FF00");
    }

    // ---- Threat level Low ----

    #[test]
    fn test_builder_threat_level_low() {
        let event = MispEventBuilder::new("T")
            .threat_level(MispThreatLevelId::Low)
            .build();
        assert_eq!(event.threat_level_id, 3);
    }

    // ---- tag count grows correctly ----

    #[test]
    fn test_builder_tag_count() {
        let event = MispEventBuilder::new("T")
            .tlp("green")
            .tlp("amber")
            .galaxy_cluster("ransomware", "WannaCry")
            .add_tag("custom:tag", "#123456")
            .build();
        assert_eq!(event.tags.len(), 4);
    }
}
