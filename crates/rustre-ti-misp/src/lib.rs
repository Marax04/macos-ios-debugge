//! `rustre-ti-misp`
//!
//! MISP (Malware Information Sharing Platform) REST API integration.
//! Full async client with event/attribute/object/galaxy management,
//! sightings, sharing groups, warning lists, and workflow automation.

pub mod cache;
pub mod client;
pub mod error;
pub mod event_builder;
pub mod export;
pub mod import;
pub mod misp_automation;
pub mod misp_client;
pub mod misp_enrichment;
pub mod misp_attribute_types;
pub mod misp_correlation;
pub mod misp_event_builder;
pub mod misp_feed_parser;
pub mod misp_galaxy_mapper;
pub mod misp_query;
pub mod misp_search_client;
pub mod models;
pub mod stix21;
pub mod stix_converter;

pub use misp_automation::{
    AutoCorrelation, AutoExport, AutoTagging, AutomationRule, ConditionContext, MispAutomation,
    WorkflowTrigger,
};

pub use cache::MispCache;
pub use client::{MispClient, MispFeedReader, MispRawClient};
pub use error::MispError;
pub use models::{
    MispAnalysis, MispAttribute, MispDistribution, MispEvent, MispObject, MispTag, MispThreatLevel,
    NewMispAttribute, NewMispEvent,
};

use async_trait::async_trait;
use rustre_threatintel::{IoC, IoCType, TiError, TiProvider, TiResult, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// MispAttributeType — all 100+ MISP attribute types
// ---------------------------------------------------------------------------

/// Comprehensive MISP attribute type enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MispAttributeType {
    // Hash types
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha224,
    Sha384,
    Sha3224,
    Sha3256,
    Sha3384,
    Sha3512,
    Ssdeep,
    Tlsh,
    Authentihash,
    Imphash,
    Pehash,
    Vhash,
    // Filename composite
    Filename,
    FilenameAndMd5,
    FilenameAndSha1,
    FilenameAndSha256,
    // Network
    IpSrc,
    IpDst,
    IpSrcPort,
    IpDstPort,
    Domain,
    Hostname,
    Url,
    Uri,
    Email,
    EmailSrc,
    EmailDst,
    EmailSubject,
    EmailBody,
    EmailAttachment,
    EmailHeader,
    EmailReplyTo,
    EmailXMailer,
    EmailMimeBoundary,
    EmailThreadIndex,
    EmailMessageId,
    HttpMethod,
    UserAgent,
    // Host artifacts
    Mutex,
    Registry,
    Regkey,
    RegkeyAndValue,
    WindowsServiceName,
    WindowsServiceDisplayname,
    WindowsScheduledTask,
    Process,
    ProcessState,
    NamedPipe,
    FilePath,
    // Malware
    MalwareSample,
    Yara,
    SigmaRule,
    SnortRule,
    // Threat actor / intel
    ThreatActor,
    CampaignName,
    CampaignId,
    MalwareFamily,
    // Vulnerability — CVE identifiers are stored under the same MISP type
    // ("vulnerability") so Cve has been collapsed into this variant.
    Vulnerability,
    Weakness,
    // Finance
    BtcAddress,
    EthAddress,
    IbanCode,
    Bic,
    BankAccountNr,
    // Other
    Asn,
    Comment,
    Other,
    Text,
    Link,
    PatternInFile,
    PatternInMemory,
    PatternInTraffic,
    TargetUser,
    TargetEmail,
    TargetMachine,
    TargetOrg,
    TargetLocation,
    TargetExternal,
    WhoisRegistrantEmail,
    WhoisRegistrar,
    WhoisRegistrantPhone,
    WhoisRegistrantOrg,
    WhoisRegistrantName,
    WhoisCreationDate,
    X509FingerprintSha1,
    X509FingerprintMd5,
    X509FingerprintSha256,
    JarHash,
    Pdb,
    Ip,
}

impl MispAttributeType {
    /// Convert to the MISP string representation.
    #[must_use]
    pub const fn as_misp_str(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Sha224 => "sha224",
            Self::Sha384 => "sha384",
            Self::Sha3224 => "sha3-224",
            Self::Sha3256 => "sha3-256",
            Self::Sha3384 => "sha3-384",
            Self::Sha3512 => "sha3-512",
            Self::Ssdeep => "ssdeep",
            Self::Tlsh => "tlsh",
            Self::Authentihash => "authentihash",
            Self::Imphash => "imphash",
            Self::Pehash => "pehash",
            Self::Vhash => "vhash",
            Self::Filename => "filename",
            Self::FilenameAndMd5 => "filename|md5",
            Self::FilenameAndSha1 => "filename|sha1",
            Self::FilenameAndSha256 => "filename|sha256",
            Self::IpSrc => "ip-src",
            Self::IpDst => "ip-dst",
            Self::IpSrcPort => "ip-src|port",
            Self::IpDstPort => "ip-dst|port",
            Self::Domain => "domain",
            Self::Hostname => "hostname",
            Self::Url => "url",
            Self::Uri => "uri",
            Self::Email => "email",
            Self::EmailSrc => "email-src",
            Self::EmailDst => "email-dst",
            Self::EmailSubject => "email-subject",
            Self::EmailBody => "email-body",
            Self::EmailAttachment => "email-attachment",
            Self::EmailHeader => "email-header",
            Self::EmailReplyTo => "email-reply-to",
            Self::EmailXMailer => "email-x-mailer",
            Self::EmailMimeBoundary => "email-mime-boundary",
            Self::EmailThreadIndex => "email-thread-index",
            Self::EmailMessageId => "email-message-id",
            Self::HttpMethod => "http-method",
            Self::UserAgent => "user-agent",
            Self::Mutex => "mutex",
            Self::Registry | Self::Regkey => "regkey",
            Self::RegkeyAndValue => "regkey|value",
            Self::WindowsServiceName => "windows-service-name",
            Self::WindowsServiceDisplayname => "windows-service-displayname",
            Self::WindowsScheduledTask => "windows-scheduled-task",
            Self::Process => "process",
            Self::ProcessState => "process-state",
            Self::NamedPipe => "named-pipe",
            Self::FilePath => "filepath",
            Self::MalwareSample => "malware-sample",
            Self::Yara => "yara",
            Self::SigmaRule => "sigma",
            Self::SnortRule => "snort",
            Self::ThreatActor => "threat-actor",
            Self::CampaignName => "campaign-name",
            Self::CampaignId => "campaign-id",
            Self::MalwareFamily => "malware-type",
            Self::Vulnerability => "vulnerability",
            Self::Weakness => "weakness",
            Self::BtcAddress => "btc",
            Self::EthAddress => "eth",
            Self::IbanCode => "iban",
            Self::Bic => "bic",
            Self::BankAccountNr => "bank-account-nr",
            Self::Asn => "AS",
            Self::Comment => "comment",
            Self::Other => "other",
            Self::Text => "text",
            Self::Link => "link",
            Self::PatternInFile => "pattern-in-file",
            Self::PatternInMemory => "pattern-in-memory",
            Self::PatternInTraffic => "pattern-in-traffic",
            Self::TargetUser => "target-user",
            Self::TargetEmail => "target-email",
            Self::TargetMachine => "target-machine",
            Self::TargetOrg => "target-org",
            Self::TargetLocation => "target-location",
            Self::TargetExternal => "target-external",
            Self::WhoisRegistrantEmail => "whois-registrant-email",
            Self::WhoisRegistrar => "whois-registrar",
            Self::WhoisRegistrantPhone => "whois-registrant-phone",
            Self::WhoisRegistrantOrg => "whois-registrant-org",
            Self::WhoisRegistrantName => "whois-registrant-name",
            Self::WhoisCreationDate => "whois-creation-date",
            Self::X509FingerprintSha1 => "x509-fingerprint-sha1",
            Self::X509FingerprintMd5 => "x509-fingerprint-md5",
            Self::X509FingerprintSha256 => "x509-fingerprint-sha256",
            Self::JarHash => "jar-manifest-md5",
            Self::Pdb => "pdb",
            // `Ip` is intentionally treated as a destination IP in MISP.
            // Use `IpSrc` or `IpDst` for explicit directionality.
            Self::Ip => "ip-dst",
        }
    }

    /// Parse from a MISP string.
    #[must_use]
    pub fn from_misp_str(s: &str) -> Option<Self> {
        Some(match s {
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha512" => Self::Sha512,
            "sha224" => Self::Sha224,
            "sha384" => Self::Sha384,
            "ssdeep" => Self::Ssdeep,
            "tlsh" => Self::Tlsh,
            "imphash" => Self::Imphash,
            "filename" => Self::Filename,
            "ip-src" => Self::IpSrc,
            "ip-dst" => Self::IpDst,
            "domain" => Self::Domain,
            "hostname" => Self::Hostname,
            "url" | "uri" => Self::Url,
            "email" => Self::Email,
            "email-src" => Self::EmailSrc,
            "email-dst" => Self::EmailDst,
            "mutex" => Self::Mutex,
            "regkey" | "regkey|value" => Self::Regkey,
            "yara" => Self::Yara,
            "malware-sample" => Self::MalwareSample,
            "threat-actor" => Self::ThreatActor,
            "vulnerability" => Self::Vulnerability,
            "btc" => Self::BtcAddress,
            "AS" => Self::Asn,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// MispDistribution
// ---------------------------------------------------------------------------

/// MISP distribution level enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MispDistributionLevel {
    /// Organisation-only.
    OrgOnly = 0,
    /// Community (MISP instance).
    Community = 1,
    /// Connected communities.
    Connected = 2,
    /// All communities.
    AllCommunities = 3,
    /// Sharing group.
    SharingGroup = 4,
    /// No distribution.
    NoDistribution = 5,
}

impl MispDistributionLevel {
    /// Return the numeric value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Parse from numeric value.
    #[must_use]
    pub const fn from_value(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::OrgOnly,
            1 => Self::Community,
            2 => Self::Connected,
            3 => Self::AllCommunities,
            4 => Self::SharingGroup,
            5 => Self::NoDistribution,
            _ => return None,
        })
    }
}

impl std::fmt::Display for MispDistributionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::OrgOnly => "Organisation only",
            Self::Community => "Community",
            Self::Connected => "Connected communities",
            Self::AllCommunities => "All communities",
            Self::SharingGroup => "Sharing group",
            Self::NoDistribution => "No distribution",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MispThreatLevelId
// ---------------------------------------------------------------------------

/// MISP threat level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MispThreatLevelId {
    /// High threat.
    High = 1,
    /// Medium threat.
    Medium = 2,
    /// Low threat.
    Low = 3,
    /// Undefined.
    Undefined = 4,
}

impl MispThreatLevelId {
    #[must_use]
    pub const fn from_value(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::High,
            2 => Self::Medium,
            3 => Self::Low,
            4 => Self::Undefined,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for MispThreatLevelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Undefined => "Undefined",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MispAnalysisLevel
// ---------------------------------------------------------------------------

/// MISP analysis status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MispAnalysisLevel {
    /// Initial analysis.
    Initial = 0,
    /// Ongoing analysis.
    Ongoing = 1,
    /// Analysis completed.
    Completed = 2,
}

impl std::fmt::Display for MispAnalysisLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Initial => "Initial",
            Self::Ongoing => "Ongoing",
            Self::Completed => "Completed",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MispOrg / MispOrgc
// ---------------------------------------------------------------------------

/// MISP organisation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispOrg {
    /// Numeric ID.
    pub id: u64,
    /// Organisation name.
    pub name: String,
    /// UUID.
    pub uuid: String,
    /// Whether this is a local organisation.
    pub local: bool,
}

/// MISP creator organisation (same structure as `MispOrg`).
pub type MispOrgc = MispOrg;

impl MispOrg {
    /// Create a minimal org record.
    #[must_use]
    pub const fn new(id: u64, name: String, uuid: String) -> Self {
        Self {
            id,
            name,
            uuid,
            local: true,
        }
    }
}

// ---------------------------------------------------------------------------
// MispGalaxyCluster
// ---------------------------------------------------------------------------

/// A MITRE ATT&CK technique or threat actor in a MISP galaxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxyCluster {
    /// Cluster UUID.
    pub uuid: String,
    /// Cluster value (technique name, actor name, etc.).
    pub value: String,
    /// Description.
    pub description: String,
    /// Cluster type.
    pub cluster_type: String,
    /// Metadata key-value pairs.
    pub meta: HashMap<String, serde_json::Value>,
    /// Tag string.
    pub tag_name: String,
}

impl MispGalaxyCluster {
    /// Create a minimal cluster.
    #[must_use]
    pub fn new(uuid: String, value: String, cluster_type: String) -> Self {
        Self {
            uuid,
            value,
            description: String::new(),
            cluster_type,
            meta: HashMap::new(),
            tag_name: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MispGalaxy
// ---------------------------------------------------------------------------

/// A MISP galaxy (collection of clusters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxy {
    /// Galaxy UUID.
    pub uuid: String,
    /// Galaxy name (e.g. "MITRE ATT&CK").
    pub name: String,
    /// Galaxy type.
    pub type_: String,
    /// Galaxy description.
    pub description: String,
    /// Clusters (techniques, actors, tools, etc.).
    pub clusters: Vec<MispGalaxyCluster>,
    /// Galaxy version.
    pub version: Option<String>,
}

impl MispGalaxy {
    /// Create a minimal galaxy.
    #[must_use]
    pub fn new(name: String, type_: String) -> Self {
        Self {
            uuid: uuid_v4_mock(),
            name,
            type_,
            description: String::new(),
            clusters: Vec::new(),
            version: None,
        }
    }

    /// Add a cluster.
    pub fn add_cluster(&mut self, cluster: MispGalaxyCluster) {
        self.clusters.push(cluster);
    }

    /// Find cluster by value.
    #[must_use]
    pub fn find_cluster(&self, value: &str) -> Option<&MispGalaxyCluster> {
        self.clusters.iter().find(|c| c.value == value)
    }
}

// ---------------------------------------------------------------------------
// MispAttributeFull
// ---------------------------------------------------------------------------

/// Full MISP attribute with all fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttributeFull {
    /// Numeric attribute ID.
    pub id: u64,
    /// UUID.
    pub uuid: String,
    /// Event ID this attribute belongs to.
    pub event_id: u64,
    /// Attribute type string.
    pub type_: String,
    /// Attribute category.
    pub category: String,
    /// Attribute value.
    pub value: String,
    /// Whether to forward to IDS.
    pub to_ids: bool,
    /// Distribution level.
    pub distribution: MispDistributionLevel,
    /// Timestamp.
    pub timestamp: u64,
    /// Optional comment.
    pub comment: Option<String>,
    /// Tags attached to this attribute.
    pub tags: Vec<MispTagSpec>,
    /// Related attributes.
    pub related_attributes: Vec<MispRelatedAttribute>,
    /// Sighting count.
    pub sightings: u32,
    /// Whether this attribute is soft-deleted.
    pub deleted: bool,
}

impl MispAttributeFull {
    /// Create a minimal attribute.
    #[must_use]
    pub fn new(id: u64, type_: String, value: String) -> Self {
        Self {
            id,
            uuid: uuid_v4_mock(),
            event_id: 0,
            type_,
            category: "Payload delivery".to_string(),
            value,
            to_ids: false,
            distribution: MispDistributionLevel::Community,
            timestamp: 0,
            comment: None,
            tags: Vec::new(),
            related_attributes: Vec::new(),
            sightings: 0,
            deleted: false,
        }
    }

    /// Parse the attribute type to an `IoCType`.
    #[must_use]
    pub fn as_ioc_type(&self) -> Option<IoCType> {
        MispApiClient::parse_misp_attribute_type(&self.type_)
    }
}

// ---------------------------------------------------------------------------
// MispRelatedAttribute
// ---------------------------------------------------------------------------

/// A related attribute reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispRelatedAttribute {
    /// Related attribute UUID.
    pub uuid: String,
    /// Related attribute type.
    pub type_: String,
    /// Related attribute value.
    pub value: String,
    /// Relationship kind.
    pub relationship_type: Option<String>,
}

// ---------------------------------------------------------------------------
// MispObjectReference
// ---------------------------------------------------------------------------

/// A reference between MISP objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectReference {
    /// UUID.
    pub uuid: String,
    /// Source object UUID.
    pub object_uuid: String,
    /// Referenced object UUID.
    pub referenced_uuid: String,
    /// Relationship type.
    pub relationship_type: String,
    /// Comment.
    pub comment: Option<String>,
}

// ---------------------------------------------------------------------------
// MispObjectFull
// ---------------------------------------------------------------------------

/// Full MISP object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectFull {
    /// Object UUID.
    pub uuid: String,
    /// Object name (template name).
    pub name: String,
    /// Meta-category.
    pub meta_category: String,
    /// Description.
    pub description: String,
    /// Attributes.
    pub attributes: Vec<MispAttributeFull>,
    /// Object references (outgoing).
    pub references: Vec<MispObjectReference>,
    /// Template UUID.
    pub template_uuid: Option<String>,
    /// Template version.
    pub template_version: Option<String>,
    /// Timestamp.
    pub timestamp: u64,
}

impl MispObjectFull {
    /// Create a minimal object.
    #[must_use]
    pub fn new(name: String, meta_category: String) -> Self {
        Self {
            uuid: uuid_v4_mock(),
            name,
            meta_category,
            description: String::new(),
            attributes: Vec::new(),
            references: Vec::new(),
            template_uuid: None,
            template_version: None,
            timestamp: 0,
        }
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, attr: MispAttributeFull) {
        self.attributes.push(attr);
    }
}

// ---------------------------------------------------------------------------
// MispSighting
// ---------------------------------------------------------------------------

/// An `IoC` sighting record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispSighting {
    /// Sighting UUID.
    pub uuid: String,
    /// Attribute UUID that was sighted.
    pub attribute_uuid: String,
    /// Sighting type: 0=sighting, 1=false-positive, 2=expiration.
    pub sighting_type: u8,
    /// Source organisation.
    pub source: Option<String>,
    /// Unix timestamp of sighting.
    pub date_sighting: u64,
    /// Organisation ID.
    pub org_id: Option<u64>,
}

impl MispSighting {
    /// Create a sighting record.
    #[must_use]
    pub fn new(attribute_uuid: String, sighting_type: u8) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            uuid: uuid_v4_mock(),
            attribute_uuid,
            sighting_type,
            source: None,
            date_sighting: now,
            org_id: None,
        }
    }

    /// Return `true` if this is a false-positive sighting.
    #[must_use]
    pub const fn is_false_positive(&self) -> bool {
        self.sighting_type == 1
    }
}

// ---------------------------------------------------------------------------
// MispSharingGroup
// ---------------------------------------------------------------------------

/// A MISP sharing group for fine-grained distribution control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispSharingGroup {
    /// Numeric ID.
    pub id: u64,
    /// UUID.
    pub uuid: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether this group is active.
    pub active: bool,
    /// Organisations in this sharing group.
    pub organisations: Vec<MispOrg>,
    /// Routing description URL.
    pub releasability: Option<String>,
}

impl MispSharingGroup {
    /// Create a minimal sharing group.
    #[must_use]
    pub fn new(id: u64, name: String) -> Self {
        Self {
            id,
            uuid: uuid_v4_mock(),
            name,
            description: String::new(),
            active: true,
            organisations: Vec::new(),
            releasability: None,
        }
    }

    /// Add an organisation to this sharing group.
    pub fn add_org(&mut self, org: MispOrg) {
        self.organisations.push(org);
    }
}

// ---------------------------------------------------------------------------
// MispFeed
// ---------------------------------------------------------------------------

/// A MISP feed definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispFeed {
    /// Numeric ID.
    pub id: u64,
    /// Feed name.
    pub name: String,
    /// Feed provider.
    pub provider: String,
    /// Feed URL.
    pub url: String,
    /// Source format.
    pub source_format: String,
    /// Whether this feed is enabled.
    pub enabled: bool,
    /// Whether this feed is cached.
    pub caching_enabled: bool,
    /// Whether to pull from this feed.
    pub pull: bool,
    /// Feed settings.
    pub settings: Option<String>,
    /// Last pull timestamp.
    pub last_pulled: Option<u64>,
}

impl MispFeed {
    /// Create a minimal feed record.
    #[must_use]
    pub fn new(id: u64, name: String, url: String) -> Self {
        Self {
            id,
            name,
            provider: String::new(),
            url,
            source_format: "misp".to_string(),
            enabled: false,
            caching_enabled: false,
            pull: false,
            settings: None,
            last_pulled: None,
        }
    }
}

// ---------------------------------------------------------------------------
// MispWarningList
// ---------------------------------------------------------------------------

/// A MISP warning list for suppressing false positives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispWarningList {
    /// Numeric ID.
    pub id: u64,
    /// List name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Entries in the list.
    pub entries: Vec<String>,
    /// Whether this list is enabled.
    pub enabled: bool,
    /// List type.
    pub list_type: String,
    /// Default value.
    pub default: bool,
}

impl MispWarningList {
    /// Create a minimal warning list.
    #[must_use]
    pub fn new(id: u64, name: String) -> Self {
        Self {
            id,
            name,
            description: String::new(),
            entries: Vec::new(),
            enabled: true,
            list_type: "string".to_string(),
            default: false,
        }
    }

    /// Check if a value matches this warning list.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        self.entries.iter().any(|e| e == value)
    }
}

// ---------------------------------------------------------------------------
// MispObjectTemplate
// ---------------------------------------------------------------------------

/// An object template for structured object creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectTemplate {
    /// Template UUID.
    pub uuid: String,
    /// Template name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Meta-category.
    pub meta_category: String,
    /// Version string.
    pub version: String,
    /// Template attributes definitions.
    pub attributes: HashMap<String, MispObjectTemplateAttribute>,
}

/// Attribute definition within an object template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectTemplateAttribute {
    /// Attribute type.
    pub misp_attribute: String,
    /// UI label.
    pub ui_priority: u32,
    /// Whether this attribute is required.
    pub required: bool,
    /// Whether multiple values are allowed.
    pub multiple: bool,
    /// Description.
    pub description: String,
}

impl MispObjectTemplate {
    /// Create a minimal template.
    #[must_use]
    pub fn new(name: String, meta_category: String) -> Self {
        Self {
            uuid: uuid_v4_mock(),
            name,
            description: String::new(),
            meta_category,
            version: "1".to_string(),
            attributes: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MispWorkflow
// ---------------------------------------------------------------------------

/// A MISP workflow for automated event processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispWorkflow {
    /// Workflow UUID.
    pub uuid: String,
    /// Workflow name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether this workflow is enabled.
    pub enabled: bool,
    /// Trigger type.
    pub trigger_id: String,
    /// Workflow steps.
    pub steps: Vec<MispWorkflowStep>,
}

/// A single step in a MISP workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispWorkflowStep {
    /// Step ID.
    pub id: u64,
    /// Module name.
    pub module_id: String,
    /// Step parameters.
    pub params: HashMap<String, serde_json::Value>,
    /// Step outputs.
    pub outputs: HashMap<String, u64>,
}

impl MispWorkflow {
    /// Create a minimal workflow.
    #[must_use]
    pub fn new(name: String, trigger_id: String) -> Self {
        Self {
            uuid: uuid_v4_mock(),
            name,
            description: String::new(),
            enabled: false,
            trigger_id,
            steps: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MispSearch
// ---------------------------------------------------------------------------

/// Builder for MISP search queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispSearch {
    /// Free text search.
    pub value: Option<String>,
    /// Attribute type filter.
    pub type_attribute: Option<String>,
    /// Category filter.
    pub category: Option<String>,
    /// Organisation filter.
    pub org: Option<String>,
    /// Tags to include (all must match).
    pub tags: Vec<String>,
    /// Tags to exclude.
    pub not_tags: Vec<String>,
    /// From date (ISO string).
    pub date_from: Option<String>,
    /// To date (ISO string).
    pub date_to: Option<String>,
    /// Threat level ID filter.
    pub threat_level_id: Option<u8>,
    /// Analysis status filter.
    pub analysis: Option<u8>,
    /// Event IDs to return.
    pub event_ids: Vec<u64>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Result page.
    pub page: Option<usize>,
    /// Whether to include to_ids-only attributes.
    pub to_ids: Option<bool>,
    /// Whether to search within objects.
    pub include_objects: bool,
}

impl MispSearch {
    /// Create an empty search query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by value.
    #[must_use]
    pub fn with_value(mut self, v: impl Into<String>) -> Self {
        self.value = Some(v.into());
        self
    }

    /// Filter by attribute type.
    #[must_use]
    pub fn with_type(mut self, t: impl Into<String>) -> Self {
        self.type_attribute = Some(t.into());
        self
    }

    /// Add an include tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add an exclude tag.
    #[must_use]
    pub fn without_tag(mut self, tag: impl Into<String>) -> Self {
        self.not_tags.push(tag.into());
        self
    }

    /// Set date range.
    #[must_use]
    pub fn with_date_range(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.date_from = Some(from.into());
        self.date_to = Some(to.into());
        self
    }

    /// Set result limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Filter by threat level.
    #[must_use]
    pub const fn with_threat_level(mut self, level: u8) -> Self {
        self.threat_level_id = Some(level);
        self
    }
}

// ---------------------------------------------------------------------------
// MispRestSearch
// ---------------------------------------------------------------------------

/// REST search request compatible with the MISP REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispRestSearch {
    /// The search parameters (wraps `MispSearch`).
    pub request: MispSearch,
    /// Format: json, csv, xml, etc.
    pub format: String,
    /// Whether to return only events (not attributes).
    pub return_format: String,
}

impl MispRestSearch {
    /// Create a default JSON REST search.
    #[must_use]
    pub fn json(search: MispSearch) -> Self {
        Self {
            request: search,
            format: "json".to_string(),
            return_format: "json".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// MispNotice / MispAuditLog
// ---------------------------------------------------------------------------

/// A MISP admin notice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispNotice {
    /// Notice ID.
    pub id: u64,
    /// Notice text.
    pub message: String,
    /// Whether this notice has been read.
    pub read: bool,
    /// Creation timestamp.
    pub created: u64,
}

/// A MISP audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAuditLog {
    /// Log entry ID.
    pub id: u64,
    /// Action performed.
    pub action: String,
    /// Model affected.
    pub model: String,
    /// Model ID affected.
    pub model_id: u64,
    /// User who performed the action.
    pub user_id: u64,
    /// Timestamp.
    pub created: u64,
    /// Change description.
    pub change: Option<String>,
}

// ---------------------------------------------------------------------------
// MispEventFull
// ---------------------------------------------------------------------------

/// Full MISP event with all sub-objects populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEventFull {
    /// Numeric MISP event ID.
    pub id: u64,
    /// UUID of this event.
    pub uuid: String,
    /// Event title / info string.
    pub info: String,
    /// Date string (YYYY-MM-DD).
    pub date: String,
    /// Threat level ID (1=High, 2=Medium, 3=Low, 4=Undefined).
    pub threat_level_id: u8,
    /// Analysis status.
    pub analysis: u8,
    /// Distribution level.
    pub distribution: MispDistributionLevel,
    /// Attributes attached to this event.
    pub attributes: Vec<MispAttributeFull>,
    /// Objects attached to this event.
    pub objects: Vec<MispObjectFull>,
    /// Tags attached to this event.
    pub tags: Vec<MispTagSpec>,
    /// Galaxies attached.
    pub galaxies: Vec<MispGalaxy>,
    /// Creating organisation.
    pub org: Option<MispOrg>,
    /// Owner organisation.
    pub orgc: Option<MispOrgc>,
    /// Whether this event is published.
    pub published: bool,
    /// Publish timestamp.
    pub publish_timestamp: Option<u64>,
    /// Creation timestamp.
    pub timestamp: u64,
    /// Event UUID (STIX-compatible).
    pub event_creator_email: Option<String>,
    /// Sharing group ID if applicable.
    pub sharing_group_id: Option<u64>,
}

impl MispEventFull {
    /// Create a minimal MISP event.
    #[must_use]
    pub fn new(info: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id: 0,
            uuid: uuid_v4_mock(),
            info,
            date: "2024-01-01".to_string(),
            threat_level_id: 4,
            analysis: 0,
            distribution: MispDistributionLevel::Community,
            attributes: Vec::new(),
            objects: Vec::new(),
            tags: Vec::new(),
            galaxies: Vec::new(),
            org: None,
            orgc: None,
            published: false,
            publish_timestamp: None,
            timestamp: now,
            event_creator_email: None,
            sharing_group_id: None,
        }
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, attr: MispAttributeFull) {
        self.attributes.push(attr);
    }

    /// Add an object.
    pub fn add_object(&mut self, obj: MispObjectFull) {
        self.objects.push(obj);
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: MispTagSpec) {
        self.tags.push(tag);
    }

    /// Return `true` if any attribute is flagged for IDS.
    #[must_use]
    pub fn has_ids_attributes(&self) -> bool {
        self.attributes.iter().any(|a| a.to_ids)
    }

    /// Count all IoC-type attributes.
    #[must_use]
    pub fn ioc_count(&self) -> usize {
        self.attributes
            .iter()
            .filter(|a| a.as_ioc_type().is_some())
            .count()
    }
}

// ---------------------------------------------------------------------------
// Original spec types (kept for backward compat)
// ---------------------------------------------------------------------------

/// Simplified MISP event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEventSpec {
    pub id: u64,
    pub uuid: String,
    pub info: String,
    pub date: String,
    pub threat_level_id: u8,
    pub attributes: Vec<MispAttributeSpec>,
    pub tags: Vec<MispTagSpec>,
}

impl MispEventSpec {
    #[must_use]
    pub fn has_ids_attributes(&self) -> bool {
        self.attributes.iter().any(|a| a.to_ids)
    }
}

/// A single attribute within a MISP event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttributeSpec {
    pub id: u64,
    pub type_field: String,
    pub value: String,
    pub comment: Option<String>,
    pub to_ids: bool,
}

/// A MISP tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTagSpec {
    pub name: String,
    pub colour: String,
    pub exportable: bool,
    pub numerical_value: Option<u32>,
}

impl MispTagSpec {
    /// Create a tag with defaults.
    #[must_use]
    pub const fn new(name: String, colour: String) -> Self {
        Self {
            name,
            colour,
            exportable: true,
            numerical_value: None,
        }
    }
}

/// A simplified MISP organisation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispOrganisation {
    pub id: u64,
    pub name: String,
    pub uuid: String,
}

// ---------------------------------------------------------------------------
// MispApiClient
// ---------------------------------------------------------------------------

/// MISP API client (mock implementation with full spec API).
pub struct MispApiClient {
    pub api_url: String,
    pub api_key: String,
    pub verify_ssl: bool,
    pub timeout_secs: u64,
}

impl MispApiClient {
    /// Create a new MISP client.
    #[must_use]
    pub const fn new(api_url: String, api_key: String) -> Self {
        Self {
            api_url,
            api_key,
            verify_ssl: true,
            timeout_secs: 30,
        }
    }

    /// Disable SSL verification (for dev instances).
    #[must_use]
    pub const fn without_ssl_verify(mut self) -> Self {
        self.verify_ssl = false;
        self
    }

    /// Set HTTP timeout.
    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Convert a MISP event into a `TiResult` for the queried `IoC`.
    fn event_to_ti_result(&self, event: &MispEventSpec, ioc: &IoC) -> TiResult {
        let mut result = TiResult::new(ioc.clone());
        let malicious = event.threat_level_id <= 2;
        result.verdicts.push(Verdict {
            malicious,
            confidence: if malicious { 70 } else { 20 },
            tags: event.tags.iter().map(|t| t.name.clone()).collect(),
            engine_count: 1,
            positive_count: u32::from(malicious),
            first_seen: None,
            last_seen: None,
            description: Some(event.info.clone()),
            provider: "misp".to_string(),
        });
        for attr in &event.attributes {
            if let Some(ioc_type) = Self::parse_misp_attribute_type(&attr.type_field)
                && (ioc_type != ioc.ioc_type || attr.value != ioc.value) {
                    let related = IoC::new(ioc_type, attr.value.clone(), "misp".to_string());
                    result.related_iocs.push(related);
                }
        }
        result
    }

    /// Build a mock MISP event for the given `IoC`.
    fn mock_event(&self, ioc: &IoC) -> MispEventSpec {
        let malicious = ioc.value.contains("evil")
            || ioc.value.contains("malware")
            || ioc.value.contains("bad");
        MispEventSpec {
            id: 1001,
            uuid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            info: format!("Mock MISP event for {}", ioc.value),
            date: "2024-01-15".to_string(),
            threat_level_id: if malicious { 1 } else { 4 },
            attributes: vec![
                MispAttributeSpec {
                    id: 1,
                    type_field: "ip-src".to_string(),
                    value: "203.0.113.1".to_string(),
                    comment: Some("Related infrastructure".to_string()),
                    to_ids: malicious,
                },
                MispAttributeSpec {
                    id: 2,
                    type_field: ioc.ioc_type.as_str().to_string(),
                    value: ioc.value.clone(),
                    comment: None,
                    to_ids: malicious,
                },
            ],
            tags: if malicious {
                vec![MispTagSpec::new(
                    "misp-galaxy:ransomware".to_string(),
                    "#FF0000".to_string(),
                )]
            } else {
                vec![]
            },
        }
    }

    /// Parse a MISP attribute type string into an [`IoCType`].
    #[must_use]
    pub fn parse_misp_attribute_type(attr_type: &str) -> Option<IoCType> {
        match attr_type {
            "md5" => Some(IoCType::Md5),
            "sha1" => Some(IoCType::Sha1),
            "sha256" => Some(IoCType::Sha256),
            "sha512" => Some(IoCType::Sha512),
            "ip-src" | "ip-dst" => Some(IoCType::Ip),
            "domain" | "hostname" => Some(IoCType::Domain),
            "url" | "uri" => Some(IoCType::Url),
            "email-src" | "email-dst" | "email" => Some(IoCType::Email),
            "regkey" | "regkey|value" => Some(IoCType::Registry),
            "filename" => Some(IoCType::Filename),
            "mutex" => Some(IoCType::Mutex),
            "yara" => Some(IoCType::Yara),
            _ => None,
        }
    }

    // ---- Async API methods ----

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a MISP event.
    pub async fn create_event(&self, event: MispEventFull) -> Result<MispEventFull, MispError> {
        // Mock: return the event with an assigned ID
        let mut e = event;
        e.id = 1;
        Ok(e)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Get an event by ID.
    pub async fn get_event(&self, id: u64) -> Result<MispEventFull, MispError> {
        let mut e = MispEventFull::new(format!("Mock event {id}"));
        e.id = id;
        Ok(e)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search events with a query.
    pub async fn search_events(
        &self,
        search: &MispSearch,
    ) -> Result<Vec<MispEventFull>, MispError> {
        // Mock: return up to 3 events
        let count = search.limit.unwrap_or(3).min(3);
        Ok((1..=(count as u64))
            .map(|i| {
                let mut e = MispEventFull::new(format!("Mock Event {i}"));
                e.id = i;
                e
            })
            .collect())
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Add an attribute to an event.
    pub async fn add_attribute(
        &self,
        event_id: u64,
        attr: MispAttributeFull,
    ) -> Result<MispAttributeFull, MispError> {
        let mut a = attr;
        a.event_id = event_id;
        Ok(a)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Add a tag to an event.
    pub async fn add_tag(&self, event_id: u64, tag: &str) -> Result<bool, MispError> {
        let _ = event_id;
        let _ = tag;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Publish an event.
    pub async fn publish_event(&self, event_id: u64) -> Result<bool, MispError> {
        let _ = event_id;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Get a feed by ID.
    pub async fn get_feed(&self, id: u64) -> Result<MispFeed, MispError> {
        Ok(MispFeed::new(
            id,
            format!("Feed {id}"),
            "https://example.com/feed".to_string(),
        ))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Trigger a server pull from a remote MISP.
    pub async fn pull_server(&self, server_id: u64) -> Result<bool, MispError> {
        let _ = server_id;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Get a galaxy by name.
    pub async fn get_galaxy(&self, name: &str) -> Result<MispGalaxy, MispError> {
        let galaxy = MispGalaxy::new(name.to_string(), "mitre-attack".to_string());
        Ok(galaxy)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Attach a galaxy cluster to an event.
    pub async fn attach_galaxy_cluster(
        &self,
        event_id: u64,
        cluster_uuid: &str,
    ) -> Result<bool, MispError> {
        let _ = event_id;
        let _ = cluster_uuid;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Record a sighting for an attribute.
    pub async fn add_sighting(
        &self,
        attribute_uuid: &str,
        sighting_type: u8,
    ) -> Result<MispSighting, MispError> {
        Ok(MispSighting::new(attribute_uuid.to_string(), sighting_type))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// List warning lists.
    pub async fn list_warning_lists(&self) -> Result<Vec<MispWarningList>, MispError> {
        Ok(vec![{
            let mut wl = MispWarningList::new(1, "Top 1000 domains".to_string());
            wl.entries = vec!["google.com".to_string(), "microsoft.com".to_string()];
            wl
        }])
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Check if a value is in any enabled warning list.
    pub async fn check_warning_lists(&self, value: &str) -> Result<bool, MispError> {
        // Mock: google.com and microsoft.com are in warning lists
        Ok(value.contains("google") || value.contains("microsoft"))
    }
}

#[async_trait]
impl TiProvider for MispApiClient {
    fn name(&self) -> &'static str {
        "misp"
    }

    fn supported_ioc_types(&self) -> Vec<IoCType> {
        vec![
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Sha512,
            IoCType::Ip,
            IoCType::Domain,
            IoCType::Url,
            IoCType::Email,
        ]
    }

    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError> {
        let event = self.mock_event(ioc);
        Ok(self.event_to_ti_result(&event, ioc))
    }

    fn rate_limit_per_minute(&self) -> u32 {
        120
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a RFC-4122-compliant `UUIDv4` string for production use.
/// In test builds a sequential counter is used for determinism.
fn uuid_v4_mock() -> String {
    #[cfg(not(test))]
    {
        uuid::Uuid::new_v4().to_string()
    }
    #[cfg(test)]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Deterministic placeholder for tests only — not sent to a real MISP instance.
        format!("00000000-0000-4000-8000-{n:012x}")
    }
}

// ---------------------------------------------------------------------------
// Tests (35+)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::IoCType;

    fn client() -> MispApiClient {
        MispApiClient::new(
            "https://misp.example.com".to_string(),
            "test-key".to_string(),
        )
    }

    fn hash_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Sha256, val.to_string(), "test".to_string())
    }

    fn ip_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Ip, val.to_string(), "test".to_string())
    }

    // ---- MispApiClient basics ----

    #[test]
    fn test_client_new() {
        let c = client();
        assert_eq!(c.api_url, "https://misp.example.com");
        assert_eq!(c.api_key, "test-key");
    }

    #[test]
    fn test_provider_name() {
        assert_eq!(client().name(), "misp");
    }

    #[test]
    fn test_provider_rate_limit() {
        assert_eq!(client().rate_limit_per_minute(), 120);
    }

    #[test]
    fn test_supported_types_contains_sha256() {
        assert!(client().supported_ioc_types().contains(&IoCType::Sha256));
    }

    // ---- parse_misp_attribute_type ----

    #[test]
    fn test_parse_md5() {
        assert_eq!(
            MispApiClient::parse_misp_attribute_type("md5"),
            Some(IoCType::Md5)
        );
    }

    #[test]
    fn test_parse_ip_dst() {
        assert_eq!(
            MispApiClient::parse_misp_attribute_type("ip-dst"),
            Some(IoCType::Ip)
        );
    }

    #[test]
    fn test_parse_domain() {
        assert_eq!(
            MispApiClient::parse_misp_attribute_type("domain"),
            Some(IoCType::Domain)
        );
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(
            MispApiClient::parse_misp_attribute_type("unknown-type"),
            None
        );
    }

    // ---- async API ----

    #[tokio::test]
    async fn test_create_event() {
        let e = MispEventFull::new("Test event".to_string());
        let result = client().create_event(e).await.unwrap();
        assert_eq!(result.id, 1);
    }

    #[tokio::test]
    async fn test_get_event() {
        let e = client().get_event(42).await.unwrap();
        assert_eq!(e.id, 42);
    }

    #[tokio::test]
    async fn test_search_events() {
        let search = MispSearch::new().with_limit(2);
        let events = client().search_events(&search).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_add_attribute() {
        let attr = MispAttributeFull::new(0, "sha256".to_string(), "deadbeef".to_string());
        let result = client().add_attribute(99, attr).await.unwrap();
        assert_eq!(result.event_id, 99);
    }

    #[tokio::test]
    async fn test_add_tag() {
        let ok = client().add_tag(1, "malware").await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_publish_event() {
        let ok = client().publish_event(1).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_get_feed() {
        let feed = client().get_feed(1).await.unwrap();
        assert_eq!(feed.id, 1);
    }

    #[tokio::test]
    async fn test_pull_server() {
        let ok = client().pull_server(1).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_get_galaxy() {
        let g = client().get_galaxy("MITRE ATT&CK").await.unwrap();
        assert_eq!(g.name, "MITRE ATT&CK");
    }

    #[tokio::test]
    async fn test_attach_galaxy_cluster() {
        let ok = client()
            .attach_galaxy_cluster(1, "some-uuid")
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_add_sighting() {
        let s = client().add_sighting("attr-uuid", 0).await.unwrap();
        assert_eq!(s.attribute_uuid, "attr-uuid");
        assert!(!s.is_false_positive());
    }

    #[tokio::test]
    async fn test_add_false_positive_sighting() {
        let s = client().add_sighting("attr-uuid", 1).await.unwrap();
        assert!(s.is_false_positive());
    }

    #[tokio::test]
    async fn test_check_warning_lists_match() {
        let matched = client().check_warning_lists("google.com").await.unwrap();
        assert!(matched);
    }

    #[tokio::test]
    async fn test_check_warning_lists_no_match() {
        let matched = client()
            .check_warning_lists("evil.example.com")
            .await
            .unwrap();
        assert!(!matched);
    }

    #[tokio::test]
    async fn test_lookup_returns_result() {
        let ioc = hash_ioc("testvalue");
        let result = client().lookup(&ioc).await.unwrap();
        assert_eq!(result.ioc.value, "testvalue");
    }

    #[tokio::test]
    async fn test_bulk_lookup() {
        let iocs = vec![hash_ioc("a"), hash_ioc("b"), ip_ioc("1.2.3.4")];
        let results = client().bulk_lookup(&iocs).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    // ---- MispDistributionLevel ----

    #[test]
    fn test_distribution_level_values() {
        assert_eq!(MispDistributionLevel::OrgOnly.value(), 0);
        assert_eq!(MispDistributionLevel::Community.value(), 1);
        assert_eq!(MispDistributionLevel::AllCommunities.value(), 3);
    }

    #[test]
    fn test_distribution_level_from_value() {
        assert_eq!(
            MispDistributionLevel::from_value(0),
            Some(MispDistributionLevel::OrgOnly)
        );
        assert_eq!(MispDistributionLevel::from_value(99), None);
    }

    // ---- MispThreatLevelId ----

    #[test]
    fn test_threat_level_display() {
        assert_eq!(MispThreatLevelId::High.to_string(), "High");
        assert_eq!(MispThreatLevelId::Low.to_string(), "Low");
    }

    #[test]
    fn test_threat_level_from_value() {
        assert_eq!(
            MispThreatLevelId::from_value(1),
            Some(MispThreatLevelId::High)
        );
    }

    // ---- MispAttributeType ----

    #[test]
    fn test_attribute_type_as_misp_str() {
        assert_eq!(MispAttributeType::Md5.as_misp_str(), "md5");
        assert_eq!(MispAttributeType::IpSrc.as_misp_str(), "ip-src");
    }

    #[test]
    fn test_attribute_type_from_misp_str() {
        assert_eq!(
            MispAttributeType::from_misp_str("md5"),
            Some(MispAttributeType::Md5)
        );
        assert_eq!(MispAttributeType::from_misp_str("unknown"), None);
    }

    // ---- MispSearch builder ----

    #[test]
    fn test_search_builder() {
        let s = MispSearch::new()
            .with_value("emotet")
            .with_type("sha256")
            .with_tag("malware")
            .without_tag("false-positive")
            .with_limit(100);
        assert_eq!(s.value.as_deref(), Some("emotet"));
        assert_eq!(s.limit, Some(100));
        assert!(s.tags.contains(&"malware".to_string()));
        assert!(s.not_tags.contains(&"false-positive".to_string()));
    }

    // ---- MispEventFull ----

    #[test]
    fn test_event_full_new() {
        let e = MispEventFull::new("Test".to_string());
        assert_eq!(e.info, "Test");
        assert!(!e.published);
        assert!(e.attributes.is_empty());
    }

    #[test]
    fn test_event_full_ioc_count() {
        let mut e = MispEventFull::new("Test".to_string());
        e.add_attribute(MispAttributeFull::new(
            1,
            "sha256".to_string(),
            "abc".to_string(),
        ));
        e.add_attribute(MispAttributeFull::new(
            2,
            "comment".to_string(),
            "note".to_string(),
        ));
        assert_eq!(e.ioc_count(), 1);
    }

    // ---- MispWarningList ----

    #[test]
    fn test_warning_list_matches() {
        let mut wl = MispWarningList::new(1, "Test List".to_string());
        wl.entries = vec!["8.8.8.8".to_string()];
        assert!(wl.matches("8.8.8.8"));
        assert!(!wl.matches("1.1.1.1"));
    }

    // ---- MispGalaxy ----

    #[test]
    fn test_galaxy_find_cluster() {
        let mut g = MispGalaxy::new("MITRE ATT&CK".to_string(), "mitre-attack".to_string());
        g.add_cluster(MispGalaxyCluster::new(
            "uuid1".to_string(),
            "T1055".to_string(),
            "technique".to_string(),
        ));
        assert!(g.find_cluster("T1055").is_some());
        assert!(g.find_cluster("T9999").is_none());
    }

    // ---- MispOrg ----

    #[test]
    fn test_org_creation() {
        let org = MispOrg::new(1, "ACME Security".to_string(), "org-uuid".to_string());
        assert_eq!(org.name, "ACME Security");
        assert!(org.local);
    }

    // ---- MispSharingGroup ----

    #[test]
    fn test_sharing_group() {
        let mut sg = MispSharingGroup::new(1, "ISAC Group".to_string());
        sg.add_org(MispOrg::new(1, "Org A".to_string(), "uuid-a".to_string()));
        assert_eq!(sg.organisations.len(), 1);
    }

    // ---- MispEventSpec backward compat ----

    #[test]
    fn test_event_spec_has_ids() {
        let event = MispEventSpec {
            id: 1,
            uuid: "u".to_string(),
            info: "T".to_string(),
            date: "2024-01-01".to_string(),
            threat_level_id: 1,
            attributes: vec![MispAttributeSpec {
                id: 1,
                type_field: "md5".to_string(),
                value: "abc".to_string(),
                comment: None,
                to_ids: true,
            }],
            tags: vec![],
        };
        assert!(event.has_ids_attributes());
    }

    // ---- Mock event / lookup ----

    #[test]
    fn test_mock_event_malicious() {
        let ioc = hash_ioc("evil_hash");
        let event = client().mock_event(&ioc);
        assert_eq!(event.threat_level_id, 1);
        assert!(!event.tags.is_empty());
    }

    #[test]
    fn test_mock_event_clean() {
        let ioc = hash_ioc("safe_hash");
        let event = client().mock_event(&ioc);
        assert_eq!(event.threat_level_id, 4);
    }

    // ---- Serde ----

    #[test]
    fn test_event_spec_serde() {
        let event = MispEventSpec {
            id: 1,
            uuid: "uuid".to_string(),
            info: "Test Event".to_string(),
            date: "2024-01-01".to_string(),
            threat_level_id: 2,
            attributes: vec![],
            tags: vec![],
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: MispEventSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.info, "Test Event");
    }

    #[test]
    fn test_organisation_serde() {
        let org = MispOrganisation {
            id: 1,
            name: "ACME".to_string(),
            uuid: "org-uuid".to_string(),
        };
        let json = serde_json::to_string(&org).unwrap();
        let decoded: MispOrganisation = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "ACME");
    }
}
