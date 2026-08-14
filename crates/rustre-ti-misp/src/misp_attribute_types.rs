//! MISP attribute type catalogue with `IoC` classification, category mapping,
//! and STIX-2.1 pattern generation.
//!
//! Covers 80+ MISP attribute types defined in the official MISP taxonomy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── AttributeCategory ────────────────────────────────────────────────────────

/// The MISP attribute category that classifies an attribute's role in an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributeCategory {
    /// File- or memory-related hashes.
    Antivirus,
    /// Attribution-related intelligence.
    Attribution,
    /// External analysis data.
    ExternalAnalysis,
    /// File-based artefacts.
    Payload,
    /// Network indicators.
    Network,
    /// Email indicators.
    Email,
    /// Host-based artifacts.
    Artifacts,
    /// Social media / persona identifiers.
    SocialNetwork,
    /// Financial intelligence.
    Financial,
    /// Support-and-reporting tickets.
    Support,
    /// Targeting information.
    Targeting,
    /// Threat actor attribution.
    Actor,
    /// Payload delivery mechanisms.
    PayloadDelivery,
    /// Free-text or informational.
    Other,
}

impl AttributeCategory {
    /// Return the canonical MISP category string.
    #[must_use]
    pub const fn as_misp_str(&self) -> &'static str {
        match self {
            Self::Antivirus => "Antivirus detection",
            Self::Attribution => "Attribution",
            Self::ExternalAnalysis => "External analysis",
            Self::Payload => "Payload installation",
            Self::Network => "Network activity",
            Self::Email => "Payload delivery",
            Self::Artifacts => "Artifacts dropped",
            Self::SocialNetwork => "Social network",
            Self::Financial => "Financial fraud",
            Self::Support => "Support Tool",
            Self::Targeting => "Targeting data",
            Self::Actor => "Attribution",
            Self::PayloadDelivery => "Payload delivery",
            Self::Other => "Other",
        }
    }

    /// Parse a MISP category string.
    #[must_use]
    pub fn from_misp_str(s: &str) -> Self {
        match s {
            "Antivirus detection" => Self::Antivirus,
            "Attribution" => Self::Attribution,
            "External analysis" => Self::ExternalAnalysis,
            "Payload installation" => Self::Payload,
            "Network activity" => Self::Network,
            "Payload delivery" => Self::PayloadDelivery,
            "Artifacts dropped" => Self::Artifacts,
            "Social network" => Self::SocialNetwork,
            "Financial fraud" => Self::Financial,
            "Targeting data" => Self::Targeting,
            _ => Self::Other,
        }
    }
}

// ── MispAttributeType (extended) ─────────────────────────────────────────────

/// Extended enumeration of 80+ MISP attribute types as defined in the
/// official MISP taxonomy (misp/misp-taxonomies).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MispAttrType {
    // ── Hash types ───────────────────────────────────────────────────────────
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
    Cdhash,
    Telfhash,
    // ── Filename / composite ─────────────────────────────────────────────────
    Filename,
    FilenameAndMd5,
    FilenameAndSha1,
    FilenameAndSha256,
    FilenameAndSha512,
    FilenameAndSsdeep,
    FilenameAndImphash,
    FilenameAndTlsh,
    FilenameAndAuthentihash,
    // ── Network ──────────────────────────────────────────────────────────────
    IpSrc,
    IpDst,
    IpSrcPort,
    IpDstPort,
    Domain,
    DomainIp,
    Hostname,
    Url,
    Uri,
    Asn,
    CidrBlock,
    Mac,
    // ── Email ─────────────────────────────────────────────────────────────────
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
    // ── HTTP / protocol ───────────────────────────────────────────────────────
    HttpMethod,
    UserAgent,
    Cookie,
    JarmHash,
    Ja3,
    Hassh,
    HasshServer,
    // ── Windows host artifacts ────────────────────────────────────────────────
    Mutex,
    Regkey,
    RegkeyAndValue,
    WindowsServiceName,
    WindowsServiceDisplayname,
    WindowsScheduledTask,
    Process,
    ProcessState,
    NamedPipe,
    FilePath,
    WindowsToken,
    PeSection,
    // ── Malware / rule ────────────────────────────────────────────────────────
    MalwareSample,
    Yara,
    SigmaRule,
    SnortRule,
    SuricataRule,
    // ── Threat actor / intelligence ───────────────────────────────────────────
    ThreatActor,
    CampaignName,
    CampaignId,
    MalwareFamily,
    // ── Vulnerability — CVE identifiers share the "vulnerability" MISP type
    // so Cve has been collapsed into Vulnerability.
    Vulnerability,
    Weakness,
    // ── Certificate ───────────────────────────────────────────────────────────
    X509FingerprintSha1,
    X509FingerprintMd5,
    X509FingerprintSha256,
    // ── Finance ───────────────────────────────────────────────────────────────
    BtcAddress,
    EthAddress,
    XmrAddress,
    IbanCode,
    Bic,
    BankAccountNr,
    CcNumber,
    // ── Whois ─────────────────────────────────────────────────────────────────
    WhoisRegistrantEmail,
    WhoisRegistrar,
    WhoisRegistrantPhone,
    WhoisRegistrantOrg,
    WhoisRegistrantName,
    WhoisCreationDate,
    WhoisNameserver,
    // ── Pattern ───────────────────────────────────────────────────────────────
    PatternInFile,
    PatternInMemory,
    PatternInTraffic,
    // ── Targeting ─────────────────────────────────────────────────────────────
    TargetUser,
    TargetEmail,
    TargetMachine,
    TargetOrg,
    TargetLocation,
    TargetExternal,
    // ── Other ─────────────────────────────────────────────────────────────────
    Comment,
    Text,
    Link,
    Pdb,
    JarHash,
    Other,
    Ip,
    Port,
    Size,
    Counter,
    DateTime,
    Attachment,
    MalwareType,
    AsnIp,
}

impl MispAttrType {
    /// Return the official MISP type string for this attribute type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
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
            Self::Cdhash => "cdhash",
            Self::Telfhash => "telfhash",
            Self::Filename => "filename",
            Self::FilenameAndMd5 => "filename|md5",
            Self::FilenameAndSha1 => "filename|sha1",
            Self::FilenameAndSha256 => "filename|sha256",
            Self::FilenameAndSha512 => "filename|sha512",
            Self::FilenameAndSsdeep => "filename|ssdeep",
            Self::FilenameAndImphash => "filename|imphash",
            Self::FilenameAndTlsh => "filename|tlsh",
            Self::FilenameAndAuthentihash => "filename|authentihash",
            Self::IpSrc => "ip-src",
            Self::IpDst => "ip-dst",
            Self::IpSrcPort => "ip-src|port",
            Self::IpDstPort => "ip-dst|port",
            Self::Domain => "domain",
            Self::DomainIp => "domain|ip",
            Self::Hostname => "hostname",
            Self::Url => "url",
            Self::Uri => "uri",
            Self::Asn => "AS",
            Self::CidrBlock => "cidr",
            Self::Mac => "mac-address",
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
            Self::Cookie => "cookie",
            Self::JarmHash => "jarm",
            Self::Ja3 => "ja3-fingerprint-md5",
            Self::Hassh => "hassh-md5",
            Self::HasshServer => "hasshserver-md5",
            Self::Mutex => "mutex",
            Self::Regkey => "regkey",
            Self::RegkeyAndValue => "regkey|value",
            Self::WindowsServiceName => "windows-service-name",
            Self::WindowsServiceDisplayname => "windows-service-displayname",
            Self::WindowsScheduledTask => "windows-scheduled-task",
            Self::Process => "process-state",
            Self::ProcessState => "process-state",
            Self::NamedPipe => "named-pipe",
            Self::FilePath => "filepath",
            Self::WindowsToken => "windows-token",
            Self::PeSection => "pattern-in-file",
            Self::MalwareSample => "malware-sample",
            Self::Yara => "yara",
            Self::SigmaRule => "sigma",
            Self::SnortRule => "snort",
            Self::SuricataRule => "suricata",
            Self::ThreatActor => "threat-actor",
            Self::CampaignName => "campaign-name",
            Self::CampaignId => "campaign-id",
            Self::MalwareFamily => "malware-type",
            Self::Vulnerability => "vulnerability",
            Self::Weakness => "weakness",
            Self::X509FingerprintSha1 => "x509-fingerprint-sha1",
            Self::X509FingerprintMd5 => "x509-fingerprint-md5",
            Self::X509FingerprintSha256 => "x509-fingerprint-sha256",
            Self::BtcAddress => "btc",
            Self::EthAddress => "eth",
            Self::XmrAddress => "xmr",
            Self::IbanCode => "iban",
            Self::Bic => "bic",
            Self::BankAccountNr => "bank-account-nr",
            Self::CcNumber => "cc-number",
            Self::WhoisRegistrantEmail => "whois-registrant-email",
            Self::WhoisRegistrar => "whois-registrar",
            Self::WhoisRegistrantPhone => "whois-registrant-phone",
            Self::WhoisRegistrantOrg => "whois-registrant-org",
            Self::WhoisRegistrantName => "whois-registrant-name",
            Self::WhoisCreationDate => "whois-creation-date",
            Self::WhoisNameserver => "whois-nameserver",
            Self::PatternInFile => "pattern-in-file",
            Self::PatternInMemory => "pattern-in-memory",
            Self::PatternInTraffic => "pattern-in-traffic",
            Self::TargetUser => "target-user",
            Self::TargetEmail => "target-email",
            Self::TargetMachine => "target-machine",
            Self::TargetOrg => "target-org",
            Self::TargetLocation => "target-location",
            Self::TargetExternal => "target-external",
            Self::Comment => "comment",
            Self::Text => "text",
            Self::Link => "link",
            Self::Pdb => "pdb",
            Self::JarHash => "jar-manifest-md5",
            Self::Other => "other",
            Self::Ip => "ip-dst",
            Self::Port => "port",
            Self::Size => "size-in-bytes",
            Self::Counter => "counter",
            Self::DateTime => "datetime",
            Self::Attachment => "attachment",
            Self::MalwareType => "malware-type",
            Self::AsnIp => "AS",
        }
    }

    /// Parse from the official MISP type string.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha512" => Self::Sha512,
            "sha224" => Self::Sha224,
            "sha384" => Self::Sha384,
            "sha3-224" => Self::Sha3224,
            "sha3-256" => Self::Sha3256,
            "sha3-384" => Self::Sha3384,
            "sha3-512" => Self::Sha3512,
            "ssdeep" => Self::Ssdeep,
            "tlsh" => Self::Tlsh,
            "authentihash" => Self::Authentihash,
            "imphash" => Self::Imphash,
            "pehash" => Self::Pehash,
            "vhash" => Self::Vhash,
            "cdhash" => Self::Cdhash,
            "telfhash" => Self::Telfhash,
            "filename" => Self::Filename,
            "filename|md5" => Self::FilenameAndMd5,
            "filename|sha1" => Self::FilenameAndSha1,
            "filename|sha256" => Self::FilenameAndSha256,
            "filename|sha512" => Self::FilenameAndSha512,
            "filename|ssdeep" => Self::FilenameAndSsdeep,
            "filename|imphash" => Self::FilenameAndImphash,
            "filename|tlsh" => Self::FilenameAndTlsh,
            "filename|authentihash" => Self::FilenameAndAuthentihash,
            "ip-src" => Self::IpSrc,
            "ip-dst" => Self::IpDst,
            "ip-src|port" => Self::IpSrcPort,
            "ip-dst|port" => Self::IpDstPort,
            "domain" => Self::Domain,
            "domain|ip" => Self::DomainIp,
            "hostname" => Self::Hostname,
            "url" => Self::Url,
            "uri" => Self::Uri,
            "AS" => Self::Asn,
            "cidr" => Self::CidrBlock,
            "mac-address" => Self::Mac,
            "email" => Self::Email,
            "email-src" => Self::EmailSrc,
            "email-dst" => Self::EmailDst,
            "email-subject" => Self::EmailSubject,
            "email-body" => Self::EmailBody,
            "email-attachment" => Self::EmailAttachment,
            "email-header" => Self::EmailHeader,
            "email-reply-to" => Self::EmailReplyTo,
            "email-x-mailer" => Self::EmailXMailer,
            "email-mime-boundary" => Self::EmailMimeBoundary,
            "email-thread-index" => Self::EmailThreadIndex,
            "email-message-id" => Self::EmailMessageId,
            "http-method" => Self::HttpMethod,
            "user-agent" => Self::UserAgent,
            "cookie" => Self::Cookie,
            "jarm" => Self::JarmHash,
            "ja3-fingerprint-md5" => Self::Ja3,
            "hassh-md5" => Self::Hassh,
            "hasshserver-md5" => Self::HasshServer,
            "mutex" => Self::Mutex,
            "regkey" => Self::Regkey,
            "regkey|value" => Self::RegkeyAndValue,
            "windows-service-name" => Self::WindowsServiceName,
            "windows-service-displayname" => Self::WindowsServiceDisplayname,
            "windows-scheduled-task" => Self::WindowsScheduledTask,
            "process-state" => Self::ProcessState,
            "named-pipe" => Self::NamedPipe,
            "filepath" => Self::FilePath,
            "malware-sample" => Self::MalwareSample,
            "yara" => Self::Yara,
            "sigma" => Self::SigmaRule,
            "snort" => Self::SnortRule,
            "suricata" => Self::SuricataRule,
            "threat-actor" => Self::ThreatActor,
            "campaign-name" => Self::CampaignName,
            "campaign-id" => Self::CampaignId,
            "malware-type" => Self::MalwareFamily,
            "vulnerability" => Self::Vulnerability,
            "weakness" => Self::Weakness,
            "x509-fingerprint-sha1" => Self::X509FingerprintSha1,
            "x509-fingerprint-md5" => Self::X509FingerprintMd5,
            "x509-fingerprint-sha256" => Self::X509FingerprintSha256,
            "btc" => Self::BtcAddress,
            "eth" => Self::EthAddress,
            "xmr" => Self::XmrAddress,
            "iban" => Self::IbanCode,
            "bic" => Self::Bic,
            "bank-account-nr" => Self::BankAccountNr,
            "cc-number" => Self::CcNumber,
            "whois-registrant-email" => Self::WhoisRegistrantEmail,
            "whois-registrar" => Self::WhoisRegistrar,
            "whois-registrant-phone" => Self::WhoisRegistrantPhone,
            "whois-registrant-org" => Self::WhoisRegistrantOrg,
            "whois-registrant-name" => Self::WhoisRegistrantName,
            "whois-creation-date" => Self::WhoisCreationDate,
            "whois-nameserver" => Self::WhoisNameserver,
            "pattern-in-file" => Self::PatternInFile,
            "pattern-in-memory" => Self::PatternInMemory,
            "pattern-in-traffic" => Self::PatternInTraffic,
            "target-user" => Self::TargetUser,
            "target-email" => Self::TargetEmail,
            "target-machine" => Self::TargetMachine,
            "target-org" => Self::TargetOrg,
            "target-location" => Self::TargetLocation,
            "target-external" => Self::TargetExternal,
            "comment" => Self::Comment,
            "text" => Self::Text,
            "link" => Self::Link,
            "pdb" => Self::Pdb,
            "jar-manifest-md5" => Self::JarHash,
            "other" => Self::Other,
            "port" => Self::Port,
            "size-in-bytes" => Self::Size,
            "counter" => Self::Counter,
            "datetime" => Self::DateTime,
            "attachment" => Self::Attachment,
            _ => return None,
        })
    }

    /// Return `true` if this attribute type is typically used as an `IoC`
    /// suitable for IDS/SIEM rule generation.
    #[must_use]
    pub const fn is_ioc(&self) -> bool {
        matches!(
            self,
            Self::Md5
                | Self::Sha1
                | Self::Sha256
                | Self::Sha512
                | Self::Sha224
                | Self::Sha384
                | Self::Ssdeep
                | Self::Tlsh
                | Self::Authentihash
                | Self::Imphash
                | Self::FilenameAndMd5
                | Self::FilenameAndSha1
                | Self::FilenameAndSha256
                | Self::IpSrc
                | Self::IpDst
                | Self::IpSrcPort
                | Self::IpDstPort
                | Self::Domain
                | Self::DomainIp
                | Self::Hostname
                | Self::Url
                | Self::EmailSrc
                | Self::EmailDst
                | Self::Mutex
                | Self::Regkey
                | Self::RegkeyAndValue
                | Self::BtcAddress
                | Self::EthAddress
                | Self::X509FingerprintSha1
                | Self::X509FingerprintSha256
                | Self::Ja3
                | Self::JarmHash
        )
    }

    /// Return the default [`AttributeCategory`] for this type.
    #[must_use]
    pub const fn default_category(&self) -> AttributeCategory {
        match self {
            Self::Md5
            | Self::Sha1
            | Self::Sha256
            | Self::Sha512
            | Self::Sha224
            | Self::Sha384
            | Self::Ssdeep
            | Self::Tlsh
            | Self::Authentihash
            | Self::Imphash
            | Self::Pehash
            | Self::Vhash
            | Self::Cdhash
            | Self::Telfhash
            | Self::Sha3224
            | Self::Sha3256
            | Self::Sha3384
            | Self::Sha3512
            | Self::FilenameAndMd5
            | Self::FilenameAndSha1
            | Self::FilenameAndSha256
            | Self::FilenameAndSha512
            | Self::FilenameAndSsdeep
            | Self::FilenameAndImphash
            | Self::FilenameAndTlsh
            | Self::FilenameAndAuthentihash
            | Self::Filename
            | Self::FilePath
            | Self::MalwareSample => AttributeCategory::Payload,

            Self::IpSrc
            | Self::IpDst
            | Self::IpSrcPort
            | Self::IpDstPort
            | Self::Domain
            | Self::DomainIp
            | Self::Hostname
            | Self::Url
            | Self::Uri
            | Self::Asn
            | Self::CidrBlock
            | Self::Mac
            | Self::HttpMethod
            | Self::UserAgent
            | Self::Cookie
            | Self::JarmHash
            | Self::Ja3
            | Self::Hassh
            | Self::HasshServer => AttributeCategory::Network,

            Self::Email
            | Self::EmailSrc
            | Self::EmailDst
            | Self::EmailSubject
            | Self::EmailBody
            | Self::EmailAttachment
            | Self::EmailHeader
            | Self::EmailReplyTo
            | Self::EmailXMailer
            | Self::EmailMimeBoundary
            | Self::EmailThreadIndex
            | Self::EmailMessageId => AttributeCategory::Email,

            Self::Mutex
            | Self::Regkey
            | Self::RegkeyAndValue
            | Self::WindowsServiceName
            | Self::WindowsServiceDisplayname
            | Self::WindowsScheduledTask
            | Self::Process
            | Self::ProcessState
            | Self::NamedPipe
            | Self::WindowsToken
            | Self::PeSection
            | Self::Pdb => AttributeCategory::Artifacts,

            Self::Yara | Self::SigmaRule | Self::SnortRule | Self::SuricataRule => {
                AttributeCategory::ExternalAnalysis
            }

            Self::ThreatActor | Self::CampaignName | Self::CampaignId | Self::MalwareFamily => {
                AttributeCategory::Attribution
            }

            Self::Vulnerability | Self::Weakness => AttributeCategory::ExternalAnalysis,

            Self::BtcAddress
            | Self::EthAddress
            | Self::XmrAddress
            | Self::IbanCode
            | Self::Bic
            | Self::BankAccountNr
            | Self::CcNumber => AttributeCategory::Financial,

            Self::WhoisRegistrantEmail
            | Self::WhoisRegistrar
            | Self::WhoisRegistrantPhone
            | Self::WhoisRegistrantOrg
            | Self::WhoisRegistrantName
            | Self::WhoisCreationDate
            | Self::WhoisNameserver => AttributeCategory::Attribution,

            Self::X509FingerprintSha1
            | Self::X509FingerprintMd5
            | Self::X509FingerprintSha256 => AttributeCategory::Network,

            Self::TargetUser
            | Self::TargetEmail
            | Self::TargetMachine
            | Self::TargetOrg
            | Self::TargetLocation
            | Self::TargetExternal => AttributeCategory::Targeting,

            Self::PatternInFile | Self::PatternInMemory | Self::PatternInTraffic => {
                AttributeCategory::Artifacts
            }

            _ => AttributeCategory::Other,
        }
    }

    /// Generate a STIX 2.1 pattern fragment for the given `value`.
    ///
    /// Returns `None` for types that do not have a natural STIX mapping.
    #[must_use]
    pub fn to_stix_pattern(&self, value: &str) -> Option<String> {
        let esc = value.replace('\'', "\\'");
        Some(match self {
            Self::Md5 => format!("[file:hashes.MD5 = '{esc}']"),
            Self::Sha1 => format!("[file:hashes.SHA-1 = '{esc}']"),
            Self::Sha256 => format!("[file:hashes.SHA-256 = '{esc}']"),
            Self::Sha512 => format!("[file:hashes.SHA-512 = '{esc}']"),
            Self::Ssdeep => format!("[file:hashes.SSDEEP = '{esc}']"),
            Self::Tlsh => format!("[file:hashes.TLSH = '{esc}']"),
            Self::Imphash => format!("[file:hashes.'ImpHash' = '{esc}']"),
            Self::Authentihash => format!("[file:hashes.Authentihash = '{esc}']"),
            Self::Filename => format!("[file:name = '{esc}']"),
            Self::FilePath => format!("[file:parent_directory_ref.path = '{esc}']"),
            Self::IpSrc => format!("[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{esc}']"),
            Self::IpDst => format!("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{esc}']"),
            Self::Domain => format!("[domain-name:value = '{esc}']"),
            Self::Hostname => format!("[domain-name:value = '{esc}']"),
            Self::Url => format!("[url:value = '{esc}']"),
            Self::EmailSrc => format!("[email-message:from_ref.value = '{esc}']"),
            Self::EmailDst => format!("[email-message:to_refs[*].value = '{esc}']"),
            Self::EmailSubject => format!("[email-message:subject = '{esc}']"),
            Self::Mutex => format!("[mutex:name = '{esc}']"),
            Self::Regkey => format!("[windows-registry-key:key = '{esc}']"),
            Self::RegkeyAndValue => {
                let parts: Vec<&str> = value.splitn(2, '|').collect();
                if parts.len() == 2 {
                    format!("[windows-registry-key:key = '{}' AND windows-registry-key:values[*].data = '{}']",
                        parts[0].replace('\'', "\\'"),
                        parts[1].replace('\'', "\\'"))
                } else {
                    format!("[windows-registry-key:key = '{esc}']")
                }
            }
            Self::X509FingerprintSha256 => {
                format!("[x509-certificate:hashes.SHA-256 = '{esc}']")
            }
            Self::X509FingerprintSha1 => {
                format!("[x509-certificate:hashes.SHA-1 = '{esc}']")
            }
            Self::Vulnerability => {
                format!("[vulnerability:name = '{esc}']")
            }
            Self::BtcAddress => format!("[cryptocurrency-transaction:output[*].address = '{esc}']"),
            Self::UserAgent => {
                format!("[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{esc}']")
            }
            Self::MalwareFamily => format!("[malware:name = '{esc}']"),
            Self::Asn => format!("[autonomous-system:number = {value}]"),
            Self::Mac => format!("[network-traffic:src_ref.value = '{esc}']"),
            Self::Yara => format!("[indicator:pattern = '{esc}']"),
            _ => return None,
        })
    }

    /// Return all MISP types that are hash-based.
    #[must_use]
    pub fn all_hash_types() -> Vec<Self> {
        vec![
            Self::Md5,
            Self::Sha1,
            Self::Sha256,
            Self::Sha512,
            Self::Sha224,
            Self::Sha384,
            Self::Sha3224,
            Self::Sha3256,
            Self::Sha3384,
            Self::Sha3512,
            Self::Ssdeep,
            Self::Tlsh,
            Self::Authentihash,
            Self::Imphash,
            Self::Pehash,
            Self::Vhash,
            Self::Cdhash,
            Self::Telfhash,
        ]
    }

    /// Return all network-level MISP types.
    #[must_use]
    pub fn all_network_types() -> Vec<Self> {
        vec![
            Self::IpSrc,
            Self::IpDst,
            Self::IpSrcPort,
            Self::IpDstPort,
            Self::Domain,
            Self::DomainIp,
            Self::Hostname,
            Self::Url,
            Self::Uri,
            Self::Asn,
            Self::CidrBlock,
            Self::Mac,
            Self::JarmHash,
            Self::Ja3,
            Self::Hassh,
            Self::HasshServer,
        ]
    }

    /// Return `true` if this type contains composite data separated by `|`.
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        matches!(
            self,
            Self::FilenameAndMd5
                | Self::FilenameAndSha1
                | Self::FilenameAndSha256
                | Self::FilenameAndSha512
                | Self::FilenameAndSsdeep
                | Self::FilenameAndImphash
                | Self::FilenameAndTlsh
                | Self::FilenameAndAuthentihash
                | Self::IpSrcPort
                | Self::IpDstPort
                | Self::DomainIp
                | Self::RegkeyAndValue
        )
    }
}

// ── AttributeTypeRegistry ─────────────────────────────────────────────────────

/// Registry mapping MISP type strings to their metadata.
#[derive(Debug, Default)]
pub struct AttributeTypeRegistry {
    /// Map from MISP string → type metadata.
    types: HashMap<&'static str, AttributeTypeMeta>,
}

/// Metadata for a single MISP attribute type.
#[derive(Debug, Clone)]
pub struct AttributeTypeMeta {
    /// The canonical type identifier.
    pub type_str: &'static str,
    /// Default category.
    pub category: AttributeCategory,
    /// Whether this type qualifies as an `IoC`.
    pub is_ioc: bool,
    /// Human-readable description.
    pub description: &'static str,
}

impl AttributeTypeRegistry {
    /// Create and populate the registry with all known types.
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self::default();
        reg.populate();
        reg
    }

    fn register(
        &mut self,
        type_str: &'static str,
        category: AttributeCategory,
        is_ioc: bool,
        description: &'static str,
    ) {
        self.types.insert(
            type_str,
            AttributeTypeMeta {
                type_str,
                category,
                is_ioc,
                description,
            },
        );
    }

    fn populate(&mut self) {
        self.register("md5", AttributeCategory::Payload, true, "MD5 hash of a file");
        self.register("sha1", AttributeCategory::Payload, true, "SHA-1 hash of a file");
        self.register("sha256", AttributeCategory::Payload, true, "SHA-256 hash of a file");
        self.register("sha512", AttributeCategory::Payload, true, "SHA-512 hash of a file");
        self.register("sha224", AttributeCategory::Payload, true, "SHA-224 hash");
        self.register("sha384", AttributeCategory::Payload, true, "SHA-384 hash");
        self.register("ssdeep", AttributeCategory::Payload, true, "Fuzzy hash (ssdeep)");
        self.register("tlsh", AttributeCategory::Payload, true, "Trend Micro Locality Sensitive Hash");
        self.register("authentihash", AttributeCategory::Payload, true, "Authenticode hash");
        self.register("imphash", AttributeCategory::Payload, true, "Import hash (PE)");
        self.register("pehash", AttributeCategory::Payload, false, "PEHash structural hash");
        self.register("vhash", AttributeCategory::Payload, false, "VHash cluster hash");
        self.register("filename", AttributeCategory::Payload, false, "File name");
        self.register("filename|md5", AttributeCategory::Payload, true, "File name + MD5");
        self.register("filename|sha256", AttributeCategory::Payload, true, "File name + SHA-256");
        self.register("ip-src", AttributeCategory::Network, true, "Source IP address");
        self.register("ip-dst", AttributeCategory::Network, true, "Destination IP address");
        self.register("ip-src|port", AttributeCategory::Network, true, "Source IP + port");
        self.register("ip-dst|port", AttributeCategory::Network, true, "Destination IP + port");
        self.register("domain", AttributeCategory::Network, true, "Domain name");
        self.register("domain|ip", AttributeCategory::Network, true, "Domain + IP composite");
        self.register("hostname", AttributeCategory::Network, true, "Hostname");
        self.register("url", AttributeCategory::Network, true, "URL");
        self.register("uri", AttributeCategory::Network, true, "URI");
        self.register("AS", AttributeCategory::Network, false, "Autonomous System Number");
        self.register("email-src", AttributeCategory::Email, true, "Source email address");
        self.register("email-dst", AttributeCategory::Email, true, "Destination email address");
        self.register("email-subject", AttributeCategory::Email, false, "Email subject");
        self.register("email-body", AttributeCategory::Email, false, "Email body");
        self.register("email-attachment", AttributeCategory::Email, true, "Email attachment name");
        self.register("mutex", AttributeCategory::Artifacts, true, "Mutex name");
        self.register("regkey", AttributeCategory::Artifacts, true, "Registry key");
        self.register("regkey|value", AttributeCategory::Artifacts, true, "Registry key + value");
        self.register("yara", AttributeCategory::ExternalAnalysis, false, "YARA rule");
        self.register("sigma", AttributeCategory::ExternalAnalysis, false, "Sigma rule");
        self.register("vulnerability", AttributeCategory::ExternalAnalysis, false, "Vulnerability / CVE");
        self.register("btc", AttributeCategory::Financial, true, "Bitcoin address");
        self.register("eth", AttributeCategory::Financial, true, "Ethereum address");
        self.register("threat-actor", AttributeCategory::Attribution, false, "Threat actor name");
        self.register("malware-type", AttributeCategory::Attribution, false, "Malware family");
        self.register("comment", AttributeCategory::Other, false, "Free-text comment");
        self.register("text", AttributeCategory::Other, false, "Free-text");
        self.register("other", AttributeCategory::Other, false, "Uncategorised attribute");
    }

    /// Look up metadata by MISP type string.
    #[must_use]
    pub fn lookup(&self, type_str: &str) -> Option<&AttributeTypeMeta> {
        self.types.get(type_str)
    }

    /// Return all registered type strings.
    #[must_use]
    pub fn all_type_strings(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.types.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Return all types that are IoC-capable.
    #[must_use]
    pub fn ioc_types(&self) -> Vec<&AttributeTypeMeta> {
        self.types.values().filter(|m| m.is_ioc).collect()
    }

    /// Return the count of registered types.
    #[must_use]
    pub fn count(&self) -> usize {
        self.types.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_hash_types_non_empty() {
        assert!(!MispAttrType::all_hash_types().is_empty());
    }

    #[test]
    fn test_all_network_types_non_empty() {
        assert!(!MispAttrType::all_network_types().is_empty());
    }

    #[test]
    fn test_md5_is_ioc() {
        assert!(MispAttrType::Md5.is_ioc());
    }

    #[test]
    fn test_comment_not_ioc() {
        assert!(!MispAttrType::Comment.is_ioc());
    }

    #[test]
    fn test_md5_as_str() {
        assert_eq!(MispAttrType::Md5.as_str(), "md5");
    }

    #[test]
    fn test_sha256_as_str() {
        assert_eq!(MispAttrType::Sha256.as_str(), "sha256");
    }

    #[test]
    fn test_ip_src_as_str() {
        assert_eq!(MispAttrType::IpSrc.as_str(), "ip-src");
    }

    #[test]
    fn test_from_str_md5() {
        assert_eq!(MispAttrType::from_str("md5"), Some(MispAttrType::Md5));
    }

    #[test]
    fn test_from_str_unknown() {
        assert!(MispAttrType::from_str("nonexistent-type").is_none());
    }

    #[test]
    fn test_stix_pattern_sha256() {
        let p = MispAttrType::Sha256.to_stix_pattern("abc123").unwrap();
        assert!(p.contains("file:hashes.SHA-256"));
        assert!(p.contains("abc123"));
    }

    #[test]
    fn test_stix_pattern_ip_dst() {
        let p = MispAttrType::IpDst.to_stix_pattern("1.2.3.4").unwrap();
        assert!(p.contains("network-traffic:dst_ref.value"));
        assert!(p.contains("1.2.3.4"));
    }

    #[test]
    fn test_stix_pattern_domain() {
        let p = MispAttrType::Domain.to_stix_pattern("evil.com").unwrap();
        assert!(p.contains("domain-name:value"));
    }

    #[test]
    fn test_stix_pattern_mutex() {
        let p = MispAttrType::Mutex.to_stix_pattern("Global\\bad").unwrap();
        assert!(p.contains("mutex:name"));
    }

    #[test]
    fn test_stix_pattern_regkey_value() {
        let p = MispAttrType::RegkeyAndValue
            .to_stix_pattern(r"HKLM\Run|evil.exe")
            .unwrap();
        assert!(p.contains("windows-registry-key:key"));
        assert!(p.contains("windows-registry-key:values"));
    }

    #[test]
    fn test_stix_pattern_comment_none() {
        assert!(MispAttrType::Comment.to_stix_pattern("test").is_none());
    }

    #[test]
    fn test_default_category_md5() {
        assert_eq!(MispAttrType::Md5.default_category(), AttributeCategory::Payload);
    }

    #[test]
    fn test_default_category_ip() {
        assert_eq!(MispAttrType::IpDst.default_category(), AttributeCategory::Network);
    }

    #[test]
    fn test_default_category_email() {
        assert_eq!(MispAttrType::EmailSrc.default_category(), AttributeCategory::Email);
    }

    #[test]
    fn test_is_composite_filename_sha256() {
        assert!(MispAttrType::FilenameAndSha256.is_composite());
    }

    #[test]
    fn test_is_composite_md5_false() {
        assert!(!MispAttrType::Md5.is_composite());
    }

    #[test]
    fn test_registry_lookup_md5() {
        let reg = AttributeTypeRegistry::new();
        let meta = reg.lookup("md5").unwrap();
        assert!(meta.is_ioc);
    }

    #[test]
    fn test_registry_lookup_unknown() {
        let reg = AttributeTypeRegistry::new();
        assert!(reg.lookup("not-a-type").is_none());
    }

    #[test]
    fn test_registry_count_nonzero() {
        let reg = AttributeTypeRegistry::new();
        assert!(reg.count() > 30);
    }

    #[test]
    fn test_registry_ioc_types_non_empty() {
        let reg = AttributeTypeRegistry::new();
        assert!(!reg.ioc_types().is_empty());
    }

    #[test]
    fn test_registry_all_type_strings_sorted() {
        let reg = AttributeTypeRegistry::new();
        let types = reg.all_type_strings();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted);
    }

    #[test]
    fn test_attribute_category_as_misp_str() {
        assert_eq!(AttributeCategory::Network.as_misp_str(), "Network activity");
        assert_eq!(AttributeCategory::Financial.as_misp_str(), "Financial fraud");
    }

    #[test]
    fn test_attribute_category_from_misp_str() {
        assert_eq!(
            AttributeCategory::from_misp_str("Network activity"),
            AttributeCategory::Network
        );
    }

    #[test]
    fn test_stix_escape_single_quote() {
        let p = MispAttrType::Domain.to_stix_pattern("it's.evil.com").unwrap();
        assert!(p.contains("\\'"));
    }

    #[test]
    fn test_vulnerability_stix() {
        let p = MispAttrType::Vulnerability.to_stix_pattern("CVE-2023-1234").unwrap();
        assert!(p.contains("vulnerability:name"));
    }

    #[test]
    fn test_btc_stix() {
        let p = MispAttrType::BtcAddress
            .to_stix_pattern("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf")
            .unwrap();
        assert!(p.contains("cryptocurrency-transaction"));
    }

    #[test]
    fn test_from_str_roundtrip() {
        let types = [
            MispAttrType::Md5,
            MispAttrType::Sha256,
            MispAttrType::IpDst,
            MispAttrType::Domain,
            MispAttrType::Mutex,
            MispAttrType::Regkey,
            MispAttrType::Yara,
        ];
        for t in &types {
            let s = t.as_str();
            let parsed = MispAttrType::from_str(s);
            assert!(parsed.is_some(), "Failed roundtrip for {s}");
        }
    }
}
