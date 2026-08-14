//! Forensics plugin modules for artifact parsing and analysis.
//!
//! Each module provides standalone parsers and scanners for a specific
//! category of forensic artifact.  All modules are `no_std`-compatible
//! in their core parsing logic; only tests and helper utilities require `std`.

pub mod browser_history;
pub mod credential_artifacts;
pub mod event_log;
pub mod file_timeline;
pub mod lnk_parser;
pub mod memory_strings;
pub mod network_artifacts;
pub mod prefetch_analyzer;
pub mod process_artifacts;
pub mod registry_artifacts;

// ─── Convenience re-exports ───────────────────────────────────────────────────

pub use browser_history::{
    BrowserArtifactAnalyzer, BrowserArtifactScanner, BrowserArtifactSummary, BrowserType,
    CookieRecord, DownloadRecord, FormDataEntry, HistoryEntry, LoginDataScanner, StorageEntry,
    StorageType,
};

pub use registry_artifacts::{
    HiveBaseBlock, MruEntry, MruType, NamedKey, NtUserArtifacts, RawHiveScanner, RegValueType,
    RegistryValue, RunKeyEntry, SamAccountFlags, SamUser, ShellbagEntry, UserAssistEntry,
};

pub use prefetch_analyzer::{
    FileMetricsEntry, PrefetchFile, PrefetchFileName, PrefetchHeader, PrefetchVersion, VolumeInfo,
    compute_prefetch_hash_win8, compute_prefetch_hash_xp, decompress_mam, is_mam_compressed,
};

pub use lnk_parser::{
    DriveType, ExtraDataBlock, ExtraDataSignature, FileAttributes, LinkInfo, ShellLink,
    ShellLinkHeader, StringData,
};

pub use event_log::{
    EventChannel, EventRecord, EvtxChunkHeader, EvtxFileHeader, EvtxScanner, SECURITY_EVENT_IDS,
    WELL_KNOWN_PROVIDERS, event_id_description, logon_type_description,
};

pub use network_artifacts::{
    ArpCacheScanner, ArpEntry, ArpState, DnsCacheEntry, DnsCacheScanner, DnsRecordData,
    DnsRecordType, DnsSource, MacAddress, NetstatEntry, NetworkInterface, PassiveDnsReconstructor,
    Protocol, TcpState, TcpTimeline, TcpTimelineEvent, TcpTimelineEventType,
};

pub use memory_strings::{
    AsciiScanner, CredentialDetector, CredentialPattern, CredentialPatternType, ExtractedString,
    IpExtractor, MemoryStringAnalysis, StringClass, StringClassifier, UrlExtractor, Utf16Scanner,
};

pub use process_artifacts::{
    EprocessEntry, EprocessListWalker, EprocessOffsets, HandleEntry, HandleTableParser, HandleType,
    LdrModuleEntry, PebLdrScanner, ProcessFlags, VadNode, VadNodeType, VadPageProtection,
};

pub use file_timeline::{
    AttributeType, MacbTimestamps, MftEntry, MftFlags, MftScanner, TimelineBuilder, TimelineEvent,
    TimelineSource, TimestampType, UsnJournalParser, UsnReasons, UsnRecord,
};

pub use credential_artifacts::{
    CredentialSummary, DpapiBlob, DpapiScanner, DpapiVersion, KerberosEncryptionType,
    KerberosTicket, KerberosTicketFlags, KerberosTicketScanner, KerberosTicketType,
    LsassCredential, LsassCredentialSource, LsassScanner, NtlmHash, SecretsdumpLine,
};
