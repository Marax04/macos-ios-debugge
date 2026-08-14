//! Parse MISP feed formats: JSON feed, CSV feed, freetext feed.
//! Validates event structure, extracts attributes by type, handles pagination,
//! merges duplicate events, and deduplicates IOCs.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ─── FeedFormat ───────────────────────────────────────────────────────────────

/// Supported MISP feed formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedFormat {
    /// Standard MISP JSON feed (array of events).
    Json,
    /// CSV feed with configurable column mapping.
    Csv,
    /// Free-text feed: one IOC per line.
    Freetext,
    /// MISP STIX 2.0 bundle.
    Stix2,
    /// `OpenIOC` XML.
    OpenIoc,
}

impl std::fmt::Display for FeedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Freetext => "freetext",
            Self::Stix2 => "stix2",
            Self::OpenIoc => "openioc",
        };
        write!(f, "{s}")
    }
}

// ─── IocRecord ────────────────────────────────────────────────────────────────

/// A deduplicated IOC record extracted from a feed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IocRecord {
    /// IOC type string (e.g. "md5", "ip-dst", "domain").
    pub ioc_type: String,
    /// IOC value.
    pub value: String,
    /// Source event UUID(s).
    pub source_events: Vec<String>,
    /// Tags extracted from source events.
    pub tags: Vec<String>,
    /// Whether this IOC is IDS-relevant.
    pub to_ids: bool,
    /// First seen timestamp (Unix seconds), if available.
    pub first_seen: Option<u64>,
    /// Last seen timestamp (Unix seconds), if available.
    pub last_seen: Option<u64>,
    /// Number of times this IOC appeared across events.
    pub occurrence_count: u32,
}

impl IocRecord {
    /// Create a new IOC record.
    #[must_use]
    pub fn new(ioc_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            ioc_type: ioc_type.into(),
            value: value.into(),
            source_events: Vec::new(),
            tags: Vec::new(),
            to_ids: false,
            first_seen: None,
            last_seen: None,
            occurrence_count: 1,
        }
    }

    /// Add a source event UUID.
    pub fn add_source(&mut self, uuid: impl Into<String>) {
        let u = uuid.into();
        if !self.source_events.contains(&u) {
            self.source_events.push(u);
        }
    }

    /// Merge another IOC record's metadata into this one.
    pub fn merge(&mut self, other: &Self) {
        for src in &other.source_events {
            self.add_source(src.clone());
        }
        for tag in &other.tags {
            if !self.tags.contains(tag) {
                self.tags.push(tag.clone());
            }
        }
        if other.to_ids {
            self.to_ids = true;
        }
        self.first_seen = match (self.first_seen, other.first_seen) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        self.last_seen = match (self.last_seen, other.last_seen) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        self.occurrence_count += other.occurrence_count;
    }

    /// Canonical deduplication key.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.ioc_type, self.value.to_ascii_lowercase())
    }
}

// ─── FeedAttribute ────────────────────────────────────────────────────────────

/// A raw attribute parsed from a feed entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedAttribute {
    pub attr_type: String,
    pub value: String,
    pub to_ids: bool,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub timestamp: Option<u64>,
}

impl FeedAttribute {
    /// Create a minimal feed attribute.
    #[must_use]
    pub fn new(attr_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            attr_type: attr_type.into(),
            value: value.into(),
            to_ids: false,
            comment: None,
            tags: Vec::new(),
            timestamp: None,
        }
    }

    /// Convert to an [`IocRecord`].
    #[must_use]
    pub fn to_ioc_record(&self, source_uuid: &str) -> IocRecord {
        let mut rec = IocRecord::new(self.attr_type.clone(), self.value.clone());
        rec.add_source(source_uuid);
        rec.to_ids = self.to_ids;
        rec.tags = self.tags.clone();
        rec.first_seen = self.timestamp;
        rec.last_seen = self.timestamp;
        rec
    }
}

// ─── FeedEntry ────────────────────────────────────────────────────────────────

/// A single parsed feed entry (event-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedEntry {
    /// UUID of this event.
    pub uuid: String,
    /// Event title/info.
    pub info: String,
    /// Threat level (1–4).
    pub threat_level_id: u8,
    /// Analysis status.
    pub analysis: u8,
    /// Attributes in this entry.
    pub attributes: Vec<FeedAttribute>,
    /// Tags on the event.
    pub event_tags: Vec<String>,
    /// Timestamp.
    pub timestamp: u64,
    /// Publishing organisation.
    pub org_name: Option<String>,
}

impl FeedEntry {
    /// Create a minimal feed entry.
    #[must_use]
    pub fn new(uuid: impl Into<String>, info: impl Into<String>) -> Self {
        Self {
            uuid: uuid.into(),
            info: info.into(),
            threat_level_id: 4,
            analysis: 0,
            attributes: Vec::new(),
            event_tags: Vec::new(),
            timestamp: 0,
            org_name: None,
        }
    }

    /// Return attributes of a given type.
    #[must_use]
    pub fn attributes_of_type(&self, type_str: &str) -> Vec<&FeedAttribute> {
        self.attributes.iter().filter(|a| a.attr_type == type_str).collect()
    }

    /// Return `true` if this entry has any IDS attributes.
    #[must_use]
    pub fn has_ids(&self) -> bool {
        self.attributes.iter().any(|a| a.to_ids)
    }

    /// Extract all IOC records from this entry.
    #[must_use]
    pub fn extract_ioc_records(&self) -> Vec<IocRecord> {
        self.attributes.iter().map(|a| a.to_ioc_record(&self.uuid)).collect()
    }
}

// ─── MispFeed ─────────────────────────────────────────────────────────────────

/// A parsed MISP feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispFeed {
    /// Feed source URL or identifier.
    pub source: String,
    /// Feed format.
    pub format: FeedFormat,
    /// Parsed entries.
    pub entries: Vec<FeedEntry>,
    /// Total number of entries including pagination.
    pub total_count: Option<usize>,
    /// Current page (1-indexed).
    pub page: usize,
    /// Page size.
    pub page_size: usize,
    /// Whether more pages are available.
    pub has_more: bool,
}

impl MispFeed {
    /// Create a new feed.
    #[must_use]
    pub fn new(source: impl Into<String>, format: FeedFormat) -> Self {
        Self {
            source: source.into(),
            format,
            entries: Vec::new(),
            total_count: None,
            page: 1,
            page_size: 100,
            has_more: false,
        }
    }

    /// Return `true` if the feed has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Extract all IOC records, deduplicated.
    #[must_use]
    pub fn extract_iocs(&self) -> Vec<IocRecord> {
        let mut map: HashMap<String, IocRecord> = HashMap::new();
        for entry in &self.entries {
            for rec in entry.extract_ioc_records() {
                let key = rec.key();
                map.entry(key).and_modify(|existing| existing.merge(&rec)).or_insert(rec);
            }
        }
        map.into_values().collect()
    }

    /// Return entries filtered by threat level.
    #[must_use]
    pub fn entries_by_threat_level(&self, level: u8) -> Vec<&FeedEntry> {
        self.entries.iter().filter(|e| e.threat_level_id == level).collect()
    }

    /// Return entries containing a given tag.
    #[must_use]
    pub fn entries_with_tag(&self, tag: &str) -> Vec<&FeedEntry> {
        self.entries
            .iter()
            .filter(|e| e.event_tags.iter().any(|t| t == tag))
            .collect()
    }
}

// ─── EventMerger ─────────────────────────────────────────────────────────────

/// Merges duplicate events across multiple feeds.
pub struct EventMerger {
    /// Event UUID → merged entry.
    events: BTreeMap<String, FeedEntry>,
    /// Statistics.
    pub merged_count: usize,
    pub new_count: usize,
}

impl EventMerger {
    /// Create a new merger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            merged_count: 0,
            new_count: 0,
        }
    }

    /// Add a feed entry, merging with an existing entry if the UUID matches.
    pub fn add(&mut self, entry: FeedEntry) {
        if let Some(existing) = self.events.get_mut(&entry.uuid) {
            // Merge: take newer threat level and more complete attributes.
            if entry.threat_level_id < existing.threat_level_id {
                existing.threat_level_id = entry.threat_level_id;
            }
            // Merge attributes (deduplicate by type+value).
            let existing_keys: HashSet<(String, String)> = existing
                .attributes
                .iter()
                .map(|a| (a.attr_type.clone(), a.value.clone()))
                .collect();
            for attr in entry.attributes {
                let key = (attr.attr_type.clone(), attr.value.clone());
                if !existing_keys.contains(&key) {
                    existing.attributes.push(attr);
                }
            }
            // Merge tags.
            for tag in &entry.event_tags {
                if !existing.event_tags.contains(tag) {
                    existing.event_tags.push(tag.clone());
                }
            }
            // Keep latest timestamp.
            if entry.timestamp > existing.timestamp {
                existing.timestamp = entry.timestamp;
            }
            self.merged_count += 1;
        } else {
            self.events.insert(entry.uuid.clone(), entry);
            self.new_count += 1;
        }
    }

    /// Add all entries from a feed.
    pub fn add_feed(&mut self, feed: &MispFeed) {
        for entry in &feed.entries {
            self.add(entry.clone());
        }
    }

    /// Return all merged entries as a vector.
    #[must_use]
    pub fn finalize(self) -> Vec<FeedEntry> {
        self.events.into_values().collect()
    }

    /// Return the total number of entries.
    #[must_use]
    pub fn total(&self) -> usize {
        self.events.len()
    }
}

impl Default for EventMerger {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CSV parser ───────────────────────────────────────────────────────────────

/// Configuration for CSV feed parsing.
#[derive(Debug, Clone)]
pub struct CsvFeedConfig {
    /// Column index for the attribute type.
    pub type_column: usize,
    /// Column index for the value.
    pub value_column: usize,
    /// Column index for the "`to_ids`" flag (optional).
    pub to_ids_column: Option<usize>,
    /// Column index for comment (optional).
    pub comment_column: Option<usize>,
    /// Column index for tags (optional, comma-separated inside field).
    pub tags_column: Option<usize>,
    /// Delimiter character.
    pub delimiter: char,
    /// Whether the first row is a header.
    pub has_header: bool,
    /// Default attribute type when `type_column` is absent.
    pub default_type: Option<String>,
}

impl Default for CsvFeedConfig {
    fn default() -> Self {
        Self {
            type_column: 0,
            value_column: 1,
            to_ids_column: None,
            comment_column: None,
            tags_column: None,
            delimiter: ',',
            has_header: true,
            default_type: None,
        }
    }
}

// ─── Freetext IOC inference ───────────────────────────────────────────────────

/// Infer an IOC type from a raw string.
#[must_use]
pub fn infer_ioc_type(value: &str) -> &'static str {
    let v = value.trim();

    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return "url";
    }

    if is_ipv4(v) {
        return "ip-dst";
    }

    if is_ipv6(v) {
        return "ip-dst";
    }

    match v.len() {
        32 if v.chars().all(|c| c.is_ascii_hexdigit()) => return "md5",
        40 if v.chars().all(|c| c.is_ascii_hexdigit()) => return "sha1",
        64 if v.chars().all(|c| c.is_ascii_hexdigit()) => return "sha256",
        128 if v.chars().all(|c| c.is_ascii_hexdigit()) => return "sha512",
        _ => {}
    }

    if v.starts_with("HKEY_") || v.starts_with("HKLM") || v.starts_with("HKCU") {
        return "regkey";
    }

    if v.contains('\\') || (v.len() > 3 && v.as_bytes().get(1) == Some(&b':')) {
        return "filename";
    }

    if !v.contains('/') && v.contains('.') && !v.contains(' ') && !v.contains('@') {
        return "domain";
    }

    if v.contains('@') && v.contains('.') {
        return "email-src";
    }

    "other"
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_ipv6(s: &str) -> bool {
    // Simplified: check for colon-separated hex groups.
    if !s.contains(':') {
        return false;
    }
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() >= 3
        && parts.iter().all(|p| p.is_empty() || (p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit())))
}

// ─── MispFeedParser ───────────────────────────────────────────────────────────

/// Parser for MISP feeds.
pub struct MispFeedParser {
    csv_config: CsvFeedConfig,
    /// Whether to validate event structure during parsing.
    pub validate: bool,
    /// Maximum number of entries to parse (0 = unlimited).
    pub max_entries: usize,
    /// Filter: only include attributes with `to_ids = true`.
    pub to_ids_only: bool,
    /// Types to include (empty = all).
    pub included_types: HashSet<String>,
    /// Types to exclude.
    pub excluded_types: HashSet<String>,
}

impl MispFeedParser {
    /// Create a new parser with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            csv_config: CsvFeedConfig::default(),
            validate: true,
            max_entries: 0,
            to_ids_only: false,
            included_types: HashSet::new(),
            excluded_types: HashSet::new(),
        }
    }

    /// Set CSV configuration.
    #[must_use]
    pub fn with_csv_config(mut self, cfg: CsvFeedConfig) -> Self {
        self.csv_config = cfg;
        self
    }

    /// Disable validation.
    #[must_use]
    pub const fn without_validation(mut self) -> Self {
        self.validate = false;
        self
    }

    /// Limit the number of entries parsed.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    /// Only include `to_ids` attributes.
    #[must_use]
    pub const fn to_ids_only(mut self) -> Self {
        self.to_ids_only = true;
        self
    }

    /// Include only these attribute types.
    #[must_use]
    pub fn include_types(mut self, types: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.included_types = types.into_iter().map(std::convert::Into::into).collect();
        self
    }

    /// Exclude these attribute types.
    #[must_use]
    pub fn exclude_types(mut self, types: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.excluded_types = types.into_iter().map(std::convert::Into::into).collect();
        self
    }

    /// Parse a JSON feed from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns a string error if JSON is malformed.
    pub fn parse_json(&self, source: &str, data: &[u8]) -> Result<MispFeed, String> {
        let json_str = std::str::from_utf8(data).map_err(|e| e.to_string())?;
        self.parse_json_str(source, json_str)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Parse a JSON feed from a string.
    pub fn parse_json_str(&self, source: &str, data: &str) -> Result<MispFeed, String> {
        let value: serde_json::Value =
            serde_json::from_str(data).map_err(|e| format!("JSON parse error: {e}"))?;

        let mut feed = MispFeed::new(source, FeedFormat::Json);
        let events = match &value {
            serde_json::Value::Array(arr) => arr.clone(),
            serde_json::Value::Object(obj) => {
                if let Some(serde_json::Value::Array(arr)) = obj.get("response") {
                    arr.clone()
                } else if let Some(serde_json::Value::Array(arr)) = obj.get("Event") {
                    arr.clone()
                } else {
                    vec![value.clone()]
                }
            }
            _ => return Err("Unexpected JSON structure".into()),
        };

        let limit = if self.max_entries == 0 { usize::MAX } else { self.max_entries };

        for raw_event in events.iter().take(limit) {
            if let Ok(entry) = self.parse_json_event(raw_event) {
                if !self.validate || self.validate_entry(&entry).is_ok() {
                    feed.entries.push(entry);
                }
            } else {
                // Skip invalid entries.
            }
        }

        feed.total_count = Some(events.len());
        feed.has_more = events.len() > limit;
        Ok(feed)
    }

    fn parse_json_event(&self, raw: &serde_json::Value) -> Result<FeedEntry, String> {
        let obj = raw.as_object().ok_or("event is not an object")?;

        let uuid = obj
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let info = obj
            .get("info")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let threat_level_id = obj
            .get("threat_level_id")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u8>().ok()).or_else(|| v.as_u64().map(|n| n as u8)))
            .unwrap_or(4);
        let analysis = obj
            .get("analysis")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u8>().ok()).or_else(|| v.as_u64().map(|n| n as u8)))
            .unwrap_or(0);
        let timestamp = obj
            .get("timestamp")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()))
            .unwrap_or(0);
        let org_name = obj.get("Org").and_then(|o| o.get("name")).and_then(|n| n.as_str()).map(std::string::ToString::to_string);

        let mut entry = FeedEntry::new(uuid, info);
        entry.threat_level_id = threat_level_id;
        entry.analysis = analysis;
        entry.timestamp = timestamp;
        entry.org_name = org_name;

        // Parse tags.
        if let Some(serde_json::Value::Array(tags)) = obj.get("Tag") {
            for tag in tags {
                if let Some(name) = tag.get("name").and_then(|n| n.as_str()) {
                    entry.event_tags.push(name.to_string());
                }
            }
        }

        // Parse attributes.
        if let Some(serde_json::Value::Array(attrs)) = obj.get("Attribute") {
            for raw_attr in attrs {
                if let Ok(attr) = self.parse_json_attribute(raw_attr)
                    && self.attribute_passes_filter(&attr) {
                        entry.attributes.push(attr);
                    }
            }
        }

        Ok(entry)
    }

    fn parse_json_attribute(&self, raw: &serde_json::Value) -> Result<FeedAttribute, String> {
        let obj = raw.as_object().ok_or("attribute is not an object")?;

        let attr_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("other")
            .to_string();
        let value = obj
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let to_ids = obj
            .get("to_ids")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let comment = obj
            .get("comment")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(std::string::ToString::to_string);
        let timestamp = obj
            .get("timestamp")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()));

        let mut attr = FeedAttribute::new(attr_type, value);
        attr.to_ids = to_ids;
        attr.comment = comment;
        attr.timestamp = timestamp;

        // Parse attribute-level tags.
        if let Some(serde_json::Value::Array(tags)) = obj.get("Tag") {
            for tag in tags {
                if let Some(name) = tag.get("name").and_then(|n| n.as_str()) {
                    attr.tags.push(name.to_string());
                }
            }
        }

        Ok(attr)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Parse a CSV feed from a string.
    pub fn parse_csv_str(&self, source: &str, data: &str) -> Result<MispFeed, String> {
        let mut feed = MispFeed::new(source, FeedFormat::Csv);
        let mut lines = data.lines();

        // Skip header if configured.
        if self.csv_config.has_header {
            lines.next();
        }

        let limit = if self.max_entries == 0 { usize::MAX } else { self.max_entries };
        let mut count = 0;

        for line in lines.take(limit) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields: Vec<&str> = line.splitn(10, self.csv_config.delimiter).collect();

            let attr_type = if let Some(default) = &self.csv_config.default_type {
                default.clone()
            } else {
                fields
                    .get(self.csv_config.type_column).map_or_else(|| "other".into(), |s| s.trim().to_string())
            };

            let value = fields
                .get(self.csv_config.value_column)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            if value.is_empty() {
                continue;
            }

            let mut attr = FeedAttribute::new(attr_type, value.clone());

            if let Some(col) = self.csv_config.to_ids_column {
                attr.to_ids = fields.get(col).is_some_and(|s| {
                    matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
                });
            }

            if let Some(col) = self.csv_config.comment_column {
                attr.comment = fields.get(col).map(|s| s.trim().to_string());
            }

            if let Some(col) = self.csv_config.tags_column
                && let Some(tag_str) = fields.get(col) {
                    attr.tags = tag_str.split(',').map(|t| t.trim().to_string()).collect();
                }

            if !self.attribute_passes_filter(&attr) {
                continue;
            }

            let uuid = format!("csv-{count:08x}-0000-0000-0000-000000000000");
            let mut entry = FeedEntry::new(uuid, format!("CSV entry {count}"));
            entry.attributes.push(attr);
            feed.entries.push(entry);
            count += 1;
        }

        Ok(feed)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Parse a freetext feed (one IOC per line).
    pub fn parse_freetext_str(&self, source: &str, data: &str) -> Result<MispFeed, String> {
        let mut feed = MispFeed::new(source, FeedFormat::Freetext);
        let limit = if self.max_entries == 0 { usize::MAX } else { self.max_entries };

        for (i, line) in data.lines().take(limit).enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            let inferred_type = infer_ioc_type(line);
            let attr_type = inferred_type.to_string();
            let attr = FeedAttribute::new(attr_type, line);

            if !self.attribute_passes_filter(&attr) {
                continue;
            }

            let uuid = format!("ft-{i:08x}-0000-0000-0000-000000000000");
            let mut entry = FeedEntry::new(uuid, format!("Freetext IOC {i}"));
            entry.attributes.push(attr);
            feed.entries.push(entry);
        }

        Ok(feed)
    }

    fn attribute_passes_filter(&self, attr: &FeedAttribute) -> bool {
        if self.to_ids_only && !attr.to_ids {
            return false;
        }
        if !self.included_types.is_empty() && !self.included_types.contains(&attr.attr_type) {
            return false;
        }
        if self.excluded_types.contains(&attr.attr_type) {
            return false;
        }
        true
    }

    fn validate_entry(&self, entry: &FeedEntry) -> Result<(), String> {
        if entry.uuid.is_empty() {
            return Err("missing uuid".into());
        }
        if entry.info.is_empty() {
            return Err("missing info".into());
        }
        if entry.threat_level_id > 4 {
            return Err("invalid threat_level_id".into());
        }
        Ok(())
    }
}

impl Default for MispFeedParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FeedPaginator ────────────────────────────────────────────────────────────

/// Helper for paginating through large feeds.
pub struct FeedPaginator {
    page_size: usize,
    current_page: usize,
    total: Option<usize>,
}

impl FeedPaginator {
    /// Create a paginator.
    #[must_use]
    pub fn new(page_size: usize) -> Self {
        Self {
            page_size: page_size.max(1),
            current_page: 1,
            total: None,
        }
    }

    /// Set total.
    pub const fn set_total(&mut self, total: usize) {
        self.total = Some(total);
    }

    /// Return current page number.
    #[must_use]
    pub const fn page(&self) -> usize {
        self.current_page
    }

    /// Return page size.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Return offset for the current page.
    #[must_use]
    pub const fn offset(&self) -> usize {
        (self.current_page - 1) * self.page_size
    }

    /// Advance to the next page.
    pub const fn next_page(&mut self) {
        self.current_page += 1;
    }

    /// Return `true` if there are more pages.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        match self.total {
            Some(total) => self.offset() + self.page_size < total,
            None => false,
        }
    }

    /// Return total number of pages.
    #[must_use]
    pub fn total_pages(&self) -> Option<usize> {
        self.total.map(|t| t.div_ceil(self.page_size))
    }
}

// ─── IocDeduplicator ──────────────────────────────────────────────────────────

/// Deduplicates IOC records across multiple feeds.
pub struct IocDeduplicator {
    records: HashMap<String, IocRecord>,
    /// Total added before deduplication.
    pub total_added: usize,
    /// Total after deduplication.
    pub total_unique: usize,
}

impl IocDeduplicator {
    /// Create a new deduplicator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            total_added: 0,
            total_unique: 0,
        }
    }

    /// Add an IOC record.
    pub fn add(&mut self, rec: IocRecord) {
        self.total_added += 1;
        let key = rec.key();
        self.records.entry(key).and_modify(|existing| existing.merge(&rec)).or_insert(rec);
        self.total_unique = self.records.len();
    }

    /// Add all IOCs from a feed.
    pub fn add_feed(&mut self, feed: &MispFeed) {
        for rec in feed.extract_iocs() {
            self.add(rec);
        }
    }

    /// Return deduplicated records.
    #[must_use]
    pub fn records(&self) -> Vec<&IocRecord> {
        self.records.values().collect()
    }

    /// Return deduplicated records of a given type.
    #[must_use]
    pub fn records_of_type(&self, ioc_type: &str) -> Vec<&IocRecord> {
        self.records.values().filter(|r| r.ioc_type == ioc_type).collect()
    }

    /// Return IDs-flagged records only.
    #[must_use]
    pub fn ids_records(&self) -> Vec<&IocRecord> {
        self.records.values().filter(|r| r.to_ids).collect()
    }

    /// Duplication rate: 1.0 = all unique, 0.0 = all duplicates.
    #[must_use]
    pub fn uniqueness_rate(&self) -> f64 {
        if self.total_added == 0 {
            return 1.0;
        }
        self.total_unique as f64 / self.total_added as f64
    }
}

impl Default for IocDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"[{
        "uuid": "aabbccdd-1111-2222-3333-aabbccddee00",
        "info": "Test event",
        "threat_level_id": "2",
        "analysis": "1",
        "timestamp": "1700000000",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            {"type": "sha256", "value": "abc123", "to_ids": true, "comment": "test hash"},
            {"type": "ip-dst", "value": "1.2.3.4", "to_ids": true}
        ]
    }]"#;

    const SAMPLE_CSV: &str = "type,value,to_ids\nmd5,d41d8cd98f00b204e9800998ecf8427e,1\nip-dst,5.6.7.8,0\n";

    const SAMPLE_FREETEXT: &str = "# comment\n1.2.3.4\nevil.example.com\nhttp://example.com/malware\n";

    #[test]
    fn test_parse_json_basic() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        assert_eq!(feed.entries.len(), 1);
        assert_eq!(feed.entries[0].threat_level_id, 2);
        assert_eq!(feed.entries[0].attributes.len(), 2);
    }

    #[test]
    fn test_parse_json_tags() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        assert!(feed.entries[0].event_tags.contains(&"tlp:amber".to_string()));
    }

    #[test]
    fn test_parse_json_attributes() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        let sha256_attrs = feed.entries[0].attributes_of_type("sha256");
        assert_eq!(sha256_attrs.len(), 1);
        assert!(sha256_attrs[0].to_ids);
    }

    #[test]
    fn test_parse_csv_basic() {
        let parser = MispFeedParser::new();
        let cfg = CsvFeedConfig {
            type_column: 0,
            value_column: 1,
            to_ids_column: Some(2),
            has_header: true,
            ..Default::default()
        };
        let parser = parser.with_csv_config(cfg);
        let feed = parser.parse_csv_str("test", SAMPLE_CSV).unwrap();
        assert_eq!(feed.entries.len(), 2);
        assert!(feed.entries[0].attributes[0].to_ids);
        assert!(!feed.entries[1].attributes[0].to_ids);
    }

    #[test]
    fn test_parse_freetext() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_freetext_str("test", SAMPLE_FREETEXT).unwrap();
        assert_eq!(feed.entries.len(), 3);
        let types: Vec<&str> = feed.entries.iter().map(|e| e.attributes[0].attr_type.as_str()).collect();
        assert!(types.contains(&"ip-dst"));
        assert!(types.contains(&"domain"));
        assert!(types.contains(&"url"));
    }

    #[test]
    fn test_infer_ioc_type_ip() {
        assert_eq!(infer_ioc_type("192.168.1.1"), "ip-dst");
    }

    #[test]
    fn test_infer_ioc_type_sha256() {
        assert_eq!(infer_ioc_type(&"a".repeat(64)), "sha256");
    }

    #[test]
    fn test_infer_ioc_type_md5() {
        assert_eq!(infer_ioc_type(&"b".repeat(32)), "md5");
    }

    #[test]
    fn test_infer_ioc_type_domain() {
        assert_eq!(infer_ioc_type("evil.example.com"), "domain");
    }

    #[test]
    fn test_infer_ioc_type_url() {
        assert_eq!(infer_ioc_type("https://example.com/malware"), "url");
    }

    #[test]
    fn test_ioc_deduplication() {
        let mut dedup = IocDeduplicator::new();
        dedup.add(IocRecord::new("md5", "abc123"));
        dedup.add(IocRecord::new("md5", "abc123")); // duplicate
        dedup.add(IocRecord::new("ip-dst", "1.2.3.4"));
        assert_eq!(dedup.total_unique, 2);
        assert_eq!(dedup.total_added, 3);
    }

    #[test]
    fn test_ioc_uniqueness_rate() {
        let mut dedup = IocDeduplicator::new();
        dedup.add(IocRecord::new("md5", "a"));
        dedup.add(IocRecord::new("md5", "a"));
        assert!((dedup.uniqueness_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_event_merger() {
        let mut merger = EventMerger::new();
        let e1 = FeedEntry::new("uuid-1", "Event A");
        let mut e2 = FeedEntry::new("uuid-1", "Event A");
        e2.attributes.push(FeedAttribute::new("sha256", "abc"));
        merger.add(e1);
        merger.add(e2);
        assert_eq!(merger.merged_count, 1);
        assert_eq!(merger.total(), 1);
        let entries = merger.finalize();
        assert_eq!(entries[0].attributes.len(), 1);
    }

    #[test]
    fn test_feed_extract_iocs() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        let iocs = feed.extract_iocs();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn test_feed_entries_by_threat_level() {
        let parser = MispFeedParser::new();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        assert_eq!(feed.entries_by_threat_level(2).len(), 1);
        assert_eq!(feed.entries_by_threat_level(1).len(), 0);
    }

    #[test]
    fn test_paginator() {
        let mut pager = FeedPaginator::new(10);
        pager.set_total(25);
        assert_eq!(pager.total_pages(), Some(3));
        assert!(pager.has_more());
        pager.next_page();
        assert!(pager.has_more());
        pager.next_page();
        assert!(!pager.has_more());
    }

    #[test]
    fn test_ioc_record_merge() {
        let mut r1 = IocRecord::new("md5", "abc");
        r1.add_source("event-1");
        r1.first_seen = Some(100);

        let mut r2 = IocRecord::new("md5", "abc");
        r2.add_source("event-2");
        r2.first_seen = Some(50);
        r2.last_seen = Some(200);

        r1.merge(&r2);
        assert_eq!(r1.source_events.len(), 2);
        assert_eq!(r1.first_seen, Some(50));
        assert_eq!(r1.last_seen, Some(200));
        assert_eq!(r1.occurrence_count, 2);
    }

    #[test]
    fn test_parser_to_ids_filter() {
        let parser = MispFeedParser::new().to_ids_only();
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        assert!(feed.entries[0].attributes.iter().all(|a| a.to_ids));
    }

    #[test]
    fn test_parser_type_filter() {
        let parser = MispFeedParser::new()
            .include_types(["sha256"]);
        let feed = parser.parse_json_str("test", SAMPLE_JSON).unwrap();
        assert_eq!(feed.entries[0].attributes.len(), 1);
        assert_eq!(feed.entries[0].attributes[0].attr_type, "sha256");
    }
}
