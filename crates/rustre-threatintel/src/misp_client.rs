//! MISP (Malware Information Sharing Platform) REST API client.
//!
//! MISP is an open-source threat intelligence platform that exposes a rich
//! REST API.  This module provides an async client for the most commonly used
//! endpoints: event search, attribute search, and attribute export.
//!
//! Authentication is performed via the `Authorization` header with the user's
//! MISP API key.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::TiError,
    ioc::{IoC, IoCType},
    provider::{TiProvider, TiResult, Verdict},
};

// ─────────────────────────────────────────────────────────────────────────────
// Core MISP types
// ─────────────────────────────────────────────────────────────────────────────

/// A MISP event (threat report / incident container).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    /// MISP-assigned numeric ID.
    pub id: Option<String>,
    /// UUID v4 identifier.
    pub uuid: Option<String>,
    /// Short title / description of the event.
    pub info: String,
    /// Distribution level (0=org-only … 4=all, 5=inherit).
    pub distribution: Option<String>,
    /// Threat level: 1=high, 2=medium, 3=low, 4=undefined.
    pub threat_level_id: Option<String>,
    /// Analysis state: 0=initial, 1=ongoing, 2=completed.
    pub analysis: Option<String>,
    /// ISO-8601 event date.
    pub date: Option<String>,
    /// Timestamp of last modification.
    pub timestamp: Option<String>,
    /// Organisation that created the event.
    pub org: Option<MispOrg>,
    /// Organisation that owns the event.
    pub orgc: Option<MispOrg>,
    /// Whether the event has been published.
    pub published: Option<bool>,
    /// Attributes (`IoCs`) attached to the event.
    pub attributes: Option<Vec<MispAttribute>>,
    /// MISP tags on this event.
    pub tag: Option<Vec<MispTag>>,
    /// Galaxy clusters related to the event.
    pub galaxy: Option<Vec<MispGalaxy>>,
}

impl MispEvent {
    /// Return the integer threat level (1–4) or `4` (undefined) if absent.
    #[must_use]
    pub fn threat_level(&self) -> u8 {
        self.threat_level_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4)
    }

    /// Map the MISP threat level to a confidence value in `[0, 100]`.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        match self.threat_level() {
            1 => 90, // high
            2 => 60, // medium
            3 => 30, // low
            _ => 0,
        }
    }
}

/// Organisation reference within a MISP event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispOrg {
    pub id: Option<String>,
    pub name: String,
    pub uuid: Option<String>,
}

/// A single MISP attribute (`IoC`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    /// MISP-assigned numeric ID.
    pub id: Option<String>,
    /// UUID v4 identifier.
    pub uuid: Option<String>,
    /// Attribute type (e.g. `"ip-dst"`, `"domain"`, `"md5"`).
    #[serde(rename = "type")]
    pub attr_type: String,
    /// Attribute category (e.g. `"Network activity"`, `"Payload delivery"`).
    pub category: Option<String>,
    /// The `IoC` value.
    pub value: String,
    /// Human-readable comment.
    pub comment: Option<String>,
    /// Whether this attribute should be used for IDS/SIEM rules.
    pub to_ids: Option<bool>,
    /// Whether this attribute has been deleted.
    pub deleted: Option<bool>,
    /// Timestamp of creation.
    pub timestamp: Option<String>,
    /// Tags attached to this attribute.
    pub tag: Option<Vec<MispTag>>,
    /// Sighting count.
    pub sightings: Option<Vec<MispSighting>>,
    /// Event ID this attribute belongs to.
    pub event_id: Option<String>,
}

impl MispAttribute {
    /// Convert this MISP attribute to a generic [`IoC`].
    ///
    /// Returns `None` when the attribute type cannot be mapped to a known
    /// [`IoCType`].
    #[must_use]
    pub fn to_ioc(&self) -> Option<IoC> {
        let ioc_type = misp_type_to_ioc_type(&self.attr_type)?;
        Some(IoC::new(ioc_type, self.value.clone(), "misp".to_owned()))
    }

    /// Return `true` when the attribute is marked for IDS consumption.
    #[must_use]
    pub fn is_ids_flag(&self) -> bool {
        self.to_ids.unwrap_or(false)
    }

    /// Return `true` when the attribute has been deleted.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.deleted.unwrap_or(false)
    }

    /// Return the tag names attached to this attribute.
    #[must_use]
    pub fn tag_names(&self) -> Vec<String> {
        self.tag
            .as_ref()
            .map(|tags| tags.iter().map(|t| t.name.clone()).collect())
            .unwrap_or_default()
    }
}

/// A MISP tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    pub id: Option<String>,
    /// Tag name, e.g. `"tlp:red"` or `"misp-galaxy:mitre-attack-pattern=\"Process Injection - T1055\""`.
    pub name: String,
    pub colour: Option<String>,
    pub exportable: Option<bool>,
}

/// A MISP sighting — evidence that an `IoC` was observed in the wild.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispSighting {
    pub id: Option<String>,
    pub attribute_id: Option<String>,
    pub event_id: Option<String>,
    /// Sighting type: 0=sighting, 1=false positive, 2=expiration.
    #[serde(rename = "type")]
    pub sighting_type: Option<String>,
    pub date_sighting: Option<String>,
    pub org_id: Option<String>,
}

/// A MISP galaxy entry (threat actor, malware family, ATT&CK technique, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxy {
    pub id: Option<String>,
    pub uuid: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub galaxy_type: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "GalaxyCluster")]
    pub clusters: Option<Vec<MispGalaxyCluster>>,
}

/// A cluster within a MISP galaxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxyCluster {
    pub id: Option<String>,
    pub uuid: Option<String>,
    pub value: String,
    pub description: Option<String>,
    #[serde(rename = "tag_name")]
    pub tag_name: Option<String>,
    pub meta: Option<HashMap<String, serde_json::Value>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type mappings
// ─────────────────────────────────────────────────────────────────────────────

/// Map a MISP attribute type string to the corresponding [`IoCType`].
///
/// Returns `None` when there is no sensible mapping.
#[must_use]
pub fn misp_type_to_ioc_type(misp_type: &str) -> Option<IoCType> {
    match misp_type {
        "md5" | "filename|md5" => Some(IoCType::Md5),
        "sha1" | "filename|sha1" => Some(IoCType::Sha1),
        "sha256" | "filename|sha256" => Some(IoCType::Sha256),
        "sha512" | "filename|sha512" => Some(IoCType::Sha512),
        "ip-src" | "ip-dst" | "ip-src|port" | "ip-dst|port" => Some(IoCType::Ip),
        "domain" | "hostname" | "domain|ip" => Some(IoCType::Domain),
        "url" | "uri" => Some(IoCType::Url),
        "email-src" | "email-dst" | "email-reply-to" => Some(IoCType::Email),
        "filename" | "target-filename" => Some(IoCType::Filename),
        "regkey" | "regkey|value" => Some(IoCType::Registry),
        "mutex" => Some(IoCType::Mutex),
        "yara" => Some(IoCType::Yara),
        _ => None,
    }
}

/// Map an [`IoCType`] back to the canonical MISP attribute type string.
#[must_use]
pub const fn ioc_type_to_misp_type(ioc_type: &IoCType) -> &'static str {
    match ioc_type {
        IoCType::Md5 => "md5",
        IoCType::Sha1 => "sha1",
        IoCType::Sha256 => "sha256",
        IoCType::Sha512 => "sha512",
        IoCType::Ip => "ip-dst",
        IoCType::Domain => "domain",
        IoCType::Url => "url",
        IoCType::Email => "email-src",
        IoCType::Filename => "filename",
        IoCType::Registry => "regkey",
        IoCType::Mutex => "mutex",
        IoCType::Yara => "yara",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MispClient
// ─────────────────────────────────────────────────────────────────────────────

/// Async REST client for a MISP instance.
///
/// ```rust,no_run
/// # use rustre_threatintel::misp_client::MispClient;
/// # #[tokio::main] async fn main() {
/// let client = MispClient::new("https://misp.example.org", "MY_API_KEY");
/// let events = client.search_events("Emotet").await.unwrap();
/// # }
/// ```
pub struct MispClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
    /// Skip TLS certificate verification (for self-signed MISP instances).
    insecure: bool,
}

impl MispClient {
    /// Create a new MISP client.
    ///
    /// `base_url` should be the root of the MISP web application, e.g.
    /// `"https://misp.example.org"`.
    #[must_use]
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            api_key: api_key.into(),
            http: reqwest::Client::new(),
            insecure: false,
        }
    }

    /// Allow insecure TLS (self-signed certificates).
    ///
    /// Returns `None` if the underlying TLS client cannot be built (e.g. the
    /// system has no TLS provider available).  Callers must handle this case
    /// rather than silently falling back to a *secure* client while the flag
    /// says insecure.
    #[must_use]
    pub fn insecure(mut self) -> Option<Self> {
        self.insecure = true;
        match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(client) => {
                self.http = client;
                Some(self)
            }
            Err(_) => None,
        }
    }

    fn auth_headers(&self) -> [(&'static str, String); 2] {
        [
            ("Authorization", self.api_key.clone()),
            ("Accept", "application/json".to_owned()),
        ]
    }

    /// Search for MISP events by a free-text query string.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn search_events(&self, query: &str) -> Result<Vec<MispEvent>, TiError> {
        let url = format!("{}/events/restSearch", self.base_url);
        let body = serde_json::json!({
            "returnFormat": "json",
            "value": query,
            "limit": 50,
            "page": 1,
        });

        let mut req = self.http.post(&url).json(&body);
        for (k, v) in self.auth_headers() {
            req = req.header(k, v);
        }

        let resp = req.send().await.map_err(|e| TiError::Http(e.to_string()))?;
        if resp.status() == 401 {
            return Err(TiError::InvalidApiKey("misp".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let events_val = raw.get("response").unwrap_or(&raw);
        let events: Vec<serde_json::Value> = if events_val.is_array() {
            serde_json::from_value(events_val.clone()).map_err(|e| TiError::Parse(e.to_string()))?
        } else {
            Vec::new()
        };

        let mut result = Vec::with_capacity(events.len());
        for ev in events {
            let event_obj = ev.get("Event").unwrap_or(&ev);
            if let Ok(e) = serde_json::from_value::<MispEvent>(event_obj.clone()) {
                result.push(e);
            }
        }
        Ok(result)
    }

    /// Search for MISP attributes (`IoCs`) by value.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn search_attributes(&self, value: &str) -> Result<Vec<MispAttribute>, TiError> {
        let url = format!("{}/attributes/restSearch", self.base_url);
        let body = serde_json::json!({
            "returnFormat": "json",
            "value": value,
            "limit": 100,
            "page": 1,
        });

        let mut req = self.http.post(&url).json(&body);
        for (k, v) in self.auth_headers() {
            req = req.header(k, v);
        }

        let resp = req.send().await.map_err(|e| TiError::Http(e.to_string()))?;
        if resp.status() == 401 {
            return Err(TiError::InvalidApiKey("misp".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let attrs_val = raw
            .get("response")
            .and_then(|r| r.get("Attribute"))
            .cloned()
            .unwrap_or(serde_json::Value::Array(Vec::new()));

        serde_json::from_value(attrs_val).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Fetch a specific MISP event by its numeric ID.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn get_event(&self, event_id: u64) -> Result<Option<MispEvent>, TiError> {
        let url = format!("{}/events/{}", self.base_url, event_id);
        let mut req = self.http.get(&url);
        for (k, v) in self.auth_headers() {
            req = req.header(k, v);
        }

        let resp = req.send().await.map_err(|e| TiError::Http(e.to_string()))?;
        if resp.status() == 404 {
            return Ok(None);
        }
        if resp.status() == 401 {
            return Err(TiError::InvalidApiKey("misp".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let event_obj = raw.get("Event").unwrap_or(&raw);
        let event =
            serde_json::from_value(event_obj.clone()).map_err(|e| TiError::Parse(e.to_string()))?;
        Ok(Some(event))
    }

    /// Create a new MISP event.
    ///
    /// Returns the newly created event with its server-assigned `id`.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn create_event(&self, event: &MispEvent) -> Result<MispEvent, TiError> {
        let url = format!("{}/events", self.base_url);
        let body = serde_json::json!({ "Event": event });
        let mut req = self.http.post(&url).json(&body);
        for (k, v) in self.auth_headers() {
            req = req.header(k, v);
        }

        let resp = req.send().await.map_err(|e| TiError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let event_obj = raw.get("Event").unwrap_or(&raw);
        serde_json::from_value(event_obj.clone()).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Add an attribute to an existing MISP event.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn add_attribute(
        &self,
        event_id: u64,
        attr: &MispAttribute,
    ) -> Result<MispAttribute, TiError> {
        let url = format!("{}/attributes/add/{}", self.base_url, event_id);
        let body = serde_json::json!({ "Attribute": attr });
        let mut req = self.http.post(&url).json(&body);
        for (k, v) in self.auth_headers() {
            req = req.header(k, v);
        }

        let resp = req.send().await.map_err(|e| TiError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let raw: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let attr_obj = raw.get("Attribute").unwrap_or(&raw);
        serde_json::from_value(attr_obj.clone()).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Export all attributes from a MISP event as generic [`IoC`] values.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP or deserialization errors.
    pub async fn export_iocs(&self, event_id: u64) -> Result<Vec<IoC>, TiError> {
        let event = self.get_event(event_id).await?;
        let iocs = event
            .and_then(|e| e.attributes)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| !a.is_deleted())
            .filter_map(|a| a.to_ioc())
            .collect();
        Ok(iocs)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TiProvider implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl TiProvider for MispClient {
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
            IoCType::Filename,
            IoCType::Registry,
            IoCType::Mutex,
        ]
    }

    fn rate_limit_per_minute(&self) -> u32 {
        120
    }

    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError> {
        let mut result = TiResult::new(ioc.clone());
        let attrs = self.search_attributes(&ioc.value).await?;

        if !attrs.is_empty() {
            let tag_names: Vec<String> = attrs
                .iter()
                .flat_map(MispAttribute::tag_names)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            result.verdicts.push(Verdict {
                malicious: attrs.iter().any(MispAttribute::is_ids_flag),
                confidence: 70,
                tags: tag_names,
                engine_count: 1,
                positive_count: u32::from(attrs.iter().any(MispAttribute::is_ids_flag)),
                first_seen: None,
                last_seen: None,
                description: Some(format!("{} MISP attribute(s) found", attrs.len())),
                provider: "misp".to_owned(),
            });
        }

        Ok(result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_misp_type_to_ioc_type_known() {
        assert_eq!(misp_type_to_ioc_type("md5"), Some(IoCType::Md5));
        assert_eq!(misp_type_to_ioc_type("ip-dst"), Some(IoCType::Ip));
        assert_eq!(misp_type_to_ioc_type("domain"), Some(IoCType::Domain));
        assert_eq!(misp_type_to_ioc_type("yara"), Some(IoCType::Yara));
    }

    #[test]
    fn test_misp_type_to_ioc_type_unknown() {
        assert_eq!(misp_type_to_ioc_type("btc"), None);
        assert_eq!(misp_type_to_ioc_type("pattern-in-memory"), None);
    }

    #[test]
    fn test_ioc_type_to_misp_type_roundtrip() {
        for t in [IoCType::Md5, IoCType::Sha256, IoCType::Ip, IoCType::Domain] {
            let misp_t = ioc_type_to_misp_type(&t);
            let back = misp_type_to_ioc_type(misp_t);
            assert_eq!(back, Some(t));
        }
    }

    #[test]
    fn test_attribute_to_ioc() {
        let attr = MispAttribute {
            id: None,
            uuid: None,
            attr_type: "sha256".to_owned(),
            category: None,
            value: "deadbeef".to_owned(),
            comment: None,
            to_ids: Some(true),
            deleted: None,
            timestamp: None,
            tag: None,
            sightings: None,
            event_id: None,
        };
        let ioc = attr.to_ioc().unwrap();
        assert_eq!(ioc.ioc_type, IoCType::Sha256);
        assert_eq!(ioc.value, "deadbeef");
    }

    #[test]
    fn test_attribute_to_ioc_unmapped_type() {
        let attr = MispAttribute {
            id: None,
            uuid: None,
            attr_type: "eppn".to_owned(),
            category: None,
            value: "user@example.com".to_owned(),
            comment: None,
            to_ids: None,
            deleted: None,
            timestamp: None,
            tag: None,
            sightings: None,
            event_id: None,
        };
        assert!(attr.to_ioc().is_none());
    }

    #[test]
    fn test_attribute_is_deleted() {
        let mut attr = MispAttribute {
            id: None,
            uuid: None,
            attr_type: "ip-dst".to_owned(),
            category: None,
            value: "1.2.3.4".to_owned(),
            comment: None,
            to_ids: None,
            deleted: Some(true),
            timestamp: None,
            tag: None,
            sightings: None,
            event_id: None,
        };
        assert!(attr.is_deleted());
        attr.deleted = Some(false);
        assert!(!attr.is_deleted());
    }

    #[test]
    fn test_event_threat_level_confidence() {
        let mut ev = MispEvent {
            id: None,
            uuid: None,
            info: "Test event".to_owned(),
            distribution: None,
            threat_level_id: Some("1".to_owned()),
            analysis: None,
            date: None,
            timestamp: None,
            org: None,
            orgc: None,
            published: None,
            attributes: None,
            tag: None,
            galaxy: None,
        };
        assert_eq!(ev.threat_level(), 1);
        assert_eq!(ev.confidence(), 90);
        ev.threat_level_id = Some("3".to_owned());
        assert_eq!(ev.confidence(), 30);
    }

    #[test]
    fn test_tag_names() {
        let attr = MispAttribute {
            id: None,
            uuid: None,
            attr_type: "md5".to_owned(),
            category: None,
            value: "abc".to_owned(),
            comment: None,
            to_ids: None,
            deleted: None,
            timestamp: None,
            tag: Some(vec![
                MispTag {
                    id: None,
                    name: "tlp:white".to_owned(),
                    colour: None,
                    exportable: None,
                },
                MispTag {
                    id: None,
                    name: "misp-galaxy:threat-actor=\"APT29\"".to_owned(),
                    colour: None,
                    exportable: None,
                },
            ]),
            sightings: None,
            event_id: None,
        };
        let names = attr.tag_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"tlp:white".to_owned()));
    }
}
