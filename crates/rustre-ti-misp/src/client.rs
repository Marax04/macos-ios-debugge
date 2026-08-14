//! MISP REST API client.
//!
//! Provides two transport layers:
//! - [`MispClient`]: full reqwest-based async client with `auth_key` header.
//! - [`MispRawClient`]: manual HTTP/1.1 over `tokio::net::TcpStream` (kept for
//!   environments without TLS libraries).
//! - [`MispFeedReader`]: read a remote MISP feed manifest + events via HTTP.

use reqwest::{
    Client as HttpClient,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::MispError;
use crate::models::{
    MispAnalysis, MispAttribute, MispDistribution, MispEvent, MispThreatLevel, NewMispAttribute,
    NewMispEvent,
};

// ---------------------------------------------------------------------------
// MispClient — reqwest-based
// ---------------------------------------------------------------------------

/// Full async MISP REST API client backed by [`reqwest`].
///
/// All requests include the `Authorization` header set to the API key.
pub struct MispClient {
    base_url: String,
    /// Stored for inspection / re-use (already embedded in `http` default headers).
    api_key: String,
    http: HttpClient,
}

impl MispClient {
    /// Read-only accessor for the configured API key.
    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a new client.
    ///
    /// `base_url` should be e.g. `https://misp.example.com` (no trailing slash).
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self, MispError> {
        let key_str = api_key.into();
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "Authorization",
            HeaderValue::from_str(&key_str)
                .map_err(|_| MispError::InvalidInput("invalid API key characters".into()))?,
        );
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = HttpClient::builder()
            .default_headers(default_headers)
            .danger_accept_invalid_certs(false)
            .build()?;

        Ok(Self {
            base_url: base_url.into(),
            api_key: key_str,
            http,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a client that skips TLS certificate verification (useful for
    /// self-signed certs in lab environments).
    pub fn new_insecure(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, MispError> {
        let key_str = api_key.into();
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "Authorization",
            HeaderValue::from_str(&key_str)
                .map_err(|_| MispError::InvalidInput("invalid API key characters".into()))?,
        );
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = HttpClient::builder()
            .default_headers(default_headers)
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            base_url: base_url.into(),
            api_key: key_str,
            http,
        })
    }

    /// Build a `MispClient` from the `MISP_URL` and `MISP_KEY` environment
    /// variables.
    ///
    /// # Errors
    /// Returns [`MispError::EnvVar`] if either variable is absent.
    pub fn from_env() -> Result<Self, MispError> {
        let url = std::env::var("MISP_URL").map_err(|_| MispError::EnvVar("MISP_URL".into()))?;
        let key = std::env::var("MISP_KEY").map_err(|_| MispError::EnvVar("MISP_KEY".into()))?;
        Self::new(url, key)
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value, MispError> {
        let resp = self.http.get(self.url(path)).send().await?;
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp.json().await?),
            401 | 403 => Err(MispError::AuthError),
            404 => Err(MispError::not_found(path)),
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(MispError::Http { status, body })
            }
        }
    }

    async fn post_json(
        &self,
        path: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, MispError> {
        let resp = self.http.post(self.url(path)).json(payload).send().await?;
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp.json().await?),
            401 | 403 => Err(MispError::AuthError),
            404 => Err(MispError::not_found(path)),
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(MispError::Http { status, body })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Public API — Events
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Return the most recent `limit` events from this MISP instance.
    pub async fn get_events(&self, limit: usize) -> Result<Vec<MispEvent>, MispError> {
        let payload = serde_json::json!({
            "returnFormat": "json",
            "limit": limit,
            "page": 1,
        });
        let json = self.post_json("/events/restSearch", &payload).await?;
        Self::parse_events_list(&json)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve a single event by its numeric ID.
    pub async fn get_event_by_id(&self, event_id: u64) -> Result<MispEvent, MispError> {
        let path = format!("/events/{event_id}");
        let json = self.get_json(&path).await?;
        Self::parse_event(&json["Event"])
            .ok_or_else(|| MispError::not_found(format!("event {event_id}")))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search events with an optional filter string (legacy `searchinfo` endpoint).
    pub async fn search_events(&self, filter: Option<&str>) -> Result<Vec<MispEvent>, MispError> {
        let path = match filter {
            Some(f) => format!("/events/index/searchinfo:{f}"),
            None => "/events/index".to_string(),
        };
        let json = self.get_json(&path).await?;
        Self::parse_events_list(&json)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a new event on the MISP instance and return the assigned ID.
    pub async fn add_event(&self, event: &NewMispEvent) -> Result<u64, MispError> {
        let payload = serde_json::json!({
            "Event": {
                "info": event.info,
                "threat_level_id": event.threat_level_id.to_string(),
                "analysis": event.analysis.to_string(),
                "distribution": event.distribution.as_id().to_string(),
                "date": event.date,
            }
        });
        let json = self.post_json("/events", &payload).await?;
        let id = json["Event"]["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| json["Event"]["id"].as_u64())
            .ok_or_else(|| MispError::invalid_input("no event id in response"))?;
        Ok(id)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Publish an event so it is shared with connected instances/communities.
    pub async fn publish_event(&self, event_id: u64) -> Result<(), MispError> {
        let path = format!("/events/publish/{event_id}");
        let payload = serde_json::json!({});
        self.post_json(&path, &payload).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Public API — Attributes
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Add an attribute to an existing event and return the assigned attribute ID.
    pub async fn add_attribute(
        &self,
        event_id: u64,
        attr: &NewMispAttribute,
    ) -> Result<u64, MispError> {
        let payload = serde_json::json!({
            "Attribute": {
                "event_id": event_id.to_string(),
                "category": attr.category,
                "type": attr.ty,
                "value": attr.value,
                "to_ids": attr.to_ids,
                "comment": attr.comment,
                "distribution": attr.distribution.as_id().to_string(),
            }
        });
        let path = format!("/attributes/add/{event_id}");
        let json = self.post_json(&path, &payload).await?;
        let id = json["Attribute"]["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| json["Attribute"]["id"].as_u64())
            .ok_or_else(|| MispError::invalid_input("no attribute id in response"))?;
        Ok(id)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search attributes by `IoC` value and optional type filter.
    ///
    /// `ioc_type` follows MISP naming (e.g. `"ip-dst"`, `"sha256"`). Pass an
    /// empty string to search across all types.
    pub async fn search_by_ioc(
        &self,
        value: &str,
        ioc_type: &str,
    ) -> Result<Vec<MispAttribute>, MispError> {
        let mut payload = serde_json::json!({
            "returnFormat": "json",
            "value": value,
        });
        if !ioc_type.is_empty() {
            payload["type"] = serde_json::Value::String(ioc_type.to_string());
        }
        let json = self.post_json("/attributes/restSearch", &payload).await?;
        let Some(arr) = json["response"]["Attribute"].as_array() else {
            return Ok(Vec::new());
        };
        let attrs = arr.iter().filter_map(Self::parse_attribute).collect();
        Ok(attrs)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search attributes by value (legacy method, no type filter).
    pub async fn search_attributes(&self, value: &str) -> Result<Vec<MispAttribute>, MispError> {
        self.search_by_ioc(value, "").await
    }

    // -----------------------------------------------------------------------
    // Public API — Feeds
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve events from a MISP feed by its numeric ID.
    pub async fn get_feed_events(&self, feed_id: u64) -> Result<Vec<MispEvent>, MispError> {
        let path = format!("/feeds/previewIndex/{feed_id}");
        let json = self.get_json(&path).await?;
        Self::parse_events_list(&json)
    }

    // -----------------------------------------------------------------------
    // Create event (legacy — takes MispEvent, returns MispEvent)
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a new event on the MISP instance (legacy, returns full event).
    pub async fn create_event(&self, event: &MispEvent) -> Result<MispEvent, MispError> {
        let payload = serde_json::json!({
            "Event": {
                "info": event.info,
                "threat_level_id": event.threat_level.as_id().to_string(),
                "analysis": event.analysis.as_id().to_string(),
                "distribution": event.distribution.as_id().to_string(),
            }
        });
        let json = self.post_json("/events", &payload).await?;
        Self::parse_event(&json["Event"])
            .ok_or_else(|| MispError::invalid_input("MISP returned no Event in create response"))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Add attribute (legacy, takes `MispAttribute`, returns `MispAttribute`).
    pub async fn add_attribute_full(
        &self,
        event_id: u64,
        attr: &MispAttribute,
    ) -> Result<MispAttribute, MispError> {
        let payload = serde_json::json!({
            "Attribute": {
                "event_id": event_id.to_string(),
                "category": attr.category,
                "type": attr.ty,
                "value": attr.value,
                "to_ids": attr.to_ids,
                "comment": attr.comment,
            }
        });
        let path = format!("/attributes/add/{event_id}");
        let json = self.post_json(&path, &payload).await?;
        Self::parse_attribute(&json["Attribute"])
            .ok_or_else(|| MispError::invalid_input("malformed attribute response"))
    }

    // -----------------------------------------------------------------------
    // Parsers
    // -----------------------------------------------------------------------

    fn parse_events_list(json: &serde_json::Value) -> Result<Vec<MispEvent>, MispError> {
        // MISP restSearch wraps results in {"response": [...]}
        let arr_opt = if let Some(arr) = json["response"].as_array() {
            Some(arr)
        } else {
            json.as_array()
        };
        let events = arr_opt
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        // Each element may be {"Event": {...}} or the event object directly.
                        let ev = if e["Event"].is_object() {
                            &e["Event"]
                        } else {
                            e
                        };
                        Self::parse_event(ev)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(events)
    }

    fn parse_event(e: &serde_json::Value) -> Option<MispEvent> {
        if e.is_null() || !e.is_object() {
            return None;
        }
        let id = e["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| e["id"].as_u64());
        let uuid = e["uuid"].as_str().unwrap_or("").to_string();
        let info = e["info"].as_str().unwrap_or("").to_string();
        let tl_id: u8 = e["threat_level_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| e["threat_level_id"].as_u64().map(|v| v as u8))
            .unwrap_or(4);
        let an_id: u8 = e["analysis"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| e["analysis"].as_u64().map(|v| v as u8))
            .unwrap_or(0);
        let dist_id: u8 = e["distribution"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| e["distribution"].as_u64().map(|v| v as u8))
            .unwrap_or(0);

        let attributes = e["Attribute"]
            .as_array()
            .map(|arr| arr.iter().filter_map(Self::parse_attribute).collect())
            .unwrap_or_default();

        let tags = e["Tag"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        let name = t["name"].as_str()?;
                        let color = t["colour"].as_str().unwrap_or("#cccccc");
                        Some(crate::models::MispTag::new(name, color))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(MispEvent {
            id,
            uuid,
            info,
            threat_level: MispThreatLevel::from_id(tl_id),
            analysis: MispAnalysis::from_id(an_id),
            distribution: match dist_id {
                1 => MispDistribution::Community,
                2 => MispDistribution::Connected,
                3 => MispDistribution::All,
                4 => MispDistribution::SharingGroup,
                5 => MispDistribution::Inherit,
                _ => MispDistribution::Organization,
            },
            attributes,
            objects: Vec::new(),
            tags,
        })
    }

    fn parse_attribute(a: &serde_json::Value) -> Option<MispAttribute> {
        if a.is_null() || !a.is_object() {
            return None;
        }
        Some(MispAttribute {
            id: a["id"].as_str().and_then(|s| s.parse().ok()),
            event_id: a["event_id"].as_str().and_then(|s| s.parse().ok()),
            category: a["category"].as_str().unwrap_or("").to_string(),
            ty: a["type"].as_str().unwrap_or("").to_string(),
            value: a["value"].as_str().unwrap_or("").to_string(),
            to_ids: a["to_ids"].as_bool().unwrap_or(false),
            comment: a["comment"].as_str().unwrap_or("").to_string(),
            tags: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// MispFeedReader — HTTP feed reader
// ---------------------------------------------------------------------------

/// Reads a public (unauthenticated) MISP feed from a remote HTTP(S) URL.
///
/// MISP feeds expose a `manifest.json` listing event UUIDs and a per-event
/// JSON file at `<uuid>.json`. This reader fetches both.
pub struct MispFeedReader {
    base_url: String,
    http: HttpClient,
}

impl MispFeedReader {
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a new feed reader pointing at `base_url`
    /// (e.g. `https://www.circl.lu/doc/misp/feed-osint`).
    pub fn new(base_url: impl Into<String>) -> Result<Self, MispError> {
        let http = HttpClient::builder().build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Fetch the feed manifest and return the list of event UUIDs.
    pub async fn fetch_manifest(&self) -> Result<Vec<String>, MispError> {
        let url = format!("{}/manifest.json", self.base_url);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(MispError::Http { status, body });
        }
        let json: serde_json::Value = resp.json().await?;
        let uuids = json
            .as_object()
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        Ok(uuids)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Fetch a single event by its UUID from the feed.
    pub async fn fetch_event(&self, uuid: &str) -> Result<MispEvent, MispError> {
        let url = format!("{}/{uuid}.json", self.base_url);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(MispError::Http { status, body });
        }
        let json: serde_json::Value = resp.json().await?;
        let ev = if json["Event"].is_object() {
            &json["Event"]
        } else {
            &json
        };
        MispClient::parse_event(ev)
            .ok_or_else(|| MispError::invalid_input(format!("could not parse event {uuid}")))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Fetch all events listed in the feed manifest.
    ///
    /// Errors on individual events are silently skipped; only successfully
    /// parsed events are returned.
    pub async fn fetch_all_events(&self) -> Result<Vec<MispEvent>, MispError> {
        let uuids = self.fetch_manifest().await?;
        let mut events = Vec::with_capacity(uuids.len());
        for uuid in &uuids {
            if let Ok(ev) = self.fetch_event(uuid).await {
                events.push(ev);
            }
        }
        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// MispRawClient — raw TCP transport (legacy, no reqwest)
// ---------------------------------------------------------------------------

/// MISP REST API client using manual HTTP/1.1 over `tokio::net::TcpStream`.
///
/// Kept for environments where reqwest / OpenSSL is unavailable. New code
/// should prefer [`MispClient`].
pub struct MispRawClient {
    base_url: String,
    api_key: String,
    verify_tls: bool,
}

impl MispRawClient {
    /// Create a new raw client.
    #[must_use]
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            verify_tls: true,
        }
    }

    /// Disable TLS verification.
    #[must_use]
    pub const fn with_no_tls_verify(mut self) -> Self {
        self.verify_tls = false;
        self
    }

    fn parse_host_port(&self) -> (String, u16) {
        let without_scheme = self
            .base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
        if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_string(), p.parse().unwrap_or(443))
        } else {
            (authority.to_string(), 443)
        }
    }

    fn reject_https(&self) -> Result<(), MispError> {
        if self.base_url.starts_with("https://") {
            return Err(MispError::invalid_input(
                "MispRawClient does not support TLS; use MispClient for https base_url to avoid leaking the API key over plaintext",
            ));
        }
        Ok(())
    }

    async fn http_get(&self, path: &str) -> Result<String, MispError> {
        self.reject_https()?;
        let (host, port) = self.parse_host_port();
        let stream = TcpStream::connect(format!("{host}:{port}")).await?;
        self.send_get(stream, &host, path).await
    }

    async fn http_post(&self, path: &str, body: &str) -> Result<String, MispError> {
        self.reject_https()?;
        let (host, port) = self.parse_host_port();
        let stream = TcpStream::connect(format!("{host}:{port}")).await?;
        self.send_post(stream, &host, path, body).await
    }

    async fn send_get(
        &self,
        mut stream: TcpStream,
        host: &str,
        path: &str,
    ) -> Result<String, MispError> {
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {key}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            key = self.api_key
        );
        stream.write_all(req.as_bytes()).await?;
        let raw = Self::read_response(&mut stream).await?;
        Self::extract_body(&raw)
    }

    async fn send_post(
        &self,
        mut stream: TcpStream,
        host: &str,
        path: &str,
        body: &str,
    ) -> Result<String, MispError> {
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {key}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nAccept: application/json\r\nConnection: close\r\n\r\n{body}",
            key = self.api_key,
            len = body.len()
        );
        stream.write_all(req.as_bytes()).await?;
        let raw = Self::read_response(&mut stream).await?;
        Self::extract_body(&raw)
    }

    async fn read_response(stream: &mut TcpStream) -> Result<String, MispError> {
        // Cap at 32 MiB to prevent a malicious server from exhausting memory.
        const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if data.len() + n > MAX_RESPONSE_BYTES {
                return Err(MispError::invalid_input(
                    "response exceeds maximum allowed size (32 MiB)",
                ));
            }
            data.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(data).map_err(|e| MispError::invalid_input(format!("response is not valid UTF-8: {e}")))
    }

    fn extract_body(raw: &str) -> Result<String, MispError> {
        if let Some(pos) = raw.find("\r\n\r\n") {
            let header = &raw[..pos];
            let body = raw[pos + 4..].to_string();
            let status: u16 = header
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
            match status {
                200..=299 => Ok(body),
                401 | 403 => Err(MispError::AuthError),
                404 => Err(MispError::not_found("MISP resource not found")),
                _ => Err(MispError::Http { status, body }),
            }
        } else {
            Err(MispError::invalid_input("malformed HTTP response"))
        }
    }

    // -----------------------------------------------------------------------
    // Public API (mirrors MispClient)
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search events with an optional filter string.
    pub async fn search_events(&self, filter: Option<&str>) -> Result<Vec<MispEvent>, MispError> {
        let path = match filter {
            Some(f) => format!("/events/index/searchinfo:{f}"),
            None => "/events/index".to_string(),
        };
        let body = self.http_get(&path).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        MispClient::parse_events_list(&json)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve a single event by its ID.
    pub async fn get_event(&self, id: u64) -> Result<MispEvent, MispError> {
        let path = format!("/events/{id}");
        let body = self.http_get(&path).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        MispClient::parse_event(&json["Event"])
            .ok_or_else(|| MispError::not_found(format!("event {id}")))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Create a new event on the MISP instance.
    pub async fn create_event(&self, event: &MispEvent) -> Result<MispEvent, MispError> {
        let payload = serde_json::json!({
            "Event": {
                "info": event.info,
                "threat_level_id": event.threat_level.as_id().to_string(),
                "analysis": event.analysis.as_id().to_string(),
                "distribution": event.distribution.as_id().to_string(),
            }
        });
        let body = self.http_post("/events", &payload.to_string()).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        MispClient::parse_event(&json["Event"])
            .ok_or_else(|| MispError::invalid_input("MISP returned no Event in create response"))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Add an attribute to an existing event.
    pub async fn add_attribute(
        &self,
        event_id: u64,
        attr: &MispAttribute,
    ) -> Result<MispAttribute, MispError> {
        let payload = serde_json::json!({
            "Attribute": {
                "event_id": event_id.to_string(),
                "category": attr.category,
                "type": attr.ty,
                "value": attr.value,
                "to_ids": attr.to_ids,
                "comment": attr.comment,
            }
        });
        let path = format!("/attributes/add/{event_id}");
        let body = self.http_post(&path, &payload.to_string()).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        MispClient::parse_attribute(&json["Attribute"])
            .ok_or_else(|| MispError::invalid_input("malformed attribute response"))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Search attributes by value.
    pub async fn search_attributes(&self, value: &str) -> Result<Vec<MispAttribute>, MispError> {
        let payload = serde_json::json!({
            "returnFormat": "json",
            "value": value,
        });
        let body = self
            .http_post("/attributes/restSearch", &payload.to_string())
            .await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let Some(arr) = json["response"]["Attribute"].as_array() else {
            return Ok(Vec::new());
        };
        let attrs = arr.iter().filter_map(MispClient::parse_attribute).collect();
        Ok(attrs)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve events from a MISP feed.
    pub async fn get_feed_events(&self, feed_id: u64) -> Result<Vec<MispEvent>, MispError> {
        let path = format!("/feeds/previewIndex/{feed_id}");
        let body = self.http_get(&path).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        MispClient::parse_events_list(&json)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Parser tests use the shared static methods on MispClient.

    #[test]
    fn test_parse_event() {
        let j = json!({
            "Event": {
                "id": "1",
                "uuid": "aaaa-bbbb",
                "info": "Test Event",
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "3",
                "Attribute": [
                    {
                        "id": "10",
                        "event_id": "1",
                        "category": "Network activity",
                        "type": "ip-dst",
                        "value": "1.2.3.4",
                        "to_ids": true,
                        "comment": ""
                    }
                ]
            }
        });
        let event = MispClient::parse_event(&j["Event"]).unwrap();
        assert_eq!(event.id, Some(1));
        assert_eq!(event.info, "Test Event");
        assert_eq!(event.threat_level, MispThreatLevel::Medium);
        assert_eq!(event.analysis, MispAnalysis::Completed);
        assert_eq!(event.attributes.len(), 1);
        assert_eq!(event.attributes[0].value, "1.2.3.4");
    }

    #[test]
    fn test_parse_attribute() {
        let j = json!({
            "id": "5",
            "event_id": "1",
            "category": "Payload delivery",
            "type": "sha256",
            "value": "deadbeef",
            "to_ids": true,
            "comment": "sample hash"
        });
        let attr = MispClient::parse_attribute(&j).unwrap();
        assert_eq!(attr.ty, "sha256");
        assert_eq!(attr.value, "deadbeef");
        assert!(attr.to_ids);
    }

    #[test]
    fn test_extract_body_success() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let body = MispRawClient::extract_body(raw).unwrap();
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn test_extract_body_401() {
        let raw = "HTTP/1.1 401 Unauthorized\r\n\r\n{}";
        assert!(matches!(
            MispRawClient::extract_body(raw),
            Err(MispError::AuthError)
        ));
    }

    #[test]
    fn test_parse_events_list_empty() {
        let j = json!([]);
        let events = MispClient::parse_events_list(&j).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_events_list_rest_search_response() {
        let j = json!({
            "response": [
                {
                    "Event": {
                        "id": "1",
                        "uuid": "aaa",
                        "info": "Evt1",
                        "threat_level_id": "1",
                        "analysis": "0",
                        "distribution": "1",
                        "Attribute": []
                    }
                }
            ]
        });
        let events = MispClient::parse_events_list(&j).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].info, "Evt1");
    }

    /// Serialize env-var tests so that concurrent test threads do not race on
    /// `MISP_URL` / `MISP_KEY`.  The mutex is process-wide and held for the
    /// duration of each test body that touches those variables.
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_from_env_missing() {
        let _guard = env_var_lock();
        // Ensure env vars are unset for this test.
        unsafe {
            std::env::remove_var("MISP_URL");
            std::env::remove_var("MISP_KEY");
        }
        assert!(matches!(MispClient::from_env(), Err(MispError::EnvVar(_))));
    }

    #[test]
    fn test_from_env_ok() {
        let _guard = env_var_lock();
        unsafe {
            std::env::set_var("MISP_URL", "https://misp.test");
            std::env::set_var("MISP_KEY", "testkey");
        }
        let client = MispClient::from_env().unwrap();
        assert_eq!(client.base_url, "https://misp.test");
        assert_eq!(client.api_key, "testkey");
        unsafe {
            std::env::remove_var("MISP_URL");
            std::env::remove_var("MISP_KEY");
        }
    }

    #[test]
    fn test_misp_feed_reader_new() {
        let reader = MispFeedReader::new("https://feed.example.com").unwrap();
        assert_eq!(reader.base_url, "https://feed.example.com");
    }
}
