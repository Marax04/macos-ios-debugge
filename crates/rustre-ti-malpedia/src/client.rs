//! Malpedia API client using manual HTTP/1.1 over a TLS stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::rustls::pki_types::ServerName;

use crate::cache::MalpediaCache;
use crate::error::MalpediaError;
use crate::models::{
    MalpediaActor, MalpediaFamily, MalpediaFamilySummary, MalpediaSample, MalpediaThreatActor,
};

const MALPEDIA_HOST: &str = "malpedia.caad.fkie.fraunhofer.de";
const MALPEDIA_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// In-memory cache
// ---------------------------------------------------------------------------

/// A single cached value with a timestamp for TTL checking.
struct CacheEntry<T> {
    value: T,
    inserted_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            inserted_at: Instant::now(),
        }
    }

    fn is_fresh(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() < ttl
    }
}

/// In-memory cache for Malpedia responses.
struct MemCache {
    families: HashMap<String, CacheEntry<MalpediaFamily>>,
    actors: HashMap<String, CacheEntry<MalpediaActor>>,
    families_list: Option<CacheEntry<Vec<MalpediaFamilySummary>>>,
    ttl: Duration,
}

impl MemCache {
    fn new(ttl: Duration) -> Self {
        Self {
            families: HashMap::new(),
            actors: HashMap::new(),
            families_list: None,
            ttl,
        }
    }

    fn get_family(&self, name: &str) -> Option<&MalpediaFamily> {
        self.families
            .get(name)
            .filter(|e| e.is_fresh(self.ttl))
            .map(|e| &e.value)
    }

    fn put_family(&mut self, fam: MalpediaFamily) {
        self.families
            .insert(fam.malpedia_name.clone(), CacheEntry::new(fam));
    }

    fn get_actor(&self, name: &str) -> Option<&MalpediaActor> {
        self.actors
            .get(name)
            .filter(|e| e.is_fresh(self.ttl))
            .map(|e| &e.value)
    }

    fn put_actor(&mut self, actor: MalpediaActor) {
        self.actors
            .insert(actor.name.clone(), CacheEntry::new(actor));
    }

    fn get_families_list(&self) -> Option<&Vec<MalpediaFamilySummary>> {
        self.families_list
            .as_ref()
            .filter(|e| e.is_fresh(self.ttl))
            .map(|e| &e.value)
    }

    fn put_families_list(&mut self, list: Vec<MalpediaFamilySummary>) {
        self.families_list = Some(CacheEntry::new(list));
    }
}

// ---------------------------------------------------------------------------
// MalpediaClient
// ---------------------------------------------------------------------------

/// Malpedia REST API client.
pub struct MalpediaClient {
    api_key: String,
    base_url: String,
    /// Optional persistent (SQLite/MySQL) cache.
    cache: Option<MalpediaCache>,
    /// In-memory cache shared across clones.
    mem: Arc<Mutex<MemCache>>,
}

impl MalpediaClient {
    /// Create a new client with a known API key.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: format!("https://{MALPEDIA_HOST}"),
            cache: None,
            mem: Arc::new(Mutex::new(MemCache::new(Duration::from_hours(1)))),
        }
    }

    /// Create a client whose API key is read from the `MALPEDIA_API_KEY`
    /// environment variable.
    ///
    /// Returns `None` when the variable is not set or empty.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("MALPEDIA_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())?;
        Some(Self::new(key))
    }

    /// Attach a persistent (SQLite/MySQL) cache.
    #[must_use]
    pub fn with_cache(mut self, cache: MalpediaCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Override the base URL (useful for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Override the in-memory cache TTL (default: 1 hour).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn with_mem_ttl(self, ttl: Duration) -> Self {
        *self.mem.lock().unwrap() = MemCache::new(ttl);
        self
    }

    fn parse_host_port(&self) -> (String, u16) {
        let s = self
            .base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        if let Some((h, p)) = s.rsplit_once(':') {
            (h.to_string(), p.parse().unwrap_or(MALPEDIA_PORT))
        } else {
            (s.to_string(), MALPEDIA_PORT)
        }
    }

    async fn http_get(&self, path: &str) -> Result<String, MalpediaError> {
        // Limit the response body to 64 MiB to prevent memory exhaustion from
        // a malicious or misbehaving server sending an unbounded response.
        const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
        let (host, port) = self.parse_host_port();

        // Build a TLS connector backed by the bundled Mozilla root certificates.
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(config));

        let tcp = TcpStream::connect(format!("{host}:{port}")).await?;
        let server_name = ServerName::try_from(host.as_str())
            .map_err(|e| MalpediaError::InvalidInput(format!("invalid hostname: {e}")))?
            .to_owned();
        let mut stream = connector.connect(server_name, tcp).await
            .map_err(MalpediaError::Network)?;

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: apitoken {key}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            key = self.api_key
        );
        stream.write_all(req.as_bytes()).await?;
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if data.len().saturating_add(n) > MAX_RESPONSE_BYTES {
                return Err(MalpediaError::InvalidInput(
                    "HTTP response exceeds 64 MiB limit".into(),
                ));
            }
            data.extend_from_slice(&buf[..n]);
        }
        let raw = String::from_utf8_lossy(&data).into_owned();
        Self::extract_body(&raw)
    }

    fn extract_body(raw: &str) -> Result<String, MalpediaError> {
        if let Some(pos) = raw.find("\r\n\r\n") {
            let header = &raw[..pos];
            let body = raw[pos + 4..].to_string();
            let status: u16 = header
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
            if status == 404 {
                return Err(MalpediaError::not_found("Malpedia resource"));
            }
            if status >= 400 {
                return Err(MalpediaError::Http { status, body });
            }
            Ok(body)
        } else {
            Err(MalpediaError::InvalidInput(
                "malformed HTTP response".into(),
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// List all malware families as lightweight summaries.
    ///
    /// Uses: `GET /api/list/families`
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub async fn list_families(&self) -> Result<Vec<MalpediaFamilySummary>, MalpediaError> {
        // 1. In-memory cache
        {
            if let Some(list) = self.mem.lock().unwrap().get_families_list() {
                return Ok(list.clone());
            }
        }
        // 2. Persistent cache
        if let Some(ref cache) = self.cache {
            let cached = cache.list_families()?;
            if !cached.is_empty() {
                let summaries: Vec<MalpediaFamilySummary> =
                    cached.iter().map(MalpediaFamilySummary::from).collect();
                self.mem
                    .lock()
                    .unwrap()
                    .put_families_list(summaries.clone());
                return Ok(summaries);
            }
        }
        // 3. API
        let body = self.http_get("/api/list/families").await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let summaries = Self::parse_family_summaries(&json);
        self.mem
            .lock()
            .unwrap()
            .put_families_list(summaries.clone());
        Ok(summaries)
    }

    /// Get a specific malware family by its Malpedia name.
    ///
    /// Uses: `GET /api/get/family/<name>`
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub async fn get_family(&self, name: &str) -> Result<MalpediaFamily, MalpediaError> {
        // 1. In-memory cache
        {
            if let Some(fam) = self.mem.lock().unwrap().get_family(name) {
                return Ok(fam.clone());
            }
        }
        // 2. Persistent cache
        if let Some(ref cache) = self.cache
            && let Some(fam) = cache.get_family(name)? {
                self.mem.lock().unwrap().put_family(fam.clone());
                return Ok(fam);
            }
        // 3. API
        let path = format!("/api/get/family/{name}");
        let body = self.http_get(&path).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let fam = Self::parse_single_family(name, &json);
        self.mem.lock().unwrap().put_family(fam.clone());
        if let Some(ref cache) = self.cache {
            cache.put_family(&fam)?;
        }
        Ok(fam)
    }

    /// Look up which malware family a hash (SHA-256) belongs to.
    ///
    /// Uses: `GET /api/find/sample/<sha256>`
    ///
    /// Returns `Ok(None)` when the hash is not known to Malpedia.
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub async fn lookup_hash(&self, hash: &str) -> Result<Option<MalpediaFamily>, MalpediaError> {
        let hash = hash.to_ascii_lowercase();
        // Check in-memory cached families first.
        {
            let guard = self.mem.lock().unwrap();
            for entry in guard.families.values() {
                if entry.is_fresh(guard.ttl) && entry.value.has_sample(&hash) {
                    return Ok(Some(entry.value.clone()));
                }
            }
        }
        // Check persistent cache.
        if let Some(ref cache) = self.cache {
            for fam in cache.list_families()? {
                if fam.has_sample(&hash) {
                    return Ok(Some(fam));
                }
            }
        }
        // Fall back to API.
        let path = format!("/api/find/sample/{hash}");
        match self.http_get(&path).await {
            Ok(body) => {
                let json: serde_json::Value = serde_json::from_str(&body)?;
                let family_name = json["family"].as_str().unwrap_or("").to_string();
                if family_name.is_empty() {
                    return Ok(None);
                }
                Ok(Some(self.get_family(&family_name).await?))
            }
            Err(MalpediaError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Alias for `lookup_hash` – kept for backwards compatibility.
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub async fn find_family_by_hash(
        &self,
        sha256: &str,
    ) -> Result<Option<MalpediaFamily>, MalpediaError> {
        self.lookup_hash(sha256).await
    }

    /// List all threat actors.
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    pub async fn list_actors(&self) -> Result<Vec<MalpediaActor>, MalpediaError> {
        if let Some(ref cache) = self.cache {
            let cached = cache.list_actors()?;
            if !cached.is_empty() {
                return Ok(cached);
            }
        }
        let body = self.http_get("/api/get/actors").await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let actors = Self::parse_actors(&json);
        if let Some(ref cache) = self.cache {
            for actor in &actors {
                cache.put_actor(actor)?;
            }
        }
        Ok(actors)
    }

    /// Get a specific threat actor by name.
    ///
    /// Uses: `GET /api/get/actor/<name>` (falls back to cached value).
    ///
    /// # Errors
    /// Returns an error if the network request or cache access fails.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub async fn get_actor(&self, name: &str) -> Result<MalpediaThreatActor, MalpediaError> {
        // 1. In-memory cache
        {
            if let Some(actor) = self.mem.lock().unwrap().get_actor(name) {
                return Ok(actor.clone());
            }
        }
        // 2. Persistent cache
        if let Some(ref cache) = self.cache
            && let Some(actor) = cache.get_actor(name)? {
                self.mem.lock().unwrap().put_actor(actor.clone());
                return Ok(actor);
            }
        // 3. API
        let path = format!("/api/get/actor/{name}");
        let body = self.http_get(&path).await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let actor = Self::parse_single_actor(name, &json);
        self.mem.lock().unwrap().put_actor(actor.clone());
        if let Some(ref cache) = self.cache {
            cache.put_actor(&actor)?;
        }
        Ok(actor)
    }

    /// Get YARA rules for a family (returns raw YARA text).
    ///
    /// # Errors
    /// Returns an error if the network request fails.
    pub async fn get_yara_rules(&self, family: &str) -> Result<String, MalpediaError> {
        let path = format!("/api/get/yara/{family}");
        self.http_get(&path).await
    }

    // -----------------------------------------------------------------------
    // Parsers
    // -----------------------------------------------------------------------

    fn parse_family_summaries(json: &serde_json::Value) -> Vec<MalpediaFamilySummary> {
        // Malpedia /api/list/families returns either:
        //   - an array of strings (canonical names only), or
        //   - an object mapping name → { common_name, ... }
        if let Some(arr) = json.as_array() {
            return arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| MalpediaFamilySummary::new(s, s))
                .collect();
        }
        if let Some(obj) = json.as_object() {
            return obj
                .iter()
                .map(|(k, v)| {
                    let common = v["common_name"].as_str().unwrap_or(k);
                    MalpediaFamilySummary::new(k, common)
                })
                .collect();
        }
        Vec::new()
    }

    #[must_use]
    pub fn parse_families(json: &serde_json::Value) -> Vec<MalpediaFamily> {
        let Some(obj) = json.as_object() else {
            return Vec::new();
        };
        obj.iter()
            .map(|(name, data)| Self::parse_single_family(name, data))
            .collect()
    }

    fn parse_single_family(name: &str, data: &serde_json::Value) -> MalpediaFamily {
        let mut fam = MalpediaFamily::new(name, data["common_name"].as_str().unwrap_or(name));
        fam.description = data["description"].as_str().unwrap_or("").to_string();
        if let Some(urls) = data["urls"].as_array() {
            fam.urls = urls
                .iter()
                .filter_map(|u| u.as_str().map(str::to_string))
                .collect();
        }
        if let Some(alt_names) = data["alt_names"].as_array() {
            fam.alt_names = alt_names
                .iter()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
        }
        if let Some(actors) = data["actors"].as_array() {
            fam.actors = actors
                .iter()
                .filter_map(|a| a.as_str().map(str::to_string))
                .collect();
        }
        if let Some(samples) = data["samples"].as_array() {
            fam.samples = samples
                .iter()
                .map(|s| MalpediaSample {
                    sha256: s["sha256"].as_str().unwrap_or("").to_string(),
                    status: s["status"].as_str().unwrap_or("").to_string(),
                    version: s["version"].as_str().unwrap_or("").to_string(),
                })
                .collect();
        }
        fam
    }

    fn parse_actors(json: &serde_json::Value) -> Vec<MalpediaActor> {
        let Some(obj) = json.as_object() else {
            return Vec::new();
        };
        obj.iter()
            .map(|(name, data)| Self::parse_single_actor(name, data))
            .collect()
    }

    fn parse_single_actor(name: &str, data: &serde_json::Value) -> MalpediaActor {
        let mut actor = MalpediaActor::new(name, data["country"].as_str().unwrap_or(""));
        actor.description = data["description"].as_str().unwrap_or("").to_string();
        if let Some(families) = data["families"].as_array() {
            actor.families = families
                .iter()
                .filter_map(|f| f.as_str().map(str::to_string))
                .collect();
        }
        actor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_single_family() {
        let data = json!({
            "common_name": "Emotet",
            "description": "Banking trojan",
            "urls": ["https://malpedia.example.com/emotet"],
            "alt_names": ["Heodo"],
            "actors": ["TA542"],
            "samples": [
                {"sha256": "abc123", "status": "active", "version": "5.0"}
            ]
        });
        let fam = MalpediaClient::parse_single_family("win.emotet", &data);
        assert_eq!(fam.common_name, "Emotet");
        assert_eq!(fam.alt_names, vec!["Heodo"]);
        assert_eq!(fam.samples.len(), 1);
        assert!(fam.has_sample("abc123"));
    }

    #[test]
    fn test_parse_single_actor() {
        let data = json!({
            "country": "RU",
            "description": "Russian state actor",
            "families": ["win.apt29_loader"]
        });
        let actor = MalpediaClient::parse_single_actor("APT29", &data);
        assert_eq!(actor.country, "RU");
        assert_eq!(actor.families, vec!["win.apt29_loader"]);
    }

    #[test]
    fn test_parse_families_map() {
        let data = json!({
            "win.emotet": {
                "common_name": "Emotet",
                "description": "",
                "urls": [],
                "alt_names": [],
                "actors": [],
                "samples": []
            },
            "win.trickbot": {
                "common_name": "TrickBot",
                "description": "",
                "urls": [],
                "alt_names": [],
                "actors": [],
                "samples": []
            }
        });
        let families = MalpediaClient::parse_families(&data);
        assert_eq!(families.len(), 2);
    }

    #[test]
    fn test_parse_family_summaries_array() {
        let data = json!(["win.emotet", "win.trickbot", "win.wannacry"]);
        let summaries = MalpediaClient::parse_family_summaries(&data);
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0].malpedia_name, "win.emotet");
    }

    #[test]
    fn test_parse_family_summaries_object() {
        let data = json!({
            "win.emotet": {"common_name": "Emotet"},
            "win.trickbot": {"common_name": "TrickBot"}
        });
        let summaries = MalpediaClient::parse_family_summaries(&data);
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn test_extract_body_ok() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}";
        assert_eq!(MalpediaClient::extract_body(raw).unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn test_extract_body_404() {
        let raw = "HTTP/1.1 404 Not Found\r\n\r\n";
        assert!(matches!(
            MalpediaClient::extract_body(raw),
            Err(MalpediaError::NotFound(_))
        ));
    }

    /// A process-wide mutex that serialises any test that mutates the process
    /// environment.  Holding this guard prevents data races on env vars, which
    /// would otherwise be UB when the test harness runs tests in parallel.
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ENV_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn test_from_env_missing() {
        let _guard = env_test_lock();
        // Ensure MALPEDIA_API_KEY is not set; from_env should return None.
        // SAFETY: protected by env_test_lock — no other thread reads env here.
        unsafe {
            std::env::remove_var("MALPEDIA_API_KEY");
        }
        assert!(MalpediaClient::from_env().is_none());
    }

    #[test]
    fn test_from_env_present() {
        let _guard = env_test_lock();
        // SAFETY: protected by env_test_lock — no other thread reads env here.
        unsafe {
            std::env::set_var("MALPEDIA_API_KEY", "test-key-123");
        }
        let client = MalpediaClient::from_env();
        assert!(client.is_some());
        // SAFETY: protected by env_test_lock — no other thread reads env here.
        unsafe {
            std::env::remove_var("MALPEDIA_API_KEY");
        }
    }

    #[test]
    fn test_mem_cache_family_roundtrip() {
        let mut cache = MemCache::new(Duration::from_secs(60));
        let fam = MalpediaFamily::new("win.emotet", "Emotet");
        cache.put_family(fam);
        let fetched = cache.get_family("win.emotet");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().common_name, "Emotet");
    }

    #[test]
    fn test_mem_cache_actor_roundtrip() {
        let mut cache = MemCache::new(Duration::from_secs(60));
        let actor = MalpediaActor::new("APT28", "RU");
        cache.put_actor(actor);
        let fetched = cache.get_actor("APT28");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().country, "RU");
    }

    #[test]
    fn test_mem_cache_expired() {
        let mut cache = MemCache::new(Duration::from_nanos(1));
        let fam = MalpediaFamily::new("win.emotet", "Emotet");
        cache.put_family(fam);
        // Sleep just enough for the nanosecond TTL to expire.
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.get_family("win.emotet").is_none());
    }

    #[test]
    fn test_mem_cache_families_list() {
        let mut cache = MemCache::new(Duration::from_secs(60));
        let list = vec![
            MalpediaFamilySummary::new("win.emotet", "Emotet"),
            MalpediaFamilySummary::new("win.trickbot", "TrickBot"),
        ];
        cache.put_families_list(list);
        let fetched = cache.get_families_list();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().len(), 2);
    }
}
