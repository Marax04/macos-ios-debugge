//! `session_multiplexer` — N-client → M-server session multiplexing.
//!
//! Provides session affinity, load balancing among equivalent servers, automatic
//! failover, and state synchronisation across the federation layer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// SessionId / ClientId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque session identifier (UUIDv4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifies a downstream client (tool caller).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(Uuid);

impl ClientId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ClientId {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadBalanceAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Algorithm used to select a server for a new session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadBalanceAlgorithm {
    /// Round-robin across all healthy servers.
    RoundRobin,
    /// Least number of active sessions.
    LeastConnections,
    /// Weighted by server capacity (weight from config).
    Weighted,
    /// IP-hash / sticky (based on client-id hash).
    ClientAffinity,
    /// Random selection.
    Random,
}

impl Default for LoadBalanceAlgorithm {
    fn default() -> Self {
        Self::LeastConnections
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerSlot — tracks a server's load
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime slot for a single upstream server.
#[derive(Debug, Clone)]
pub struct ServerSlot {
    pub name: String,
    pub weight: u32,
    pub active_sessions: u32,
    pub total_sessions: u64,
    pub is_healthy: bool,
    pub avg_latency_ms: f64,
}

impl ServerSlot {
    #[must_use]
    pub fn new(name: impl Into<String>, weight: u32) -> Self {
        Self {
            name: name.into(),
            weight,
            active_sessions: 0,
            total_sessions: 0,
            is_healthy: true,
            avg_latency_ms: 0.0,
        }
    }

    /// Effective load score (lower = less loaded).
    #[must_use]
    pub fn load_score(&self) -> f64 {
        if self.weight == 0 {
            f64::MAX
        } else {
            self.active_sessions as f64 / self.weight as f64
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionState
// ─────────────────────────────────────────────────────────────────────────────

/// State of a multiplexed session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Idle,
    Failing,
    Failover { from: String, to: String },
    Closed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Idle => write!(f, "idle"),
            Self::Failing => write!(f, "failing"),
            Self::Failover { from, to } => write!(f, "failover({from}→{to})"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single multiplexed session binding a client to a server.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub id: SessionId,
    pub client_id: ClientId,
    /// Current upstream server assigned to this session.
    pub server_name: String,
    pub state: SessionState,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub call_count: u64,
    pub error_count: u32,
    /// Metadata associated with this session (e.g. binary path, tags).
    pub metadata: HashMap<String, String>,
    /// Previous server (valid during failover).
    pub previous_server: Option<String>,
}

impl SessionEntry {
    #[must_use]
    pub fn new(client_id: ClientId, server_name: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            id: SessionId::new(),
            client_id,
            server_name: server_name.into(),
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            call_count: 0,
            error_count: 0,
            metadata: HashMap::new(),
            previous_server: None,
        }
    }

    /// Record a successful tool call on this session.
    pub fn record_call(&mut self) {
        self.call_count += 1;
        self.last_activity = Instant::now();
        self.state = SessionState::Active;
    }

    /// Record a failed tool call.
    pub fn record_error(&mut self) {
        self.error_count += 1;
        self.last_activity = Instant::now();
        if self.error_count >= 3 {
            self.state = SessionState::Failing;
        }
    }

    /// Mark the session as performing a failover.
    pub fn begin_failover(&mut self, new_server: impl Into<String>) {
        let new = new_server.into();
        self.previous_server = Some(self.server_name.clone());
        self.state = SessionState::Failover {
            from: self.server_name.clone(),
            to: new.clone(),
        };
        self.server_name = new;
        self.error_count = 0;
    }

    /// Complete a failover (transition to Active on the new server).
    pub fn complete_failover(&mut self) {
        self.previous_server = None;
        self.state = SessionState::Active;
    }

    /// Idle duration.
    #[must_use]
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Returns `true` when this session is usable (not closed or failing).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !matches!(self.state, SessionState::Closed | SessionState::Failing)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AffinityMap — maps clients to preferred servers
// ─────────────────────────────────────────────────────────────────────────────

/// Remembers which server a client prefers (session affinity).
pub struct AffinityMap {
    map: DashMap<ClientId, String>,
    ttl: Duration,
    timestamps: DashMap<ClientId, Instant>,
}

impl AffinityMap {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            timestamps: DashMap::new(),
        }
    }

    /// Store or refresh an affinity mapping.
    pub fn set(&self, client: &ClientId, server: impl Into<String>) {
        self.map.insert(client.clone(), server.into());
        self.timestamps.insert(client.clone(), Instant::now());
    }

    /// Look up the affinity for a client.
    #[must_use]
    pub fn get(&self, client: &ClientId) -> Option<String> {
        if let Some(ts) = self.timestamps.get(client) {
            if ts.elapsed() > self.ttl {
                self.map.remove(client);
                self.timestamps.remove(client);
                return None;
            }
        }
        self.map.get(client).map(|s| s.clone())
    }

    /// Remove an affinity entry.
    pub fn remove(&self, client: &ClientId) {
        self.map.remove(client);
        self.timestamps.remove(client);
    }

    /// Evict expired entries.
    pub fn evict_expired(&self) {
        let ttl = self.ttl;
        self.timestamps.retain(|client, ts| {
            let keep = ts.elapsed() <= ttl;
            if !keep {
                self.map.remove(client);
            }
            keep
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionMultiplexer
// ─────────────────────────────────────────────────────────────────────────────

/// Multiplexes N client sessions across M upstream MCP servers.
pub struct SessionMultiplexer {
    /// Active sessions by session ID.
    sessions: DashMap<SessionId, SessionEntry>,
    /// Server slots with load tracking.
    slots: RwLock<HashMap<String, ServerSlot>>,
    /// Client-to-server affinity map.
    affinity: AffinityMap,
    /// Load balancing algorithm.
    algorithm: LoadBalanceAlgorithm,
    /// Round-robin cursor.
    rr_cursor: Mutex<usize>,
    /// Idle timeout for sessions.
    idle_timeout: Duration,
    /// Maximum sessions per server (0 = unlimited).
    max_sessions_per_server: u32,
}

impl SessionMultiplexer {
    #[must_use]
    pub fn new(algorithm: LoadBalanceAlgorithm) -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            slots: RwLock::new(HashMap::new()),
            affinity: AffinityMap::new(Duration::from_secs(3600)),
            algorithm,
            rr_cursor: Mutex::new(0),
            idle_timeout: Duration::from_secs(300),
            max_sessions_per_server: 0,
        })
    }

    // ── Server registration ─────────────────────────────────────────────────

    /// Register an upstream server with the multiplexer.
    pub async fn register_server(&self, name: impl Into<String>, weight: u32) {
        let mut slots = self.slots.write().await;
        let n = name.into();
        slots.entry(n.clone()).or_insert_with(|| ServerSlot::new(n, weight));
    }

    /// Deregister a server; sessions assigned to it will be migrated on next call.
    pub async fn deregister_server(&self, name: &str) {
        self.slots.write().await.remove(name);
        // Mark affected sessions as Failing so they get failed over
        for mut s in self.sessions.iter_mut() {
            if s.server_name == name {
                s.state = SessionState::Failing;
            }
        }
    }

    /// Update a server's health status.
    pub async fn set_server_health(&self, name: &str, healthy: bool) {
        if let Some(slot) = self.slots.write().await.get_mut(name) {
            slot.is_healthy = healthy;
        }
    }

    // ── Session lifecycle ───────────────────────────────────────────────────

    /// Create a new session for a client, selecting the best server.
    pub async fn create_session(
        &self,
        client_id: ClientId,
        tool_hint: Option<&str>,
    ) -> Option<SessionId> {
        let server = self.select_server(&client_id, tool_hint).await?;
        let mut entry = SessionEntry::new(client_id.clone(), &server);
        let session_id = entry.id.clone();
        {
            let mut slots = self.slots.write().await;
            if let Some(slot) = slots.get_mut(&server) {
                slot.active_sessions += 1;
                slot.total_sessions += 1;
            }
        }
        self.affinity.set(&client_id, &server);
        entry.metadata.insert("created_by".into(), "multiplexer".into());
        self.sessions.insert(session_id.clone(), entry);
        Some(session_id)
    }

    /// Close a session and decrement server load.
    pub async fn close_session(&self, id: &SessionId) -> bool {
        if let Some((_, mut entry)) = self.sessions.remove(id) {
            entry.state = SessionState::Closed;
            let mut slots = self.slots.write().await;
            if let Some(slot) = slots.get_mut(&entry.server_name) {
                slot.active_sessions = slot.active_sessions.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    /// Record a successful tool call on a session.
    pub fn record_call(&self, id: &SessionId) {
        if let Some(mut e) = self.sessions.get_mut(id) {
            e.record_call();
        }
    }

    /// Record an error on a session; may trigger failover.
    pub async fn record_error(&self, id: &SessionId) -> Option<String> {
        let needs_failover = {
            if let Some(mut e) = self.sessions.get_mut(id) {
                e.record_error();
                matches!(e.state, SessionState::Failing)
            } else {
                false
            }
        };
        if needs_failover {
            self.failover(id).await
        } else {
            None
        }
    }

    /// Perform a failover for a session to the best available alternative server.
    ///
    /// Returns the new server name on success.
    pub async fn failover(&self, id: &SessionId) -> Option<String> {
        let old_server = self.sessions.get(id)?.server_name.clone();
        // Pick a new server, excluding the failing one
        let new_server = self.select_server_excluding(&old_server).await?;
        if let Some(mut entry) = self.sessions.get_mut(id) {
            // Update slot counts
            {
                let mut slots = self.slots.write().await;
                if let Some(slot) = slots.get_mut(&old_server) {
                    slot.active_sessions = slot.active_sessions.saturating_sub(1);
                }
                if let Some(slot) = slots.get_mut(&new_server) {
                    slot.active_sessions += 1;
                }
            }
            let client = entry.client_id.clone();
            entry.begin_failover(&new_server);
            self.affinity.set(&client, &new_server);
        }
        Some(new_server)
    }

    /// Complete an in-progress failover.
    pub fn complete_failover(&self, id: &SessionId) {
        if let Some(mut e) = self.sessions.get_mut(id) {
            e.complete_failover();
        }
    }

    // ── Lookup ──────────────────────────────────────────────────────────────

    /// Get session entry by ID.
    #[must_use]
    pub fn get_session(&self, id: &SessionId) -> Option<SessionEntry> {
        self.sessions.get(id).map(|e| e.clone())
    }

    /// Get the assigned server for a session.
    #[must_use]
    pub fn server_for_session(&self, id: &SessionId) -> Option<String> {
        self.sessions.get(id).map(|e| e.server_name.clone())
    }

    /// List all active session IDs for a client.
    #[must_use]
    pub fn sessions_for_client(&self, client_id: &ClientId) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|e| &e.value().client_id == client_id)
            .map(|e| e.key().clone())
            .collect()
    }

    // ── Maintenance ─────────────────────────────────────────────────────────

    /// Evict sessions that have been idle longer than `idle_timeout`.
    pub async fn evict_idle_sessions(&self) {
        let idle = self.idle_timeout;
        let stale: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|e| e.value().idle_duration() > idle)
            .map(|e| e.key().clone())
            .collect();
        for id in stale {
            self.close_session(&id).await;
        }
        self.affinity.evict_expired();
    }

    // ── Server selection ────────────────────────────────────────────────────

    async fn select_server(&self, client: &ClientId, _hint: Option<&str>) -> Option<String> {
        // Check affinity first
        if let Some(affinity_server) = self.affinity.get(client) {
            let slots = self.slots.read().await;
            if let Some(slot) = slots.get(&affinity_server) {
                if slot.is_healthy
                    && (self.max_sessions_per_server == 0
                        || slot.active_sessions < self.max_sessions_per_server)
                {
                    return Some(affinity_server);
                }
            }
        }
        self.select_server_by_algorithm().await
    }

    async fn select_server_by_algorithm(&self) -> Option<String> {
        let slots = self.slots.read().await;
        let healthy: Vec<&ServerSlot> = slots.values().filter(|s| s.is_healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        match &self.algorithm {
            LoadBalanceAlgorithm::LeastConnections => {
                healthy
                    .iter()
                    .min_by(|a, b| {
                        a.load_score()
                            .partial_cmp(&b.load_score())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|s| s.name.clone())
            }
            LoadBalanceAlgorithm::RoundRobin => {
                drop(slots);
                let mut cursor = self.rr_cursor.lock().await;
                let slots2 = self.slots.read().await;
                let healthy2: Vec<&ServerSlot> =
                    slots2.values().filter(|s| s.is_healthy).collect();
                if healthy2.is_empty() {
                    return None;
                }
                let idx = *cursor % healthy2.len();
                *cursor = cursor.wrapping_add(1);
                Some(healthy2[idx].name.clone())
            }
            LoadBalanceAlgorithm::Weighted => {
                let total: u32 = healthy.iter().map(|s| s.weight).sum();
                if total == 0 {
                    return healthy.first().map(|s| s.name.clone());
                }
                // Weighted selection using a simple hash of time
                let pick = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
                    % total) as u32;
                let mut acc = 0u32;
                for slot in &healthy {
                    acc += slot.weight;
                    if pick < acc {
                        return Some(slot.name.clone());
                    }
                }
                healthy.last().map(|s| s.name.clone())
            }
            LoadBalanceAlgorithm::ClientAffinity | LoadBalanceAlgorithm::Random => {
                healthy.first().map(|s| s.name.clone())
            }
        }
    }

    async fn select_server_excluding(&self, exclude: &str) -> Option<String> {
        let slots = self.slots.read().await;
        let healthy: Vec<&ServerSlot> = slots
            .values()
            .filter(|s| s.is_healthy && s.name != exclude)
            .collect();
        healthy
            .iter()
            .min_by(|a, b| {
                a.load_score()
                    .partial_cmp(&b.load_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.name.clone())
    }

    // ── Statistics ──────────────────────────────────────────────────────────

    /// Snapshot of current multiplexer stats.
    pub async fn stats(&self) -> MultiplexerStats {
        let slots = self.slots.read().await;
        let total_sessions = self.sessions.len();
        let active = self
            .sessions
            .iter()
            .filter(|e| matches!(e.value().state, SessionState::Active))
            .count();
        let failover_count = self
            .sessions
            .iter()
            .filter(|e| matches!(e.value().state, SessionState::Failover { .. }))
            .count();
        let sessions_per_server: HashMap<String, u32> = slots
            .iter()
            .map(|(k, v)| (k.clone(), v.active_sessions))
            .collect();
        MultiplexerStats {
            total_sessions,
            active_sessions: active,
            failover_count,
            server_count: slots.len(),
            sessions_per_server,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiplexerStats
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot statistics for the multiplexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexerStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub failover_count: usize,
    pub server_count: usize,
    pub sessions_per_server: HashMap<String, u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// StateSyncMessage — for cross-session state sharing
// ─────────────────────────────────────────────────────────────────────────────

/// A message used to synchronise state between sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncMessage {
    pub source_session: String,
    pub target_session: Option<String>, // None = broadcast
    pub key: String,
    pub value: serde_json::Value,
    pub timestamp_ms: u64,
}

impl StateSyncMessage {
    #[must_use]
    pub fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn broadcast(
        source: impl Into<String>,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        Self {
            source_session: source.into(),
            target_session: None,
            key: key.into(),
            value,
            timestamp_ms: Self::now_ms(),
        }
    }

    #[must_use]
    pub fn targeted(
        source: impl Into<String>,
        target: impl Into<String>,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        Self {
            source_session: source.into(),
            target_session: Some(target.into()),
            key: key.into(),
            value,
            timestamp_ms: Self::now_ms(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_mux_with_servers() -> Arc<SessionMultiplexer> {
        let mux = SessionMultiplexer::new(LoadBalanceAlgorithm::LeastConnections);
        mux.register_server("ghidra", 10).await;
        mux.register_server("ida", 10).await;
        mux
    }

    #[tokio::test]
    async fn test_create_and_close_session() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let sid = mux.create_session(client.clone(), None).await.unwrap();
        let s = mux.get_session(&sid).unwrap();
        assert_eq!(s.state, SessionState::Active);
        assert!(mux.close_session(&sid).await);
        assert!(mux.get_session(&sid).is_none());
    }

    #[tokio::test]
    async fn test_sessions_for_client() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let s1 = mux.create_session(client.clone(), None).await.unwrap();
        let s2 = mux.create_session(client.clone(), None).await.unwrap();
        let sessions = mux.sessions_for_client(&client);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&s1));
        assert!(sessions.contains(&s2));
    }

    #[tokio::test]
    async fn test_load_balancing_least_connections() {
        let mux = make_mux_with_servers().await;
        let c1 = ClientId::new();
        let c2 = ClientId::new();
        let s1 = mux.create_session(c1, None).await.unwrap();
        let s2 = mux.create_session(c2, None).await.unwrap();
        let srv1 = mux.server_for_session(&s1).unwrap();
        let srv2 = mux.server_for_session(&s2).unwrap();
        // With two equal servers, the two sessions should go to different ones
        assert_ne!(srv1, srv2);
    }

    #[tokio::test]
    async fn test_affinity_sticky() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let s1 = mux.create_session(client.clone(), None).await.unwrap();
        let srv1 = mux.server_for_session(&s1).unwrap();
        // Second session for same client should stick to same server via affinity
        let s2 = mux.create_session(client.clone(), None).await.unwrap();
        let srv2 = mux.server_for_session(&s2).unwrap();
        assert_eq!(srv1, srv2);
    }

    #[tokio::test]
    async fn test_record_errors_triggers_failing() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let sid = mux.create_session(client, None).await.unwrap();
        for _ in 0..3 {
            mux.record_error(&sid).await;
        }
        let s = mux.get_session(&sid).unwrap();
        assert_eq!(s.state, SessionState::Failing);
    }

    #[tokio::test]
    async fn test_failover_picks_other_server() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let sid = mux.create_session(client, None).await.unwrap();
        let original = mux.server_for_session(&sid).unwrap();
        let new_server = mux.failover(&sid).await.unwrap();
        assert_ne!(original, new_server);
    }

    #[tokio::test]
    async fn test_deregister_server_marks_sessions_failing() {
        let mux = make_mux_with_servers().await;
        let client = ClientId::new();
        let sid = mux.create_session(client, None).await.unwrap();
        let srv = mux.server_for_session(&sid).unwrap();
        mux.deregister_server(&srv).await;
        let s = mux.get_session(&sid).unwrap();
        assert_eq!(s.state, SessionState::Failing);
    }

    #[tokio::test]
    async fn test_stats() {
        let mux = make_mux_with_servers().await;
        let s = mux.stats().await;
        assert_eq!(s.server_count, 2);
        assert_eq!(s.total_sessions, 0);
    }

    #[test]
    fn test_server_slot_load_score() {
        let mut slot = ServerSlot::new("a", 4);
        slot.active_sessions = 8;
        assert!((slot.load_score() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_session_entry_record_call() {
        let mut e = SessionEntry::new(ClientId::new(), "srv");
        e.record_call();
        e.record_call();
        assert_eq!(e.call_count, 2);
    }

    #[test]
    fn test_affinity_map_set_get() {
        let map = AffinityMap::new(Duration::from_secs(60));
        let c = ClientId::new();
        map.set(&c, "ghidra");
        assert_eq!(map.get(&c), Some("ghidra".to_string()));
    }

    #[test]
    fn test_affinity_map_ttl_expired() {
        let map = AffinityMap::new(Duration::from_nanos(1));
        let c = ClientId::new();
        map.set(&c, "srv");
        std::thread::sleep(Duration::from_millis(5));
        assert!(map.get(&c).is_none());
    }

    #[test]
    fn test_state_sync_broadcast() {
        let msg = StateSyncMessage::broadcast("s1", "analysis.symbols", serde_json::json!([]));
        assert!(msg.target_session.is_none());
        assert_eq!(msg.key, "analysis.symbols");
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new();
        assert!(!id.to_string().is_empty());
    }
}
