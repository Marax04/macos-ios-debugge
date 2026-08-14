//! Plugin IPC: message-passing between the plugin host and sandboxed plugins.
//!
//! Defines [`PluginMessage`], [`PluginChannel`], [`IpcSerializer`], and
//! [`ChannelStats`] for a minimal, synchronous IPC layer.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// PluginMessage
// ─────────────────────────────────────────────────────────────────────────────

/// A message that can be sent between host and plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginMessage {
    Ping {
        seq: u64,
    },
    Pong {
        seq: u64,
    },
    Initialize {
        config: HashMap<String, String>,
    },
    Shutdown,
    AnalyzeRequest {
        address: u64,
        data: Vec<u8>,
        context: HashMap<String, String>,
    },
    AnalyzeResponse {
        address: u64,
        result: AnalysisResult,
    },
    BinaryViewUpdate {
        view_id: u64,
        name: String,
    },
    Log {
        level: LogLevel,
        message: String,
    },
    Error {
        code: u32,
        message: String,
    },
    Event {
        name: String,
        payload: Vec<u8>,
    },
    Call {
        method: String,
        args: Vec<u8>,
    },
    Return {
        method: String,
        result: Vec<u8>,
        error: Option<String>,
    },
}

impl PluginMessage {
    /// Returns a short descriptive tag for this message variant.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
            Self::Pong { .. } => "pong",
            Self::Initialize { .. } => "initialize",
            Self::Shutdown => "shutdown",
            Self::AnalyzeRequest { .. } => "analyze_request",
            Self::AnalyzeResponse { .. } => "analyze_response",
            Self::BinaryViewUpdate { .. } => "binary_view_update",
            Self::Log { .. } => "log",
            Self::Error { .. } => "error",
            Self::Event { .. } => "event",
            Self::Call { .. } => "call",
            Self::Return { .. } => "return",
        }
    }

    /// Whether this message type expects a response.
    #[must_use]
    pub const fn expects_response(&self) -> bool {
        matches!(
            self,
            Self::Ping { .. }
                | Self::AnalyzeRequest { .. }
                | Self::Call { .. }
                | Self::Initialize { .. }
        )
    }

    /// Sequence number if applicable.
    #[must_use]
    pub const fn seq(&self) -> Option<u64> {
        match self {
            Self::Ping { seq } | Self::Pong { seq } => Some(*seq),
            _ => None,
        }
    }
}

impl fmt::Display for PluginMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ping { seq } => write!(f, "Ping({seq})"),
            Self::Pong { seq } => write!(f, "Pong({seq})"),
            Self::Log { level, message } => write!(f, "Log[{level}]: {message}"),
            Self::Error { code, message } => write!(f, "Error({code}): {message}"),
            other => write!(f, "Message({})", other.tag()),
        }
    }
}

/// Log level for plugin log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        };
        f.write_str(s)
    }
}

/// Result returned by a plugin after analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub success: bool,
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
}

/// A single finding produced by a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub address: u64,
    pub description: String,
    pub severity: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// IpcSerializer
// ─────────────────────────────────────────────────────────────────────────────

/// Serializes and deserializes [`PluginMessage`]s to/from bytes.
pub struct IpcSerializer;

impl IpcSerializer {
    /// Serialize.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn serialize(msg: &PluginMessage) -> Result<Vec<u8>, String> {
        serde_json::to_vec(msg).map_err(|e| e.to_string())
    }

    /// Deserialize.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn deserialize(data: &[u8]) -> Result<PluginMessage, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    /// Frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn frame(msg: &PluginMessage) -> Result<Vec<u8>, String> {
        let payload = Self::serialize(msg)?;
        let len = u32::try_from(payload.len())
            .map_err(|_| "serialized message too large to frame (> 4 GiB)".to_string())?;
        let mut frame = len.to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Unframe.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Decode a length-prefixed frame, returning the message and bytes consumed.
    pub fn unframe(data: &[u8]) -> Result<(PluginMessage, usize), String> {
        if data.len() < 4 {
            return Err("frame too short".into());
        }
        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(format!(
                "incomplete frame: need {} got {}",
                4 + len,
                data.len()
            ));
        }
        let msg = Self::deserialize(&data[4..4 + len])?;
        Ok((msg, 4 + len))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelStats
// ─────────────────────────────────────────────────────────────────────────────

/// Cumulative statistics for a [`PluginChannel`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    pub ping_count: u64,
    pub pong_count: u64,
    /// Total round-trip time accumulated across completed ping/pong pairs (microseconds).
    pub total_rtt_micros: u64,
}

impl ChannelStats {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    #[must_use]
    pub const fn total_messages(&self) -> u64 {
        self.messages_sent + self.messages_received
    }

    /// Record a completed ping/pong round trip.
    pub fn record_rtt(&mut self, rtt: Duration) {
        let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
        self.total_rtt_micros = self.total_rtt_micros.saturating_add(micros);
    }

    /// Average ping/pong round-trip time, or zero if no pongs have been observed.
    #[must_use]
    pub const fn average_rtt(&self) -> Duration {
        if self.pong_count == 0 {
            Duration::ZERO
        } else {
            Duration::from_micros(self.total_rtt_micros / self.pong_count)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginChannel
// ─────────────────────────────────────────────────────────────────────────────

/// A bidirectional in-process channel for host↔plugin communication.
///
/// In production this would wrap a Unix socket, named pipe, or shared-memory
/// ring buffer. Here it uses in-memory queues for testing.
pub struct PluginChannel {
    pub plugin_id: String,
    host_to_plugin: VecDeque<PluginMessage>,
    plugin_to_host: VecDeque<PluginMessage>,
    /// Channel statistics.
    pub stats: ChannelStats,
    seq: u64,
    /// Whether the channel is open.
    pub open: bool,
    /// Maximum queue depth (0 = unbounded).
    pub max_queue_depth: usize,
    pending_acks: HashMap<u64, Instant>,
}

/// Returns an error if the underlying operation fails.
impl PluginChannel {
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            host_to_plugin: VecDeque::new(),
            plugin_to_host: VecDeque::new(),
            stats: ChannelStats::default(),
            seq: 0,
            open: true,
            max_queue_depth: 0,
            pending_acks: HashMap::new(),
        }
    }

    /// Host send.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Send a message from host to plugin.
    pub fn host_send(&mut self, msg: PluginMessage) -> Result<(), String> {
        if !self.open {
            return Err("channel closed".into());
        }
        if self.max_queue_depth > 0 && self.host_to_plugin.len() >= self.max_queue_depth {
            self.stats.errors += 1;
            return Err("host→plugin queue full".into());
        }
        if let Ok(bytes) = IpcSerializer::serialize(&msg) {
            self.stats.bytes_sent += bytes.len() as u64;
        }
        self.stats.messages_sent += 1;
        if matches!(msg, PluginMessage::Ping { .. }) {
            self.stats.ping_count += 1;
        }
        self.host_to_plugin.push_back(msg);
        Ok(())
    }

    /// Plugin receives a message from the host.
    pub fn plugin_recv(&mut self) -> Option<PluginMessage> {
        let msg = self.host_to_plugin.pop_front()?;
        self.stats.messages_received += 1;
        Some(msg)
    }

    /// Plugin send.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Plugin sends a message to the host.
    pub fn plugin_send(&mut self, msg: PluginMessage) -> Result<(), String> {
        if !self.open {
            return Err("channel closed".into());
        }
        if self.max_queue_depth > 0 && self.plugin_to_host.len() >= self.max_queue_depth {
            self.stats.errors += 1;
            return Err("plugin→host queue full".into());
        }
        if let Ok(bytes) = IpcSerializer::serialize(&msg) {
            self.stats.bytes_sent += bytes.len() as u64;
        }
        self.stats.messages_sent += 1;
        if matches!(msg, PluginMessage::Pong { .. }) {
            self.stats.pong_count += 1;
        }
        self.plugin_to_host.push_back(msg);
        Ok(())
    }

    /// Host receives a message from the plugin.
    pub fn host_recv(&mut self) -> Option<PluginMessage> {
        let msg = self.plugin_to_host.pop_front()?;
        self.stats.messages_received += 1;
        if let PluginMessage::Pong { seq } = &msg {
            if let Some(sent_at) = self.pending_acks.remove(seq) {
                self.stats.record_rtt(sent_at.elapsed());
            }
        }
        Some(msg)
    }

    /// Ping.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Send a Ping from host and record the sequence number.
    pub fn ping(&mut self) -> Result<u64, String> {
        self.seq += 1;
        let seq = self.seq;
        self.pending_acks.insert(seq, Instant::now());
        self.host_send(PluginMessage::Ping { seq })?;
        Ok(seq)
    }

    /// Respond to all pending Pings with Pong (simulates plugin processing).
    pub fn process_pings(&mut self) {
        let mut pings = Vec::new();
        while let Some(msg) = self.plugin_recv() {
            if let PluginMessage::Ping { seq } = msg {
                pings.push(seq);
            }
        }
        for seq in pings {
            self.plugin_send(PluginMessage::Pong { seq }).ok();
        }
    }

    /// Drain all responses from the plugin queue.
    pub fn drain_responses(&mut self) -> Vec<PluginMessage> {
        let mut msgs = Vec::new();
        while let Some(m) = self.host_recv() {
            msgs.push(m);
        }
        msgs
    }

    /// Number of messages waiting for the plugin.
    #[must_use]
    pub fn pending_for_plugin(&self) -> usize {
        self.host_to_plugin.len()
    }

    /// Number of messages waiting for the host.
    #[must_use]
    pub fn pending_for_host(&self) -> usize {
        self.plugin_to_host.len()
    }

    /// Close the channel.
    pub const fn close(&mut self) {
        self.open = false;
    }

    /// Reset queue and stats.
    pub fn reset(&mut self) {
        self.host_to_plugin.clear();
        self.plugin_to_host.clear();
        self.stats.reset();
        self.pending_acks.clear();
    }
}

impl fmt::Debug for PluginChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginChannel")
            .field("plugin_id", &self.plugin_id)
            .field("open", &self.open)
            .field("pending_for_plugin", &self.host_to_plugin.len())
            .field("pending_for_host", &self.plugin_to_host.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages multiple [`PluginChannel`]s, one per loaded plugin.
#[derive(Default)]
pub struct ChannelManager {
    channels: HashMap<String, PluginChannel>,
}

impl ChannelManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self, plugin_id: impl Into<String>) {
        let id = plugin_id.into();
        self.channels.insert(id.clone(), PluginChannel::new(id));
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&PluginChannel> {
        self.channels.get(id)
    }
    pub fn get_mut(&mut self, id: &str) -> Option<&mut PluginChannel> {
        self.channels.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) {
        self.channels.remove(id);
    }

    pub fn plugin_ids(&self) -> Vec<&str> {
        self.channels.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.channels.len()
    }

    /// Broadcast a message to all open plugin channels.
    pub fn broadcast(&mut self, msg: PluginMessage) -> usize {
        let mut sent = 0;
        for ch in self.channels.values_mut() {
            if ch.open && ch.host_send(msg.clone()).is_ok() {
                sent += 1;
            }
        }
        sent
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- PluginMessage ---

    #[test]
    fn message_tag_ping() {
        assert_eq!(PluginMessage::Ping { seq: 1 }.tag(), "ping");
    }

    #[test]
    fn message_tag_shutdown() {
        assert_eq!(PluginMessage::Shutdown.tag(), "shutdown");
    }

    #[test]
    fn message_expects_response_ping() {
        assert!(PluginMessage::Ping { seq: 0 }.expects_response());
    }

    #[test]
    fn message_expects_response_shutdown_false() {
        assert!(!PluginMessage::Shutdown.expects_response());
    }

    #[test]
    fn message_seq_ping() {
        assert_eq!(PluginMessage::Ping { seq: 42 }.seq(), Some(42));
    }

    #[test]
    fn message_seq_other_none() {
        assert_eq!(PluginMessage::Shutdown.seq(), None);
    }

    #[test]
    fn message_display_ping() {
        let s = format!("{}", PluginMessage::Ping { seq: 7 });
        assert!(s.contains('7'));
    }

    // --- IpcSerializer ---

    #[test]
    fn serializer_roundtrip_ping() {
        let msg = PluginMessage::Ping { seq: 99 };
        let bytes = IpcSerializer::serialize(&msg).unwrap();
        let decoded = IpcSerializer::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serializer_roundtrip_log() {
        let msg = PluginMessage::Log {
            level: LogLevel::Info,
            message: "hello".into(),
        };
        let bytes = IpcSerializer::serialize(&msg).unwrap();
        let decoded = IpcSerializer::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serializer_frame_unframe() {
        let msg = PluginMessage::Pong { seq: 5 };
        let frame = IpcSerializer::frame(&msg).unwrap();
        let (decoded, n) = IpcSerializer::unframe(&frame).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(n, frame.len());
    }

    #[test]
    fn serializer_unframe_too_short() {
        assert!(IpcSerializer::unframe(&[0, 0]).is_err());
    }

    #[test]
    fn serializer_unframe_incomplete() {
        // Frame says 100 bytes payload but we only give 10
        let mut frame = 100u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 10]);
        assert!(IpcSerializer::unframe(&frame).is_err());
    }

    // --- ChannelStats ---

    #[test]
    fn stats_total_messages() {
        let s = ChannelStats {
            messages_sent: 3,
            messages_received: 2,
            ..Default::default()
        };
        assert_eq!(s.total_messages(), 5);
    }

    #[test]
    fn stats_reset() {
        let mut s = ChannelStats {
            messages_sent: 10,
            ..Default::default()
        };
        s.reset();
        assert_eq!(s.messages_sent, 0);
    }

    // --- PluginChannel ---

    #[test]
    fn channel_host_send_plugin_recv() {
        let mut ch = PluginChannel::new("test");
        ch.host_send(PluginMessage::Ping { seq: 1 }).unwrap();
        let msg = ch.plugin_recv().unwrap();
        assert_eq!(msg, PluginMessage::Ping { seq: 1 });
    }

    #[test]
    fn channel_plugin_send_host_recv() {
        let mut ch = PluginChannel::new("test");
        ch.plugin_send(PluginMessage::Pong { seq: 1 }).unwrap();
        let msg = ch.host_recv().unwrap();
        assert_eq!(msg, PluginMessage::Pong { seq: 1 });
    }

    #[test]
    fn channel_closed_send_fails() {
        let mut ch = PluginChannel::new("test");
        ch.close();
        assert!(ch.host_send(PluginMessage::Shutdown).is_err());
    }

    #[test]
    fn channel_ping_process_pong() {
        let mut ch = PluginChannel::new("test");
        ch.ping().unwrap();
        ch.process_pings();
        let responses = ch.drain_responses();
        assert_eq!(responses.len(), 1);
        assert!(matches!(responses[0], PluginMessage::Pong { seq: 1 }));
    }

    #[test]
    fn channel_stats_messages_sent() {
        let mut ch = PluginChannel::new("test");
        ch.host_send(PluginMessage::Shutdown).unwrap();
        assert_eq!(ch.stats.messages_sent, 1);
    }

    #[test]
    fn channel_pending_for_plugin() {
        let mut ch = PluginChannel::new("test");
        ch.host_send(PluginMessage::Shutdown).unwrap();
        assert_eq!(ch.pending_for_plugin(), 1);
    }

    #[test]
    fn channel_reset_clears_queues() {
        let mut ch = PluginChannel::new("test");
        ch.host_send(PluginMessage::Shutdown).unwrap();
        ch.reset();
        assert_eq!(ch.pending_for_plugin(), 0);
    }

    #[test]
    fn channel_max_queue_depth_enforced() {
        let mut ch = PluginChannel::new("test");
        ch.max_queue_depth = 2;
        ch.host_send(PluginMessage::Shutdown).unwrap();
        ch.host_send(PluginMessage::Shutdown).unwrap();
        assert!(ch.host_send(PluginMessage::Shutdown).is_err());
    }

    // --- ChannelManager ---

    #[test]
    fn channel_manager_create_get() {
        let mut mgr = ChannelManager::new();
        mgr.create("plugin_a");
        assert!(mgr.get("plugin_a").is_some());
    }

    #[test]
    fn channel_manager_remove() {
        let mut mgr = ChannelManager::new();
        mgr.create("plugin_b");
        mgr.remove("plugin_b");
        assert!(mgr.get("plugin_b").is_none());
    }

    #[test]
    fn channel_manager_count() {
        let mut mgr = ChannelManager::new();
        mgr.create("a");
        mgr.create("b");
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn channel_manager_broadcast() {
        let mut mgr = ChannelManager::new();
        mgr.create("x");
        mgr.create("y");
        let sent = mgr.broadcast(PluginMessage::Shutdown);
        assert_eq!(sent, 2);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(format!("{}", LogLevel::Warn), "WARN");
    }
}
