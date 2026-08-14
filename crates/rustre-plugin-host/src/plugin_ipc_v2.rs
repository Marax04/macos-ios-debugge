//! Plugin IPC — in-process message-passing between host and plugin.
//!
//! Provides `IpcMessage`, `IpcChannel`, `MessageQueue`, `FramedMessage`,
//! and `IpcSerializer` for reliable framed message exchange.

use std::collections::VecDeque;

// ── IpcMsgType ────────────────────────────────────────────────────────────────

/// Type tag for an IPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcMsgType {
    Request,
    Response,
    Event,
    Heartbeat,
    Shutdown,
}

impl IpcMsgType {
    pub fn as_u8(&self) -> u8 {
        match self {
            IpcMsgType::Request   => 0,
            IpcMsgType::Response  => 1,
            IpcMsgType::Event     => 2,
            IpcMsgType::Heartbeat => 3,
            IpcMsgType::Shutdown  => 4,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(IpcMsgType::Request),
            1 => Some(IpcMsgType::Response),
            2 => Some(IpcMsgType::Event),
            3 => Some(IpcMsgType::Heartbeat),
            4 => Some(IpcMsgType::Shutdown),
            _ => None,
        }
    }
}

// ── IpcPayload ────────────────────────────────────────────────────────────────

/// The payload carried in an IPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcPayload {
    Empty,
    Json(String),
    Binary(Vec<u8>),
    Error { code: u32, message: String },
}

impl IpcPayload {
    /// Serialise payload to bytes for framing.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            IpcPayload::Empty => vec![0x00],
            IpcPayload::Json(s) => {
                let mut v = vec![0x01];
                v.extend_from_slice(s.as_bytes());
                v
            }
            IpcPayload::Binary(b) => {
                let mut v = vec![0x02];
                v.extend_from_slice(b);
                v
            }
            IpcPayload::Error { code, message } => {
                let mut v = vec![0x03];
                v.extend_from_slice(&code.to_le_bytes());
                v.extend_from_slice(message.as_bytes());
                v
            }
        }
    }

    /// Deserialise payload from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let tag = *bytes.first()?;
        let rest = &bytes[1..];
        match tag {
            0x00 => Some(IpcPayload::Empty),
            0x01 => {
                let s = std::str::from_utf8(rest).ok()?.to_string();
                Some(IpcPayload::Json(s))
            }
            0x02 => Some(IpcPayload::Binary(rest.to_vec())),
            0x03 => {
                if rest.len() < 4 { return None; }
                let code = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
                let message = std::str::from_utf8(&rest[4..]).ok()?.to_string();
                Some(IpcPayload::Error { code, message })
            }
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool { matches!(self, IpcPayload::Empty) }
    pub fn is_error(&self) -> bool { matches!(self, IpcPayload::Error { .. }) }
}

// ── IpcMessage ────────────────────────────────────────────────────────────────

/// A complete IPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcMessage {
    /// Monotonically increasing message ID.
    pub id: u64,
    pub msg_type: IpcMsgType,
    pub payload: IpcPayload,
}

impl IpcMessage {
    pub fn new(id: u64, msg_type: IpcMsgType, payload: IpcPayload) -> Self {
        Self { id, msg_type, payload }
    }

    pub fn request(id: u64, payload: IpcPayload) -> Self {
        Self::new(id, IpcMsgType::Request, payload)
    }

    pub fn response(id: u64, payload: IpcPayload) -> Self {
        Self::new(id, IpcMsgType::Response, payload)
    }

    pub fn heartbeat(id: u64) -> Self {
        Self::new(id, IpcMsgType::Heartbeat, IpcPayload::Empty)
    }

    pub fn shutdown(id: u64) -> Self {
        Self::new(id, IpcMsgType::Shutdown, IpcPayload::Empty)
    }

    pub fn event(id: u64, payload: IpcPayload) -> Self {
        Self::new(id, IpcMsgType::Event, payload)
    }

    pub fn is_shutdown(&self) -> bool { self.msg_type == IpcMsgType::Shutdown }
    pub fn is_heartbeat(&self) -> bool { self.msg_type == IpcMsgType::Heartbeat }
}

// ── MessageQueue ──────────────────────────────────────────────────────────────

/// A bounded FIFO queue of `IpcMessage` values.
pub struct MessageQueue {
    messages: VecDeque<IpcMessage>,
    pub max_size: usize,
    dropped: u64,
}

impl MessageQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            messages: VecDeque::with_capacity(max_size.min(256)),
            max_size,
            dropped: 0,
        }
    }

    /// Enqueue a message.  Returns `false` and increments `dropped` if full.
    pub fn enqueue(&mut self, msg: IpcMessage) -> bool {
        if self.messages.len() >= self.max_size {
            self.dropped += 1;
            return false;
        }
        self.messages.push_back(msg);
        true
    }

    /// Dequeue the next message, or `None` if empty.
    pub fn dequeue(&mut self) -> Option<IpcMessage> {
        self.messages.pop_front()
    }

    pub fn len(&self) -> usize { self.messages.len() }
    pub fn is_empty(&self) -> bool { self.messages.is_empty() }
    pub fn is_full(&self) -> bool { self.messages.len() >= self.max_size }
    pub fn dropped(&self) -> u64 { self.dropped }

    /// Drain all messages into a Vec.
    pub fn drain_all(&mut self) -> Vec<IpcMessage> {
        self.messages.drain(..).collect()
    }

    /// Peek at the front message without removing it.
    pub fn peek(&self) -> Option<&IpcMessage> {
        self.messages.front()
    }
}

// ── IpcChannel ────────────────────────────────────────────────────────────────

/// A bidirectional in-process IPC channel.
pub struct IpcChannel {
    tx: VecDeque<IpcMessage>,
    rx: VecDeque<IpcMessage>,
    pub connected: bool,
    next_id: u64,
}

impl IpcChannel {
    pub fn new() -> Self {
        Self {
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            connected: true,
            next_id: 1,
        }
    }

    /// Send a message (places it in the TX queue).
    pub fn send(&mut self, msg: IpcMessage) -> bool {
        if !self.connected { return false; }
        self.tx.push_back(msg);
        true
    }

    /// Receive the next message from the RX queue.
    pub fn recv(&mut self) -> Option<IpcMessage> {
        if !self.connected { return None; }
        self.rx.pop_front()
    }

    /// Deliver messages from TX into another channel's RX (simulate transport).
    pub fn flush_to(&mut self, other: &mut IpcChannel) {
        while let Some(msg) = self.tx.pop_front() {
            other.rx.push_back(msg);
        }
    }

    /// Allocate the next message ID.
    pub fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn disconnect(&mut self) { self.connected = false; }
    pub fn tx_pending(&self) -> usize { self.tx.len() }
    pub fn rx_pending(&self) -> usize { self.rx.len() }
}

impl Default for IpcChannel { fn default() -> Self { Self::new() } }

// ── FramedMessage ─────────────────────────────────────────────────────────────

/// A length-prefixed, checksummed frame for wire-format IPC.
///
/// Wire format: `[length:u32][checksum:u32][data...]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedMessage {
    pub length: u32,
    pub checksum: u32,
    pub data: Vec<u8>,
}

impl FramedMessage {
    /// Compute a simple Adler-32 checksum over `data`.
    pub fn adler32(data: &[u8]) -> u32 {
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in data {
            a = (a + byte as u32) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    /// Create a frame from raw data bytes.
    ///
    /// # Panics
    /// Panics if `data` is larger than `u32::MAX` bytes (> 4 GiB), which is not
    /// a realistic IPC payload size.
    pub fn from_data(data: Vec<u8>) -> Self {
        let length = u32::try_from(data.len())
            .expect("FramedMessage data must not exceed u32::MAX bytes");
        let checksum = Self::adler32(&data);
        Self { length, checksum, data }
    }

    /// Verify that the checksum matches the data.
    pub fn verify(&self) -> bool {
        Self::adler32(&self.data) == self.checksum && self.data.len() == self.length as usize
    }

    /// Serialise the frame to bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.checksum.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialise a frame from a byte slice.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 { return None; }
        let length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let checksum = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data = bytes[8..].to_vec();
        if data.len() != length as usize { return None; }
        Some(Self { length, checksum, data })
    }
}

// ── IpcSerializer ─────────────────────────────────────────────────────────────

/// Serializes and deserialises `IpcMessage` values to/from `FramedMessage`.
pub struct IpcSerializer;

impl IpcSerializer {
    /// Serialise an `IpcMessage` to a framed byte sequence.
    ///
    /// Wire layout inside the frame data:
    /// `[id:u64][type:u8][payload...]`
    pub fn serialize_message(msg: &IpcMessage) -> FramedMessage {
        let mut data = Vec::new();
        data.extend_from_slice(&msg.id.to_le_bytes());
        data.push(msg.msg_type.as_u8());
        data.extend_from_slice(&msg.payload.to_bytes());
        FramedMessage::from_data(data)
    }

    /// Deserialise an `IpcMessage` from a `FramedMessage`.
    pub fn deserialize_message(frame: &FramedMessage) -> Option<IpcMessage> {
        if !frame.verify() { return None; }
        let data = &frame.data;
        if data.len() < 9 { return None; }
        let id = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let msg_type = IpcMsgType::from_u8(data[8])?;
        let payload = IpcPayload::from_bytes(&data[9..])?;
        Some(IpcMessage::new(id, msg_type, payload))
    }

    /// Round-trip encode then decode an `IpcMessage`.
    pub fn roundtrip(msg: &IpcMessage) -> Option<IpcMessage> {
        let frame = Self::serialize_message(msg);
        Self::deserialize_message(&frame)
    }
}

// ── PluginIpc ─────────────────────────────────────────────────────────────────

/// High-level IPC manager for a plugin/host pair.
pub struct PluginIpc {
    pub host_channel: IpcChannel,
    pub plugin_channel: IpcChannel,
    pub serializer: IpcSerializer,
}

impl PluginIpc {
    pub fn new() -> Self {
        Self {
            host_channel: IpcChannel::new(),
            plugin_channel: IpcChannel::new(),
            serializer: IpcSerializer,
        }
    }

    /// Send a message from host to plugin.
    pub fn host_send(&mut self, msg: IpcMessage) -> bool {
        self.host_channel.send(msg)
    }

    /// Receive a message on the plugin side.
    pub fn plugin_recv(&mut self) -> Option<IpcMessage> {
        self.host_channel.flush_to(&mut self.plugin_channel);
        self.plugin_channel.recv()
    }

    /// Send a message from plugin to host.
    pub fn plugin_send(&mut self, msg: IpcMessage) -> bool {
        self.plugin_channel.send(msg)
    }

    /// Receive a message on the host side.
    pub fn host_recv(&mut self) -> Option<IpcMessage> {
        self.plugin_channel.flush_to(&mut self.host_channel);
        self.host_channel.recv()
    }

    /// Disconnect both channels.
    pub fn shutdown(&mut self) {
        self.host_channel.disconnect();
        self.plugin_channel.disconnect();
    }
}

impl Default for PluginIpc { fn default() -> Self { Self::new() } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_msg_type_roundtrip() {
        for t in [
            IpcMsgType::Request,
            IpcMsgType::Response,
            IpcMsgType::Event,
            IpcMsgType::Heartbeat,
            IpcMsgType::Shutdown,
        ] {
            assert_eq!(IpcMsgType::from_u8(t.as_u8()), Some(t));
        }
    }

    #[test]
    fn payload_empty_roundtrip() {
        let p = IpcPayload::Empty;
        let bytes = p.to_bytes();
        assert_eq!(IpcPayload::from_bytes(&bytes), Some(IpcPayload::Empty));
    }

    #[test]
    fn payload_json_roundtrip() {
        let p = IpcPayload::Json(r#"{"key":"value"}"#.to_string());
        let bytes = p.to_bytes();
        assert_eq!(IpcPayload::from_bytes(&bytes), Some(p));
    }

    #[test]
    fn payload_binary_roundtrip() {
        let p = IpcPayload::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = p.to_bytes();
        assert_eq!(IpcPayload::from_bytes(&bytes), Some(p));
    }

    #[test]
    fn payload_error_roundtrip() {
        let p = IpcPayload::Error { code: 404, message: "not found".to_string() };
        let bytes = p.to_bytes();
        assert_eq!(IpcPayload::from_bytes(&bytes), Some(p));
    }

    #[test]
    fn message_queue_enqueue_dequeue() {
        let mut q = MessageQueue::new(4);
        q.enqueue(IpcMessage::heartbeat(1));
        q.enqueue(IpcMessage::heartbeat(2));
        assert_eq!(q.len(), 2);
        let m = q.dequeue().unwrap();
        assert_eq!(m.id, 1);
    }

    #[test]
    fn message_queue_overflow_drops() {
        let mut q = MessageQueue::new(2);
        assert!(q.enqueue(IpcMessage::heartbeat(1)));
        assert!(q.enqueue(IpcMessage::heartbeat(2)));
        assert!(!q.enqueue(IpcMessage::heartbeat(3)));
        assert_eq!(q.dropped(), 1);
    }

    #[test]
    fn ipc_channel_send_recv() {
        let mut host = IpcChannel::new();
        let mut plugin = IpcChannel::new();
        host.send(IpcMessage::request(1, IpcPayload::Empty));
        host.flush_to(&mut plugin);
        let msg = plugin.recv().unwrap();
        assert_eq!(msg.id, 1);
        assert_eq!(msg.msg_type, IpcMsgType::Request);
    }

    #[test]
    fn ipc_channel_disconnected_send_fails() {
        let mut ch = IpcChannel::new();
        ch.disconnect();
        assert!(!ch.send(IpcMessage::heartbeat(1)));
    }

    #[test]
    fn framed_message_roundtrip() {
        let data = b"hello IPC".to_vec();
        let frame = FramedMessage::from_data(data.clone());
        assert!(frame.verify());
        let wire = frame.to_wire();
        let decoded = FramedMessage::from_wire(&wire).unwrap();
        assert_eq!(decoded.data, data);
        assert!(decoded.verify());
    }

    #[test]
    fn framed_message_corrupt_checksum() {
        let data = b"test".to_vec();
        let mut frame = FramedMessage::from_data(data);
        frame.checksum ^= 0xFFFF; // corrupt
        assert!(!frame.verify());
    }

    #[test]
    fn serializer_roundtrip_request() {
        let msg = IpcMessage::request(42, IpcPayload::Json(r#"{"a":1}"#.to_string()));
        let decoded = IpcSerializer::roundtrip(&msg).unwrap();
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.msg_type, IpcMsgType::Request);
        assert_eq!(decoded.payload, IpcPayload::Json(r#"{"a":1}"#.to_string()));
    }

    #[test]
    fn serializer_roundtrip_shutdown() {
        let msg = IpcMessage::shutdown(99);
        let decoded = IpcSerializer::roundtrip(&msg).unwrap();
        assert!(decoded.is_shutdown());
    }

    #[test]
    fn plugin_ipc_host_to_plugin() {
        let mut ipc = PluginIpc::new();
        ipc.host_send(IpcMessage::request(1, IpcPayload::Empty));
        let msg = ipc.plugin_recv().unwrap();
        assert_eq!(msg.id, 1);
    }

    #[test]
    fn plugin_ipc_plugin_to_host() {
        let mut ipc = PluginIpc::new();
        ipc.plugin_send(IpcMessage::response(2, IpcPayload::Empty));
        let msg = ipc.host_recv().unwrap();
        assert_eq!(msg.id, 2);
        assert_eq!(msg.msg_type, IpcMsgType::Response);
    }

    #[test]
    fn adler32_deterministic() {
        let a = FramedMessage::adler32(b"hello");
        let b2 = FramedMessage::adler32(b"hello");
        assert_eq!(a, b2);
        assert_ne!(a, FramedMessage::adler32(b"world"));
    }
}
