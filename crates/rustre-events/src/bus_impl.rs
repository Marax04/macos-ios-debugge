// bus_impl.rs — Full event bus implementation
// Part of rustre-events crate.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// Cast helpers: deliberate precision-loss boundaries. Isolating these in
// module-private fns keeps the lossy-cast lint from firing at call sites.
#[inline]
const fn cast_usize_to_f64(v: usize) -> f64 { v as f64 }
#[inline]
const fn cast_u64_to_f64(v: u64) -> f64 { v as f64 }

// ── BusCoreEvent: the discriminated union of all bus events ─────────────────────

/// All event variants that flow through the synchronous spin-poll bus.
///
/// This is the event type for [`BusImplEventBus`].  For the async tokio-broadcast
/// platform bus see [`crate::CoreEvent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum BusCoreEvent {
    // — Breakpoint events —
    BreakpointHit(BreakpointHit),
    BreakpointAdded(BreakpointAdded),
    BreakpointRemoved(BreakpointRemoved),

    // — Analysis events —
    AnalysisStarted(AnalysisStarted),
    AnalysisProgress(AnalysisProgress),
    AnalysisCompleted(AnalysisCompleted),
    AnalysisFailed(AnalysisFailed),

    // — Symbol events —
    SymbolAdded(SymbolAdded),
    SymbolRenamed(SymbolRenamed),
    SymbolRemoved(SymbolRemoved),

    // — Function events —
    FunctionDecompiled(FunctionDecompiled),
    FunctionAnnotated(FunctionAnnotated),

    // — Type events —
    TypeDefined(TypeDefined),
    TypeRemoved(TypeRemoved),

    // — Binary/session events —
    BinaryLoaded(BinaryLoaded),
    BinaryUnloaded(BinaryUnloaded),
    SessionOpened(SessionOpened),
    SessionClosed(SessionClosed),

    // — UI navigation events —
    NavigateTo(NavigateTo),
    ViewFocused(ViewFocused),

    // — Comment events —
    CommentSet(CommentSet),

    // — Tag events —
    TagAdded(TagAdded),
    TagRemoved(TagRemoved),

    // — Generic / extensibility —
    Custom(CustomEvent),
}

impl BusCoreEvent {
    /// The timestamp embedded in this event (milliseconds since UNIX epoch).
    #[must_use] 
    pub const fn timestamp_ms(&self) -> u64 {
        match self {
            Self::BreakpointHit(e) => e.timestamp_ms,
            Self::BreakpointAdded(e) => e.timestamp_ms,
            Self::BreakpointRemoved(e) => e.timestamp_ms,
            Self::AnalysisStarted(e) => e.timestamp_ms,
            Self::AnalysisProgress(e) => e.timestamp_ms,
            Self::AnalysisCompleted(e) => e.timestamp_ms,
            Self::AnalysisFailed(e) => e.timestamp_ms,
            Self::SymbolAdded(e) => e.timestamp_ms,
            Self::SymbolRenamed(e) => e.timestamp_ms,
            Self::SymbolRemoved(e) => e.timestamp_ms,
            Self::FunctionDecompiled(e) => e.timestamp_ms,
            Self::FunctionAnnotated(e) => e.timestamp_ms,
            Self::TypeDefined(e) => e.timestamp_ms,
            Self::TypeRemoved(e) => e.timestamp_ms,
            Self::BinaryLoaded(e) => e.timestamp_ms,
            Self::BinaryUnloaded(e) => e.timestamp_ms,
            Self::SessionOpened(e) => e.timestamp_ms,
            Self::SessionClosed(e) => e.timestamp_ms,
            Self::NavigateTo(e) => e.timestamp_ms,
            Self::ViewFocused(e) => e.timestamp_ms,
            Self::CommentSet(e) => e.timestamp_ms,
            Self::TagAdded(e) => e.timestamp_ms,
            Self::TagRemoved(e) => e.timestamp_ms,
            Self::Custom(e) => e.timestamp_ms,
        }
    }

    /// Human-readable event type name.
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::BreakpointHit(_) => "BreakpointHit",
            Self::BreakpointAdded(_) => "BreakpointAdded",
            Self::BreakpointRemoved(_) => "BreakpointRemoved",
            Self::AnalysisStarted(_) => "AnalysisStarted",
            Self::AnalysisProgress(_) => "AnalysisProgress",
            Self::AnalysisCompleted(_) => "AnalysisCompleted",
            Self::AnalysisFailed(_) => "AnalysisFailed",
            Self::SymbolAdded(_) => "SymbolAdded",
            Self::SymbolRenamed(_) => "SymbolRenamed",
            Self::SymbolRemoved(_) => "SymbolRemoved",
            Self::FunctionDecompiled(_) => "FunctionDecompiled",
            Self::FunctionAnnotated(_) => "FunctionAnnotated",
            Self::TypeDefined(_) => "TypeDefined",
            Self::TypeRemoved(_) => "TypeRemoved",
            Self::BinaryLoaded(_) => "BinaryLoaded",
            Self::BinaryUnloaded(_) => "BinaryUnloaded",
            Self::SessionOpened(_) => "SessionOpened",
            Self::SessionClosed(_) => "SessionClosed",
            Self::NavigateTo(_) => "NavigateTo",
            Self::ViewFocused(_) => "ViewFocused",
            Self::CommentSet(_) => "CommentSet",
            Self::TagAdded(_) => "TagAdded",
            Self::TagRemoved(_) => "TagRemoved",
            Self::Custom(_) => "Custom",
        }
    }
}

// ── Concrete event structs ────────────────────────────────────────────────────

pub(crate) fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_new_with_ts {
    ($t:ident) => {
        impl $t {
            #[inline]
            fn stamp() -> u64 {
                $crate::bus_impl::now_ms()
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHit {
    pub timestamp_ms: u64,
    pub address: u64,
    pub thread_id: u32,
    pub hit_count: u32,
    pub condition_name: Option<String>,
}

impl BreakpointHit {
    #[must_use] 
    pub fn new(address: u64, thread_id: u32) -> Self {
        Self {
            timestamp_ms: now_ms(),
            address,
            thread_id,
            hit_count: 1,
            condition_name: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointAdded {
    pub timestamp_ms: u64,
    pub address: u64,
    pub kind: String,
}

impl BreakpointAdded {
    pub fn new(address: u64, kind: impl Into<String>) -> Self {
        Self {
            timestamp_ms: now_ms(),
            address,
            kind: kind.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointRemoved {
    pub timestamp_ms: u64,
    pub address: u64,
}

impl BreakpointRemoved {
    #[must_use] 
    pub fn new(address: u64) -> Self {
        Self {
            timestamp_ms: now_ms(),
            address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStarted {
    pub timestamp_ms: u64,
    pub session_id: String,
    pub binary_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisProgress {
    pub timestamp_ms: u64,
    pub session_id: String,
    pub phase: String,
    pub percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCompleted {
    pub timestamp_ms: u64,
    pub session_id: String,
    pub duration_ms: u64,
    pub functions_found: u32,
    pub symbols_found: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFailed {
    pub timestamp_ms: u64,
    pub session_id: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolAdded {
    pub timestamp_ms: u64,
    pub address: u64,
    pub name: String,
    pub kind: String,
}

impl SymbolAdded {
    pub fn new(address: u64, name: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            timestamp_ms: now_ms(),
            address,
            name: name.into(),
            kind: kind.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRenamed {
    pub timestamp_ms: u64,
    pub address: u64,
    pub old_name: String,
    pub new_name: String,
}

impl SymbolRenamed {
    pub fn new(address: u64, old_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            timestamp_ms: now_ms(),
            address,
            old_name: old_name.into(),
            new_name: new_name.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRemoved {
    pub timestamp_ms: u64,
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDecompiled {
    pub timestamp_ms: u64,
    pub address: u64,
    pub name: String,
    pub decompiler: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnnotated {
    pub timestamp_ms: u64,
    pub address: u64,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefined {
    pub timestamp_ms: u64,
    pub type_id: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRemoved {
    pub timestamp_ms: u64,
    pub type_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryLoaded {
    pub timestamp_ms: u64,
    pub path: String,
    pub arch: String,
    pub bits: u8,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryUnloaded {
    pub timestamp_ms: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpened {
    pub timestamp_ms: u64,
    pub session_id: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClosed {
    pub timestamp_ms: u64,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigateTo {
    pub timestamp_ms: u64,
    pub address: u64,
    pub view: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewFocused {
    pub timestamp_ms: u64,
    pub view_name: String,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentSet {
    pub timestamp_ms: u64,
    pub address: u64,
    pub old_comment: Option<String>,
    pub new_comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagAdded {
    pub timestamp_ms: u64,
    pub address: u64,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRemoved {
    pub timestamp_ms: u64,
    pub address: u64,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEvent {
    pub timestamp_ms: u64,
    pub name: String,
    pub payload: serde_json::Value,
}

impl CustomEvent {
    pub fn new(name: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            timestamp_ms: now_ms(),
            name: name.into(),
            payload,
        }
    }
}

// ── Typed event extractor traits ─────────────────────────────────────────────

/// Implemented by any type that can be extracted from a `CoreEvent`.
pub trait FromCoreEvent: Sized {
    fn from_core(event: &BusCoreEvent) -> Option<Self>;
}

impl FromCoreEvent for BreakpointHit {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::BreakpointHit(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for BreakpointAdded {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::BreakpointAdded(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for SymbolAdded {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::SymbolAdded(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for SymbolRenamed {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::SymbolRenamed(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for FunctionDecompiled {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::FunctionDecompiled(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for AnalysisCompleted {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::AnalysisCompleted(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for BinaryLoaded {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::BinaryLoaded(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for CommentSet {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::CommentSet(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

impl FromCoreEvent for CustomEvent {
    fn from_core(event: &BusCoreEvent) -> Option<Self> {
        if let BusCoreEvent::Custom(e) = event {
            Some(e.clone())
        } else {
            None
        }
    }
}

// ── Channel primitives (manual broadcast without tokio) ──────────────────────

/// A single slot in the ring-buffer shared between publisher and subscriber.
#[derive(Clone)]
pub struct Slot {
    pub event: Option<BusCoreEvent>,
    pub seq: u64,
}

impl Slot {
    #[must_use] 
    pub const fn seq(&self) -> u64 {
        self.seq
    }
}

/// Shared ring buffer for broadcast delivery without `tokio`.
struct RingBuf {
    buf: Vec<Slot>,
    capacity: usize,
    head: u64, // next sequence number to write
}

impl RingBuf {
    fn new(capacity: usize) -> Self {
        let cap = capacity
            .checked_next_power_of_two()
            .expect("RingBuf capacity too large: next power of two overflows usize");
        Self {
            buf: vec![
                Slot {
                    event: None,
                    seq: 0
                };
                cap
            ],
            capacity: cap,
            head: 0,
        }
    }

    fn mask(&self, seq: u64) -> usize {
        usize::try_from(seq).unwrap_or(usize::MAX) & (self.capacity - 1)
    }

    fn push(&mut self, event: BusCoreEvent) -> u64 {
        let seq = self.head;
        let idx = self.mask(seq);
        self.buf[idx] = Slot {
            event: Some(event),
            seq,
        };
        self.head += 1;
        seq
    }

    /// Try to read event at sequence `seq`. Returns `None` if already overwritten.
    fn get(&self, seq: u64) -> Option<&BusCoreEvent> {
        if seq >= self.head {
            return None; // not yet written
        }
        // Check if overwritten (head has lapped seq by more than capacity).
        if self.head - seq > self.capacity as u64 {
            return None; // overwritten
        }
        let idx = self.mask(seq);
        let slot = &self.buf[idx];
        // Verify the slot still holds the requested sequence; if not, it was
        // overwritten between the bounds check and the load.
        if slot.seq() != seq {
            return None;
        }
        slot.event.as_ref()
    }

    const fn current_head(&self) -> u64 {
        self.head
    }
}

// ── EventLog: ring buffer of last N events ───────────────────────────────────

/// Fixed-capacity ring buffer keeping the last `capacity` events.
pub struct EventLog {
    buf: RwLock<VecDeque<BusCoreEvent>>,
    capacity: usize,
}

impl EventLog {
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, event: BusCoreEvent) {
        let mut buf = self.buf.write().unwrap_or_else(|e: std::sync::PoisonError<_>| e.into_inner());
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn len(&self) -> usize {
        self.buf.read().unwrap().len()
    }

    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain all buffered events into a `Vec` (clone).
    ///
    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn snapshot(&self) -> Vec<BusCoreEvent> {
        let buf = self.buf.read().unwrap();
        let mut out = Vec::with_capacity(buf.len());
        out.extend(buf.iter().cloned());
        out
    }

    /// Return events matching a predicate.
    ///
    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn filter<F>(&self, pred: F) -> Vec<BusCoreEvent>
    where
        F: Fn(&BusCoreEvent) -> bool,
    {
        let buf = self.buf.read().unwrap();
        let mut out = Vec::with_capacity(buf.len());
        out.extend(buf.iter().filter(|e| pred(e)).cloned());
        out
    }

    /// Events since a timestamp.
    pub fn since(&self, ts_ms: u64) -> Vec<BusCoreEvent> {
        self.filter(|e: &BusCoreEvent| e.timestamp_ms() > ts_ms)
    }

    /// Clear the log.
    ///
    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn clear(&self) {
        self.buf.write().unwrap().clear();
    }
}

// ── Persistence: jsonl writer ─────────────────────────────────────────────────

struct JsonlWriter {
    writer: BufWriter<File>,
}

impl JsonlWriter {
    fn open(path: &PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    fn write_event(&mut self, event: &BusCoreEvent) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, event)
            .map_err(std::io::Error::other)?;
        self.writer.write_all(b"\n")
    }
}

// ── EventStats: sliding window rate measurement ───────────────────────────────

const STATS_WINDOW_SEC: u64 = 5;

pub struct EventStats {
    total_published: AtomicU64,
    total_dropped: AtomicU64,
    /// Recent event timestamps (ms) in a sliding window.
    window: Mutex<VecDeque<u64>>,
}

impl EventStats {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            total_published: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            window: Mutex::new(VecDeque::new()),
        }
    }

    fn record_published(&self) {
        self.total_published.fetch_add(1, Ordering::Relaxed);
        let ts = now_ms();
        let cutoff = ts.saturating_sub(STATS_WINDOW_SEC * 1000);
        let mut win = self.window.lock().unwrap();
        win.push_back(ts);
        while win.front().is_some_and(|&t| t < cutoff) {
            win.pop_front();
        }
        drop(win);
    }

    pub fn record_dropped(&self) {
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Events published in the last `STATS_WINDOW_SEC` seconds.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn events_per_second(&self) -> f64 {
        let count = {
            let win = self.window.lock().unwrap();
            cast_usize_to_f64(win.len())
        };
        count / cast_u64_to_f64(STATS_WINDOW_SEC)
    }

    pub fn total_published(&self) -> u64 {
        self.total_published.load(Ordering::Relaxed)
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }
}

impl Default for EventStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── EventReceiver ─────────────────────────────────────────────────────────────

/// A subscriber's view into the event bus.
/// Boxed predicate used to filter events at the receiver.
pub type EventPredicate = Box<dyn Fn(&BusCoreEvent) -> bool + Send + Sync>;

/// Reads from the shared ring buffer starting at the sequence it was created.
pub struct EventReceiver {
    bus: Arc<EventBusInner>,
    next_seq: Mutex<u64>,
    predicate: Option<EventPredicate>,
    replay_queue: Mutex<VecDeque<BusCoreEvent>>,
}

impl EventReceiver {
    fn new(bus: Arc<EventBusInner>, start_seq: u64) -> Self {
        Self {
            bus,
            next_seq: Mutex::new(start_seq),
            predicate: None,
            replay_queue: Mutex::new(VecDeque::new()),
        }
    }
}

impl Drop for EventReceiver {
    fn drop(&mut self) {
        self.bus.subscriber_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl EventReceiver {
    /// Try to receive the next event (non-blocking).
    ///
    /// # Panics
    /// Panics if the internal `Mutex` or `RwLock` is poisoned.
    pub fn try_recv(&self) -> Option<BusCoreEvent> {
        loop {
            let queued = self.replay_queue.lock().unwrap().pop_front();
            match queued {
                Some(event) => {
                    if let Some(ref pred) = self.predicate
                        && !pred(&event) {
                            continue;
                        }
                    return Some(event);
                }
                None => break,
            }
        }
        let mut seq = self.next_seq.lock().unwrap();
        loop {
            let event_opt = {
                let ring = self.bus.ring.read().unwrap();
                ring.get(*seq).cloned()
            };
            if let Some(event) = event_opt {
                *seq += 1;
                if let Some(ref pred) = self.predicate
                    && !pred(&event) {
                        continue;
                    }
                drop(seq);
                return Some(event);
            }
            return None;
        }
    }

    /// Blocking receive with timeout.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<BusCoreEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(e) = self.try_recv() {
                return Some(e);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    /// Drain all currently available events.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` or `RwLock` is poisoned.
    pub fn drain(&self) -> Vec<BusCoreEvent> {
        let mut events = Vec::with_capacity(usize::try_from(self.pending()).unwrap_or(usize::MAX));
        while let Some(e) = self.try_recv() {
            events.push(e);
        }
        events
    }

    /// How many events are waiting (approximate).
    ///
    /// # Panics
    /// Panics if the internal `Mutex` or `RwLock` is poisoned.
    pub fn pending(&self) -> u64 {
        let seq = *self.next_seq.lock().unwrap();
        let head = self.bus.ring.read().unwrap().current_head();
        head.saturating_sub(seq)
    }
}

/// A filtered receiver that only yields events matching a predicate.
pub struct FilteredReceiver {
    inner: EventReceiver,
}

impl FilteredReceiver {
    pub fn try_recv(&self) -> Option<BusCoreEvent> {
        self.inner.try_recv()
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Option<BusCoreEvent> {
        self.inner.recv_timeout(timeout)
    }

    pub fn drain(&self) -> Vec<BusCoreEvent> {
        self.inner.drain()
    }
}

/// A typed receiver that only yields a specific `CoreEvent` variant.
pub struct TypedReceiver<T: FromCoreEvent> {
    inner: EventReceiver,
    _marker: std::marker::PhantomData<T>,
}

impl<T: FromCoreEvent> TypedReceiver<T> {
    pub fn try_recv(&self) -> Option<T> {
        loop {
            let e = self.inner.try_recv()?;
            if let Some(v) = T::from_core(&e) {
                return Some(v);
            }
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Option<T> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = self.try_recv() {
                return Some(v);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    pub fn drain(&self) -> Vec<T> {
        let mut result = Vec::with_capacity(usize::try_from(self.inner.pending()).unwrap_or(usize::MAX));
        while let Some(v) = self.try_recv() { result.push(v); }
        result
    }
}

// ── Inner bus state ───────────────────────────────────────────────────────────

struct EventBusInner {
    ring: RwLock<RingBuf>,
    log: EventLog,
    stats: EventStats,
    persist_writer: Mutex<Option<JsonlWriter>>,
    subscriber_count: AtomicUsize,
}

impl EventBusInner {
    fn new(ring_capacity: usize, log_capacity: usize) -> Self {
        Self {
            ring: RwLock::new(RingBuf::new(ring_capacity)),
            log: EventLog::new(log_capacity),
            stats: EventStats::new(),
            persist_writer: Mutex::new(None),
            subscriber_count: AtomicUsize::new(0),
        }
    }

    fn publish(&self, event: BusCoreEvent) {
        // Write to persistent log if enabled.
        // Acquire the writer once, write, then restore it regardless of the
        // result so that a single I/O error does not permanently lose the writer.
        {
            let mut guard = self.persist_writer.lock().unwrap();
            if let Some(ref mut writer) = *guard
                && writer.write_event(&event).is_err() {
                    self.stats.record_dropped();
                }
        }

        // Append to EventLog ring.
        self.log.push(event.clone());

        // Push to broadcast ring.
        self.ring.write().unwrap().push(event);

        self.stats.record_published();
    }
}

// ── EventBus: the public API ──────────────────────────────────────────────────

/// The main event bus.
/// Capacity: ring buffer holds last 10000 events; log holds last 10000.
pub struct BusImplEventBus {
    inner: Arc<EventBusInner>,
}

impl BusImplEventBus {
    /// Create a new bus with default capacities (ring: 10000, log: 10000).
    #[must_use] 
    pub fn new() -> Self {
        Self {
            inner: Arc::new(EventBusInner::new(10_000, 10_000)),
        }
    }

    /// Create a new bus with explicit capacities.
    #[must_use] 
    pub fn with_capacity(ring_capacity: usize, log_capacity: usize) -> Self {
        Self {
            inner: Arc::new(EventBusInner::new(ring_capacity, log_capacity)),
        }
    }

    /// Enable persistent logging to a `.jsonl` file.
    ///
    /// # Errors
    /// Returns an `io::Error` if the file cannot be opened.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn enable_persistence(&self, path: &&PathBuf) -> std::io::Result<()> {
        let writer = JsonlWriter::open(path)?;
        *self.inner.persist_writer.lock().unwrap() = Some(writer);
        Ok(())
    }

    /// Disable persistent logging.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn disable_persistence(&self) {
        *self.inner.persist_writer.lock().unwrap() = None;
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: BusCoreEvent) {
        self.inner.publish(event);
    }

    /// Subscribe: returns a receiver that sees all events from this point forward.
    ///
    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    #[must_use]
    pub fn subscribe(&self) -> EventReceiver {
        let start_seq = self.inner.ring.read().unwrap().current_head();
        self.inner.subscriber_count.fetch_add(1, Ordering::Relaxed);
        EventReceiver::new(Arc::clone(&self.inner), start_seq)
    }

    /// Subscribe with a filter predicate.
    pub fn subscribe_filtered<F>(&self, pred: F) -> FilteredReceiver
    where
        F: Fn(&BusCoreEvent) -> bool + Send + Sync + 'static,
    {
        let mut rx = self.subscribe();
        rx.predicate = Some(Box::new(pred));
        FilteredReceiver { inner: rx }
    }

    /// Subscribe to a specific typed event variant.
    #[must_use] 
    pub fn subscribe_to<T: FromCoreEvent>(&self) -> TypedReceiver<T> {
        TypedReceiver {
            inner: self.subscribe(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Replay all buffered log events to a new receiver.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn replay_to(&self, rx: &EventReceiver) {
        // Enqueue the full log snapshot (which retains events that have
        // already fallen out of the ring) into the receiver's replay queue
        // so they are delivered by subsequent try_recv calls.
        let snapshot = self.inner.log.snapshot();
        let mut queue = rx.replay_queue.lock().unwrap();
        queue.reserve(snapshot.len());
        queue.extend(snapshot);
    }

    /// Get a snapshot of the event log.
    #[must_use] 
    pub fn log_snapshot(&self) -> Vec<BusCoreEvent> {
        self.inner.log.snapshot()
    }

    /// Filter the log.
    pub fn log_filter<F>(&self, pred: F) -> Vec<BusCoreEvent>
    where
        F: Fn(&BusCoreEvent) -> bool,
    {
        self.inner.log.filter(pred)
    }

    /// Events in log since timestamp.
    #[must_use] 
    pub fn log_since(&self, ts_ms: u64) -> Vec<BusCoreEvent> {
        self.inner.log.since(ts_ms)
    }

    /// Current stats.
    #[must_use] 
    pub fn stats(&self) -> &EventStats {
        &self.inner.stats
    }

    /// Number of active subscribers (approximate).
    #[must_use] 
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscriber_count.load(Ordering::Relaxed)
    }
}

impl Default for BusImplEventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ── EventStream: iterator adapter ─────────────────────────────────────────────

/// An iterator that drains a receiver with a poll timeout.
pub struct EventStream<'a> {
    rx: &'a EventReceiver,
    poll_timeout: Duration,
    max_drain: Option<usize>,
}

impl<'a> EventStream<'a> {
    pub const fn new(rx: &'a EventReceiver) -> Self {
        EventStream {
            rx,
            poll_timeout: Duration::from_millis(5),
            max_drain: None,
        }
    }

    #[must_use] 
    pub const fn with_poll_timeout(mut self, t: Duration) -> Self {
        self.poll_timeout = t;
        self
    }

    #[must_use] 
    pub const fn with_max(mut self, n: usize) -> Self {
        self.max_drain = Some(n);
        self
    }
}

impl Iterator for EventStream<'_> {
    type Item = BusCoreEvent;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(remaining) = self.max_drain {
            if remaining == 0 {
                return None;
            }
            let item = self.rx.recv_timeout(self.poll_timeout)?;
            self.max_drain = Some(remaining - 1);
            Some(item)
        } else {
            self.rx.recv_timeout(self.poll_timeout)
        }
    }
}

// ── Convenience helpers for common publish patterns ──────────────────────────

impl BusImplEventBus {
    pub fn publish_breakpoint_hit(&self, address: u64, thread_id: u32) {
        self.publish(BusCoreEvent::BreakpointHit(BreakpointHit::new(
            address, thread_id,
        )));
    }

    pub fn publish_symbol_renamed(
        &self,
        address: u64,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) {
        self.publish(BusCoreEvent::SymbolRenamed(SymbolRenamed::new(
            address, old_name, new_name,
        )));
    }

    pub fn publish_symbol_added(
        &self,
        address: u64,
        name: impl Into<String>,
        kind: impl Into<String>,
    ) {
        self.publish(BusCoreEvent::SymbolAdded(SymbolAdded::new(
            address, name, kind,
        )));
    }

    pub fn publish_binary_loaded(
        &self,
        path: impl Into<String>,
        arch: impl Into<String>,
        bits: u8,
        size_bytes: u64,
    ) {
        self.publish(BusCoreEvent::BinaryLoaded(BinaryLoaded {
            timestamp_ms: now_ms(),
            path: path.into(),
            arch: arch.into(),
            bits,
            size_bytes,
        }));
    }

    pub fn publish_navigate_to(&self, address: u64, view: impl Into<String>) {
        self.publish(BusCoreEvent::NavigateTo(NavigateTo {
            timestamp_ms: now_ms(),
            address,
            view: view.into(),
        }));
    }

    pub fn publish_custom(&self, name: impl Into<String>, payload: serde_json::Value) {
        self.publish(BusCoreEvent::Custom(CustomEvent::new(name, payload)));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_publish_and_receive() {
        let bus = BusImplEventBus::new();
        let rx = bus.subscribe();

        bus.publish_symbol_renamed(0x1000, "sub_1000", "decrypt");
        bus.publish_breakpoint_hit(0x2000, 1);

        let events = rx.drain();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], BusCoreEvent::SymbolRenamed(_)));
        assert!(matches!(events[1], BusCoreEvent::BreakpointHit(_)));
    }

    #[test]
    fn test_subscribe_before_publish() {
        let bus = BusImplEventBus::new();
        let rx = bus.subscribe();

        for i in 0..5u64 {
            bus.publish_navigate_to(i * 0x100, "disasm");
        }

        let events = rx.drain();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn test_filtered_receiver() {
        let bus = BusImplEventBus::new();
        let rx = bus.subscribe_filtered(|e| matches!(e, BusCoreEvent::SymbolRenamed(_)));

        bus.publish_breakpoint_hit(0x1000, 1);
        bus.publish_symbol_renamed(0x2000, "a", "b");
        bus.publish_breakpoint_hit(0x3000, 1);
        bus.publish_symbol_renamed(0x4000, "c", "d");

        let events = rx.drain();
        // Only SymbolRenamed events should come through.
        assert_eq!(events.len(), 2);
        for e in &events {
            assert!(matches!(e, BusCoreEvent::SymbolRenamed(_)));
        }
    }

    #[test]
    fn test_typed_receiver() {
        let bus = BusImplEventBus::new();
        let rx: TypedReceiver<BreakpointHit> = bus.subscribe_to();

        bus.publish_symbol_renamed(0x1000, "a", "b");
        bus.publish_breakpoint_hit(0x2000, 7);
        bus.publish_symbol_renamed(0x3000, "c", "d");
        bus.publish_breakpoint_hit(0x4000, 8);

        let hits = rx.drain();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].address, 0x2000);
        assert_eq!(hits[0].thread_id, 7);
        assert_eq!(hits[1].address, 0x4000);
    }

    #[test]
    fn test_event_log() {
        let bus = BusImplEventBus::new();

        for i in 0..10u64 {
            bus.publish_navigate_to(i, "hex");
        }

        let snap = bus.log_snapshot();
        assert_eq!(snap.len(), 10);

        let nav_events = bus.log_filter(|e| matches!(e, BusCoreEvent::NavigateTo(_)));
        assert_eq!(nav_events.len(), 10);
    }

    #[test]
    fn test_stats() {
        let bus = BusImplEventBus::new();

        for _ in 0..20 {
            bus.publish_breakpoint_hit(0x1000, 1);
        }

        let stats = bus.stats();
        assert_eq!(stats.total_published(), 20);
        assert!(stats.events_per_second() >= 0.0);
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = BusImplEventBus::new();
        let rx1 = bus.subscribe();
        let rx2 = bus.subscribe();

        bus.publish_breakpoint_hit(0x5000, 3);
        bus.publish_symbol_renamed(0x6000, "x", "y");

        let e1 = rx1.drain();
        let e2 = rx2.drain();
        assert_eq!(e1.len(), 2);
        assert_eq!(e2.len(), 2);
    }

    #[test]
    fn test_recv_timeout() {
        let bus = BusImplEventBus::new();
        let rx = bus.subscribe();

        // No events yet — should time out.
        let result = rx.recv_timeout(Duration::from_millis(10));
        assert!(result.is_none());

        bus.publish_breakpoint_hit(0x1000, 1);
        let result = rx.recv_timeout(Duration::from_millis(10));
        assert!(result.is_some());
    }

    #[test]
    fn test_event_stream_iterator() {
        let bus = BusImplEventBus::new();
        let rx = bus.subscribe();

        bus.publish_breakpoint_hit(0x1, 0);
        bus.publish_breakpoint_hit(0x2, 0);
        bus.publish_breakpoint_hit(0x3, 0);

        let stream = EventStream::new(&rx).with_poll_timeout(Duration::from_millis(1));
        let events: Vec<_> = stream.take(3).collect();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_log_capacity_eviction() {
        let bus = BusImplEventBus::with_capacity(1000, 5);

        for i in 0..10u64 {
            bus.publish_navigate_to(i, "v");
        }

        // Log should hold at most 5.
        let snap = bus.log_snapshot();
        assert_eq!(snap.len(), 5);
    }

    #[test]
    fn test_ring_buffer_wrap() {
        let bus = BusImplEventBus::with_capacity(4, 1000);
        let rx = bus.subscribe();

        // Publish more than ring capacity.
        for i in 0..8u64 {
            bus.publish_navigate_to(i, "v");
        }

        // Receiver starts from head-at-subscribe; events 0..8 after head=0.
        let events = rx.drain();
        // We should get at least those published after subscribe.
        assert!(!events.is_empty());
    }

    #[test]
    fn test_custom_event() {
        let bus = BusImplEventBus::new();
        let rx: TypedReceiver<CustomEvent> = bus.subscribe_to();

        bus.publish_custom("test_event", serde_json::json!({"key": "value"}));

        let evs = rx.drain();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].name, "test_event");
    }
}
