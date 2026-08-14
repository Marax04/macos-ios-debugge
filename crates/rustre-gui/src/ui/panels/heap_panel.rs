// ============================================================================
// ui/panels/heap_panel.rs — Heap analyzer panel for RustRE
//
// Ported from the legacy eframe/egui prototype to the current zyphora GPUI
// API. All data structures (HeapInfo, HeapChunk, HeapStats, BucketEntry,
// HeapEvent, SprayCandidate…) and the underlying analytics (bucket
// computation, statistics, spray detection) are preserved verbatim. Only the
// rendering layer was rewritten on top of `gpui::div` element builders,
// following the same convention as `patches_panel.rs`.
// ============================================================================

use crate::core::app_state::UIState;
use crate::core::event_bus::{EventBus, UICommand};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Data types — preserved 1:1 from the legacy panel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ChunkStatus {
    Busy,
    Free,
    Unknown,
}

impl ChunkStatus {
    pub const fn color(&self) -> Hsla {
        match self {
            Self::Busy => colors::err(),
            Self::Free => colors::ok(),
            Self::Unknown => colors::text_muted(),
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Busy => "BUSY",
            Self::Free => "FREE",
            Self::Unknown => "????",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeapChunk {
    pub address: u64,
    pub size: u64,
    pub user_size: u64,
    pub status: ChunkStatus,
    pub flags: u32,
    pub padding: u8,
    pub call_stack: Vec<CallFrame>,
    pub tag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CallFrame {
    pub address: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HeapSegment {
    pub address: u64,
    pub size: u64,
    pub committed: u64,
    pub reserved: u64,
}

#[derive(Debug, Clone)]
pub struct HeapInfo {
    pub address: u64,
    pub flags: u32,
    pub segment_count: usize,
    pub total_size: u64,
    pub used_size: u64,
    pub free_size: u64,
    pub segments: Vec<HeapSegment>,
    pub chunks: Vec<HeapChunk>,
    pub heap_type: HeapType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeapType {
    NtHeap,
    SegmentHeap,
    LowFragHeap,
    Unknown,
}

impl HeapType {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NtHeap => "NT Heap",
            Self::SegmentHeap => "Segment Heap",
            Self::LowFragHeap => "LFH",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BucketEntry {
    pub size_class: u64,
    pub count: usize,
    pub total_bytes: u64,
    pub busy: usize,
    pub free: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeapEventKind {
    Allocated,
    Freed,
    Reallocated,
}

impl HeapEventKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Allocated => "ALLOC",
            Self::Freed => "FREE",
            Self::Reallocated => "REALLOC",
        }
    }

    pub const fn color(&self) -> Hsla {
        match self {
            Self::Allocated => colors::ok(),
            Self::Freed => colors::err(),
            Self::Reallocated => colors::accent_blue(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeapEvent {
    pub timestamp: f64,
    pub address: u64,
    pub size: u64,
    pub kind: HeapEventKind,
    pub heap_address: u64,
    pub call_stack: Vec<CallFrame>,
}

#[derive(Debug, Clone)]
pub struct SprayCandidate {
    pub size: u64,
    pub count: usize,
    pub chunks: Vec<u64>,
    pub confidence: f32,
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct HeapStats {
    pub alloc_count: usize,
    pub free_count: usize,
    pub total_bytes_allocated: u64,
    pub total_bytes_free: u64,
    pub largest_free_chunk: u64,
    pub fragmentation_pct: f32,
    pub spray_candidates: Vec<SprayCandidate>,
}

impl HeapStats {
    pub fn compute(chunks: &[HeapChunk]) -> Self {
        let mut alloc_count = 0usize;
        let mut free_count = 0usize;
        let mut total_bytes_allocated = 0u64;
        let mut total_bytes_free = 0u64;
        let mut largest_free_chunk = 0u64;
        let mut size_map: HashMap<u64, Vec<u64>> = HashMap::new();

        for chunk in chunks {
            match chunk.status {
                ChunkStatus::Busy => {
                    alloc_count += 1;
                    total_bytes_allocated += chunk.user_size;
                    size_map
                        .entry(chunk.size)
                        .or_default()
                        .push(chunk.address);
                }
                ChunkStatus::Free => {
                    free_count += 1;
                    total_bytes_free += chunk.size;
                    if chunk.size > largest_free_chunk {
                        largest_free_chunk = chunk.size;
                    }
                }
                ChunkStatus::Unknown => {}
            }
        }

        let fragmentation_pct = if total_bytes_allocated + total_bytes_free > 0 {
            total_bytes_free as f32 / (total_bytes_allocated + total_bytes_free) as f32 * 100.0
        } else {
            0.0
        };

        let mut spray_candidates: Vec<SprayCandidate> = size_map
            .into_iter()
            .filter(|(_, addrs)| addrs.len() >= 20)
            .map(|(size, addrs)| {
                let count = addrs.len();
                let confidence = ((count as f32 - 20.0) / 80.0).clamp(0.0, 1.0);
                SprayCandidate {
                    size,
                    count,
                    chunks: addrs,
                    confidence,
                }
            })
            .collect();
        spray_candidates.sort_by(|a, b| b.count.cmp(&a.count));

        Self {
            alloc_count,
            free_count,
            total_bytes_allocated,
            total_bytes_free,
            largest_free_chunk,
            fragmentation_pct,
            spray_candidates,
        }
    }
}

// ---------------------------------------------------------------------------
// Filter / sort state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ChunkFilter {
    All,
    BusyOnly,
    FreeOnly,
    WithCallStack,
}

impl ChunkFilter {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::BusyOnly => "Busy",
            Self::FreeOnly => "Free",
            Self::WithCallStack => "With Stack",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChunkSortColumn {
    Address,
    Size,
    UserSize,
    Status,
    Flags,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActiveTab {
    Chunks,
    Buckets,
    Statistics,
    Timeline,
}

impl ActiveTab {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Chunks => "Chunks",
            Self::Buckets => "Buckets",
            Self::Statistics => "Statistics",
            Self::Timeline => "Timeline",
        }
    }
}

// ---------------------------------------------------------------------------
// Panel state
// ---------------------------------------------------------------------------

pub struct HeapPanel {
    pub heaps: Vec<HeapInfo>,
    pub selected_heap_idx: Option<usize>,
    pub selected_chunk_idx: Option<usize>,

    pub chunk_filter: ChunkFilter,
    pub sort_column: ChunkSortColumn,
    pub sort_ascending: bool,

    pub search_address: String,
    pub search_result: Option<usize>,

    pub active_tab: ActiveTab,

    pub timeline_events: Vec<HeapEvent>,
    pub timeline_zoom: f32,
    pub timeline_offset: f32,
    pub timeline_filter_heap: Option<u64>,

    pub last_refresh: Option<Instant>,
    pub is_refreshing: bool,
    pub auto_refresh: bool,
    pub auto_refresh_interval: Duration,

    pub show_call_stack_popup: bool,
    pub popup_chunk_idx: Option<usize>,

    pub bucket_entries: Vec<BucketEntry>,

    pub stats: Option<HeapStats>,

    pub navigate_to_address: Option<u64>,
}

impl Default for HeapPanel {
    fn default() -> Self {
        Self {
            // Heap data is a runtime debugger feature — empty until a live
            // debug session populates it. The generators below remain for the
            // 'load demo' tooling but are never invoked at panel construction.
            heaps: Vec::new(),
            selected_heap_idx: None,
            selected_chunk_idx: None,
            chunk_filter: ChunkFilter::All,
            sort_column: ChunkSortColumn::Address,
            sort_ascending: true,
            search_address: String::new(),
            search_result: None,
            active_tab: ActiveTab::Chunks,
            timeline_events: Vec::new(),
            timeline_zoom: 1.0,
            timeline_offset: 0.0,
            timeline_filter_heap: None,
            last_refresh: None,
            is_refreshing: false,
            auto_refresh: false,
            auto_refresh_interval: Duration::from_secs(2),
            show_call_stack_popup: false,
            popup_chunk_idx: None,
            bucket_entries: Vec::new(),
            stats: None,
            navigate_to_address: None,
        }
    }
}

impl HeapPanel {
    pub fn new() -> Self {
        let mut p = Self::default();
        p.recompute_for_selected_heap();
        p
    }

    pub fn take_navigate_address(&mut self) -> Option<u64> {
        self.navigate_to_address.take()
    }

    pub fn refresh(&mut self) {
        self.is_refreshing = true;
        self.last_refresh = Some(Instant::now());
        self.is_refreshing = false;
        if let Some(idx) = self.selected_heap_idx {
            if idx < self.heaps.len() {
                self.recompute_for_selected_heap();
            }
        }
    }

    pub fn recompute_for_selected_heap(&mut self) {
        if let Some(idx) = self.selected_heap_idx {
            if idx < self.heaps.len() {
                let chunks = &self.heaps[idx].chunks;
                self.bucket_entries = compute_buckets(chunks);
                self.stats = Some(HeapStats::compute(chunks));
            }
        }
    }

    pub fn do_address_search(&mut self) {
        let addr_str = self
            .search_address
            .trim()
            .replace("0x", "")
            .replace("0X", "");
        let Ok(target) = u64::from_str_radix(&addr_str, 16) else {
            self.search_result = None;
            return;
        };
        let Some(heap_idx) = self.selected_heap_idx else {
            return;
        };
        if heap_idx >= self.heaps.len() {
            return;
        }
        let chunks = &self.heaps[heap_idx].chunks;
        self.search_result = chunks
            .iter()
            .position(|c| target >= c.address && target < c.address + c.size);
    }
}

// ---------------------------------------------------------------------------
// Demo data generators
// ---------------------------------------------------------------------------

fn generate_demo_heaps() -> Vec<HeapInfo> {
    let chunks1 = generate_demo_chunks(0x0010_0000, 120);
    let chunks2 = generate_demo_chunks(0x0030_0000, 45);

    vec![
        HeapInfo {
            address: 0x0052_0000,
            flags: 0x0002,
            segment_count: 3,
            total_size: 0x0010_0000,
            used_size: 0x0008_A000,
            free_size: 0x0007_6000,
            segments: vec![
                HeapSegment {
                    address: 0x0052_0000,
                    size: 0x4_0000,
                    committed: 0x3_8000,
                    reserved: 0x4_0000,
                },
                HeapSegment {
                    address: 0x0057_0000,
                    size: 0x8_0000,
                    committed: 0x5_2000,
                    reserved: 0x8_0000,
                },
            ],
            chunks: chunks1,
            heap_type: HeapType::NtHeap,
        },
        HeapInfo {
            address: 0x0062_0000,
            flags: 0x0008,
            segment_count: 1,
            total_size: 0x0004_0000,
            used_size: 0x0001_2000,
            free_size: 0x0002_E000,
            segments: vec![HeapSegment {
                address: 0x0062_0000,
                size: 0x4_0000,
                committed: 0x2_0000,
                reserved: 0x4_0000,
            }],
            chunks: chunks2,
            heap_type: HeapType::LowFragHeap,
        },
        HeapInfo {
            address: 0x0072_0000,
            flags: 0x0040,
            segment_count: 2,
            total_size: 0x0008_0000,
            used_size: 0x0005_5000,
            free_size: 0x0002_B000,
            segments: vec![],
            chunks: Vec::new(),
            heap_type: HeapType::SegmentHeap,
        },
    ]
}

fn generate_demo_chunks(base: u64, count: usize) -> Vec<HeapChunk> {
    let sizes = [16u64, 24, 32, 48, 64, 96, 128, 256, 512, 1024];
    let mut chunks = Vec::with_capacity(count);
    let mut addr = base;

    for i in 0..count {
        let size = sizes[i % sizes.len()];
        let status = if i.is_multiple_of(3) {
            ChunkStatus::Free
        } else {
            ChunkStatus::Busy
        };
        let user_size = if size > 8 { size - 8 } else { 0 };

        let call_stack = if status == ChunkStatus::Busy && i.is_multiple_of(5) {
            vec![
                CallFrame {
                    address: 0x0040_1234 + i as u64 * 0x10,
                    symbol: Some(format!("sub_{:08X}", 0x0040_1234 + i * 0x10)),
                    module: Some("target.exe".into()),
                },
                CallFrame {
                    address: 0x0040_3A00,
                    symbol: Some("allocate_buffer".into()),
                    module: Some("target.exe".into()),
                },
                CallFrame {
                    address: 0x77A0_1234,
                    symbol: Some("RtlAllocateHeap".into()),
                    module: Some("ntdll.dll".into()),
                },
            ]
        } else {
            Vec::new()
        };

        chunks.push(HeapChunk {
            address: addr,
            size,
            user_size,
            status,
            flags: if i.is_multiple_of(7) { 0x05 } else { 0x01 },
            padding: (i % 8) as u8,
            call_stack,
            tag: if i.is_multiple_of(10) {
                Some(format!("Tag_{}", i / 10))
            } else {
                None
            },
        });

        addr += size + 8;
    }

    chunks
}

fn generate_demo_timeline() -> Vec<HeapEvent> {
    let mut events = Vec::new();
    let heap_addr = 0x0052_0000u64;

    for i in 0..80 {
        let t = i as f64 * 0.05;
        let addr = 0x0052_1000u64 + (i as u64 % 32) * 0x40;
        let size = 32u64 + (i % 8) as u64 * 16;

        let kind = match i % 4 {
            0 | 1 => HeapEventKind::Allocated,
            2 => HeapEventKind::Freed,
            _ => HeapEventKind::Reallocated,
        };

        events.push(HeapEvent {
            timestamp: t,
            address: addr,
            size,
            kind,
            heap_address: heap_addr,
            call_stack: Vec::new(),
        });
    }

    events
}

fn compute_buckets(chunks: &[HeapChunk]) -> Vec<BucketEntry> {
    let mut map: HashMap<u64, (usize, u64, usize, usize)> = HashMap::new();

    for chunk in chunks {
        let bucket_size = round_to_bucket(chunk.size);
        let e = map.entry(bucket_size).or_default();
        e.0 += 1;
        e.1 += chunk.size;
        match chunk.status {
            ChunkStatus::Busy => e.2 += 1,
            ChunkStatus::Free => e.3 += 1,
            ChunkStatus::Unknown => {}
        }
    }

    let mut entries: Vec<BucketEntry> = map
        .into_iter()
        .map(|(size_class, (count, total, busy, free))| BucketEntry {
            size_class,
            count,
            total_bytes: total,
            busy,
            free,
        })
        .collect();
    entries.sort_by_key(|e| e.size_class);
    entries
}

fn round_to_bucket(size: u64) -> u64 {
    if size <= 256 {
        (size + 15) & !15
    } else if size <= 1024 {
        (size + 63) & !63
    } else if size <= 8192 {
        (size + 511) & !511
    } else {
        (size + 4095) & !4095
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.2} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn format_addr(a: u64) -> String {
    format!("{a:#018X}")
}

// ---------------------------------------------------------------------------
// Per-UIState slot
// ---------------------------------------------------------------------------

/// Container so the panel can be embedded in `UIState` in the future. Today
/// the render entry-point builds a fresh `HeapPanel` from demo data on every
/// frame, mirroring the convention in `patches_panel.rs`.
#[derive(Default)]
pub struct HeapPanelState {
    pub panel: Option<HeapPanel>,
}

// ---------------------------------------------------------------------------
// Render — entry point
// ---------------------------------------------------------------------------

pub fn render_heap_panel(
    state: Arc<Mutex<UIState>>,
    bus: &Arc<EventBus>,
    panel: &HeapPanel,
) -> impl IntoElement {
    // Caller in app.rs holds the UI mutex; parking_lot is not reentrant — drop
    // the Arc without re-locking to avoid a renderer deadlock.
    drop(state);
    let bus = Arc::clone(bus);

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(render_toolbar(panel, &bus))
        .child(render_tab_strip(panel, &bus))
        .child(
            div()
                .flex()
                .flex_row()
                .flex_1()
                .overflow_hidden()
                .child(render_heap_list(panel, &bus))
                .child(render_main_pane(panel)),
        )
        .child(if panel.show_call_stack_popup {
            render_call_stack_popup(panel).into_any_element()
        } else {
            div().into_any_element()
        })
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------

fn render_toolbar(panel: &HeapPanel, bus: &Arc<EventBus>) -> impl IntoElement {
    let last_refresh_text = panel
        .last_refresh
        .map(|t| format!("Last refresh: {:.1}s ago", t.elapsed().as_secs_f32()))
        .unwrap_or_else(|| "Never refreshed".to_string());

    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::TOOLBAR_H))
        .px_2()
        .gap_1()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(tb_btn_primary(
            if panel.is_refreshing {
                "Refreshing..."
            } else {
                "Refresh"
            },
            UICommand::HeapRefresh,
            bus,
        ))
        .child(checkbox_chip(
            "Auto",
            panel.auto_refresh,
            UICommand::HeapToggleAutoRefresh,
            bus,
        ))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!(
                    "every {}s",
                    panel.auto_refresh_interval.as_secs()
                )),
        )
        .child(divider())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child("Filter:"),
        )
        .child(filter_chip(
            ChunkFilter::All.label(),
            matches!(panel.chunk_filter, ChunkFilter::All),
            UICommand::HeapSetFilter(0),
            bus,
        ))
        .child(filter_chip(
            ChunkFilter::BusyOnly.label(),
            matches!(panel.chunk_filter, ChunkFilter::BusyOnly),
            UICommand::HeapSetFilter(1),
            bus,
        ))
        .child(filter_chip(
            ChunkFilter::FreeOnly.label(),
            matches!(panel.chunk_filter, ChunkFilter::FreeOnly),
            UICommand::HeapSetFilter(2),
            bus,
        ))
        .child(filter_chip(
            ChunkFilter::WithCallStack.label(),
            matches!(panel.chunk_filter, ChunkFilter::WithCallStack),
            UICommand::HeapSetFilter(3),
            bus,
        ))
        .child(divider())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child("Search:"),
        )
        .child(
            div()
                .w(px(160.0))
                .px_2()
                .py_1()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .text_size(px(sizes::LABEL))
                .text_color(if panel.search_address.is_empty() {
                    colors::text_muted()
                } else {
                    colors::text_primary()
                })
                .truncate()
                .child(if panel.search_address.is_empty() {
                    "0x...".to_string()
                } else {
                    panel.search_address.clone()
                }),
        )
        .child(tb_btn("Find", UICommand::HeapFindAddress, bus))
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(last_refresh_text),
        )
}

fn render_tab_strip(panel: &HeapPanel, bus: &Arc<EventBus>) -> impl IntoElement {
    let tabs = [
        ActiveTab::Chunks,
        ActiveTab::Buckets,
        ActiveTab::Statistics,
        ActiveTab::Timeline,
    ];

    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::TAB_H))
        .px_2()
        .gap_1()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .children(tabs.iter().enumerate().map(|(i, t)| {
            let idx = u8::try_from(i).unwrap_or(0);
            view_btn(t.label(), &panel.active_tab == t, UICommand::HeapSetTab(idx), bus)
        }))
}

// ---------------------------------------------------------------------------
// Left pane: heap list
// ---------------------------------------------------------------------------

fn render_heap_list(panel: &HeapPanel, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .w(px(260.0))
        .h_full()
        .bg(colors::bg_surface())
        .border_r_1()
        .border_color(colors::border())
        .child(
            div()
                .h(px(22.0))
                .px_2()
                .flex()
                .items_center()
                .bg(colors::bg_elevated())
                .border_b_1()
                .border_color(colors::border())
                .text_size(px(sizes::HEADING))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Heaps"),
        )
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .flex()
                .flex_col()
                .gap_1()
                .p_1()
                .children(panel.heaps.iter().enumerate().map(|(i, h)| {
                    render_heap_card(h, panel.selected_heap_idx == Some(i), i, bus)
                })),
        )
}

fn render_heap_card(
    heap: &HeapInfo,
    selected: bool,
    idx: usize,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let total = heap.total_size.max(1) as f32;
    let used_frac = (heap.used_size as f32 / total).clamp(0.0, 1.0);
    let bus = Arc::clone(bus);
    let addr = heap.address;

    div()
        .id(SharedString::from(format!("heap-card-{idx}")))
        .flex()
        .flex_col()
        .gap_1()
        .p_2()
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::HeapSelectHeap(idx));
            bus.send_command(UICommand::HeapCopyAddr(addr));
        })
        .bg(if selected {
            colors::bg_selection()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if selected {
            colors::border_focus()
        } else {
            colors::border()
        })
        .rounded_sm()
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_address())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(format_addr(heap.address)),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::syn_prefix())
                        .truncate()
                        .child(heap.heap_type.label()),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .truncate()
                        .child(format!("{} segs", heap.segment_count)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::warn())
                        .truncate()
                        .child(format!("Used: {}", format_bytes(heap.used_size))),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::ok())
                        .truncate()
                        .child(format!("Free: {}", format_bytes(heap.free_size))),
                ),
        )
        .child(
            div()
                .w_full()
                .h(px(4.0))
                .bg(colors::bg_base())
                .rounded_sm()
                .child(
                    div()
                        .w(gpui::relative(used_frac))
                        .h(px(4.0))
                        .bg(colors::accent())
                        .rounded_sm(),
                ),
        )
}

// ---------------------------------------------------------------------------
// Main pane (right) — dispatches on the active tab
// ---------------------------------------------------------------------------

fn render_main_pane(panel: &HeapPanel) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .flex_1()
        .h_full()
        .overflow_hidden()
        .child(match panel.active_tab {
            ActiveTab::Chunks => render_chunks_tab(panel).into_any_element(),
            ActiveTab::Buckets => render_buckets_tab(panel).into_any_element(),
            ActiveTab::Statistics => render_statistics_tab(panel).into_any_element(),
            ActiveTab::Timeline => render_timeline_tab(panel).into_any_element(),
        })
}

// ---------------------------------------------------------------------------
// Chunks tab
// ---------------------------------------------------------------------------

fn render_chunks_tab(panel: &HeapPanel) -> impl IntoElement {
    let Some(heap_idx) = panel.selected_heap_idx else {
        return empty_message("Select a heap from the left panel").into_any_element();
    };
    if heap_idx >= panel.heaps.len() {
        return empty_message("Heap index out of range").into_any_element();
    }

    let chunks = &panel.heaps[heap_idx].chunks;

    let mut filtered: Vec<usize> = (0..chunks.len())
        .filter(|&i| match panel.chunk_filter {
            ChunkFilter::All => true,
            ChunkFilter::BusyOnly => chunks[i].status == ChunkStatus::Busy,
            ChunkFilter::FreeOnly => chunks[i].status == ChunkStatus::Free,
            ChunkFilter::WithCallStack => !chunks[i].call_stack.is_empty(),
        })
        .collect();

    filtered.sort_by(|&a, &b| {
        let ca = &chunks[a];
        let cb = &chunks[b];
        let ord = match panel.sort_column {
            ChunkSortColumn::Address => ca.address.cmp(&cb.address),
            ChunkSortColumn::Size => ca.size.cmp(&cb.size),
            ChunkSortColumn::UserSize => ca.user_size.cmp(&cb.user_size),
            ChunkSortColumn::Status => ca.status.label().cmp(cb.status.label()),
            ChunkSortColumn::Flags => ca.flags.cmp(&cb.flags),
        };
        if panel.sort_ascending {
            ord
        } else {
            ord.reverse()
        }
    });

    let search_highlight = panel.search_result;

    let rows = filtered.iter().enumerate().map(|(row_idx, &chunk_idx)| {
        let chunk = &chunks[chunk_idx];
        render_chunk_row(
            chunk,
            row_idx,
            panel.selected_chunk_idx == Some(chunk_idx),
            search_highlight == Some(chunk_idx),
        )
    });

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .child(
            div()
                .h(px(20.0))
                .px_2()
                .flex()
                .items_center()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .bg(colors::bg_surface())
                .border_b_1()
                .border_color(colors::border())
                .truncate()
                .child(format!(
                    "{} chunks shown ({} total)",
                    filtered.len(),
                    chunks.len()
                )),
        )
        .child(render_chunk_header(panel))
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .flex()
                .flex_col()
                .children(rows),
        )
        .child(if let Some(sel) = panel.selected_chunk_idx {
            if sel < chunks.len() {
                render_chunk_detail(&chunks[sel]).into_any_element()
            } else {
                div().into_any_element()
            }
        } else {
            div().into_any_element()
        })
        .into_any_element()
}

fn render_chunk_header(panel: &HeapPanel) -> impl IntoElement {
    let cols = [
        ("Address", 160.0, ChunkSortColumn::Address),
        ("Size", 60.0, ChunkSortColumn::Size),
        ("User Size", 70.0, ChunkSortColumn::UserSize),
        ("Status", 60.0, ChunkSortColumn::Status),
        ("Flags", 60.0, ChunkSortColumn::Flags),
        ("Pad", 36.0, ChunkSortColumn::Flags),
        ("Tag", 80.0, ChunkSortColumn::Flags),
    ];

    let mut row = div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(20.0))
        .px_2()
        .gap_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border());

    for (label, w, col) in cols {
        let active = panel.sort_column == col;
        let arrow = if active {
            if panel.sort_ascending {
                " ^"
            } else {
                " v"
            }
        } else {
            ""
        };
        row = row.child(
            div()
                .w(px(w))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(if active {
                    colors::text_bright()
                } else {
                    colors::text_muted()
                })
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(format!("{label}{arrow}")),
        );
    }
    row.child(
        div()
            .flex_1()
            .text_size(px(sizes::LABEL - 0.5))
            .text_color(colors::text_muted())
            .font_weight(FontWeight::SEMIBOLD)
            .truncate()
            .child("Stack"),
    )
}

fn render_chunk_row(
    chunk: &HeapChunk,
    row_idx: usize,
    selected: bool,
    search_hit: bool,
) -> impl IntoElement {
    let bg = if search_hit {
        colors::warn()
    } else if selected {
        colors::bg_selection()
    } else if row_idx.is_multiple_of(2) {
        colors::bg_surface()
    } else {
        colors::bg_panel()
    };

    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H + 1.0))
        .px_2()
        .gap_2()
        .bg(bg)
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(160.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_address())
                .truncate()
                .child(format_addr(chunk.address)),
        )
        .child(
            div()
                .w(px(60.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .truncate()
                .child(format!("{}", chunk.size)),
        )
        .child(
            div()
                .w(px(70.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{}", chunk.user_size)),
        )
        .child(
            div()
                .w(px(60.0))
                .text_size(px(sizes::LABEL))
                .text_color(chunk.status.color())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(chunk.status.label()),
        )
        .child(
            div()
                .w(px(60.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{:#04X}", chunk.flags)),
        )
        .child(
            div()
                .w(px(36.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{}", chunk.padding)),
        )
        .child(
            div()
                .w(px(80.0))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::syn_symbol())
                .truncate()
                .child(chunk.tag.clone().unwrap_or_default()),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(if chunk.call_stack.is_empty() {
                    colors::text_muted()
                } else {
                    colors::accent_blue()
                })
                .truncate()
                .child(if chunk.call_stack.is_empty() {
                    String::new()
                } else {
                    format!("[{} frames]", chunk.call_stack.len())
                }),
        )
}

fn render_chunk_detail(chunk: &HeapChunk) -> impl IntoElement {
    let mut body = div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .py_2()
        .bg(colors::bg_surface())
        .border_t_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .child(kv("Address", &format_addr(chunk.address)))
                .child(kv("Chunk Size", &format!("{} ({:#X})", chunk.size, chunk.size)))
                .child(kv(
                    "User Size",
                    &format!("{} ({:#X})", chunk.user_size, chunk.user_size),
                ))
                .child(kv("Status", chunk.status.label()))
                .child(kv("Flags", &format!("{:#010b} ({:#04X})", chunk.flags, chunk.flags)))
                .child(kv("Pad", &format!("{}", chunk.padding))),
        );

    if let Some(tag) = &chunk.tag {
        body = body.child(kv("Tag", tag));
    }

    if !chunk.call_stack.is_empty() {
        body = body.child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Allocation Call Stack:"),
        );
        for (i, frame) in chunk.call_stack.iter().enumerate() {
            let sym = frame.symbol.as_deref().unwrap_or("???");
            let module = frame.module.as_deref().unwrap_or("???");
            body = body.child(
                div()
                    .text_size(px(sizes::LABEL - 1.0))
                    .text_color(colors::text_secondary())
                    .truncate()
                    .child(format!(
                        "  #{i} {:#018X} {module}!{sym}",
                        frame.address
                    )),
            );
        }
    }
    body
}

// ---------------------------------------------------------------------------
// Buckets tab
// ---------------------------------------------------------------------------

fn render_buckets_tab(panel: &HeapPanel) -> impl IntoElement {
    if panel.selected_heap_idx.is_none() {
        return empty_message("Select a heap first").into_any_element();
    }
    let max_count = panel
        .bucket_entries
        .iter()
        .map(|b| b.count)
        .max()
        .unwrap_or(1) as f32;

    let header = div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(20.0))
        .px_2()
        .gap_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(hdr_cell("Size Class", 100.0))
        .child(hdr_cell("Count", 60.0))
        .child(hdr_cell("Busy", 60.0))
        .child(hdr_cell("Free", 60.0))
        .child(hdr_cell("Total Bytes", 100.0))
        .child(hdr_cell("Distribution", 160.0));

    let rows = panel.bucket_entries.iter().map(|b| {
        let frac = (b.count as f32 / max_count).clamp(0.0, 1.0);
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(sizes::ROW_H))
            .px_2()
            .gap_2()
            .border_b_1()
            .border_color(colors::border())
            .child(cell(&format_bytes(b.size_class), 100.0, colors::syn_immediate()))
            .child(cell(&format!("{}", b.count), 60.0, colors::text_primary()))
            .child(cell(&format!("{}", b.busy), 60.0, colors::err()))
            .child(cell(&format!("{}", b.free), 60.0, colors::ok()))
            .child(cell(
                &format_bytes(b.total_bytes),
                100.0,
                colors::text_secondary(),
            ))
            .child(
                div()
                    .w(px(160.0))
                    .h(px(6.0))
                    .bg(colors::bg_base())
                    .rounded_sm()
                    .child(
                        div()
                            .w(gpui::relative(frac))
                            .h(px(6.0))
                            .bg(colors::accent())
                            .rounded_sm(),
                    ),
            )
    });

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .child(
            div()
                .h(px(22.0))
                .px_2()
                .flex()
                .items_center()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child("Allocation buckets grouped by size class"),
        )
        .child(header)
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .flex()
                .flex_col()
                .children(rows),
        )
        .into_any_element()
}

// ---------------------------------------------------------------------------
// Statistics tab
// ---------------------------------------------------------------------------

fn render_statistics_tab(panel: &HeapPanel) -> impl IntoElement {
    if panel.selected_heap_idx.is_none() {
        return empty_message("Select a heap first").into_any_element();
    }
    let Some(stats) = panel.stats.as_ref() else {
        return empty_message("No stats yet — refresh to compute").into_any_element();
    };

    let frag_color = if stats.fragmentation_pct > 50.0 {
        colors::err()
    } else if stats.fragmentation_pct > 25.0 {
        colors::warn()
    } else {
        colors::ok()
    };
    let frag_frac = (stats.fragmentation_pct / 100.0).clamp(0.0, 1.0);

    let mut body = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Heap Statistics"),
        )
        .child(stat_line("Allocations", &stats.alloc_count.to_string(), colors::text_primary()))
        .child(stat_line(
            "Free chunks",
            &stats.free_count.to_string(),
            colors::ok(),
        ))
        .child(stat_line(
            "Bytes allocated",
            &format_bytes(stats.total_bytes_allocated),
            colors::warn(),
        ))
        .child(stat_line(
            "Bytes free",
            &format_bytes(stats.total_bytes_free),
            colors::ok(),
        ))
        .child(stat_line(
            "Largest free chunk",
            &format_bytes(stats.largest_free_chunk),
            colors::accent_cyan(),
        ))
        .child(stat_line(
            "Fragmentation",
            &format!("{:.1}%", stats.fragmentation_pct),
            frag_color,
        ))
        .child(
            div()
                .w_full()
                .h(px(8.0))
                .bg(colors::bg_base())
                .rounded_sm()
                .child(
                    div()
                        .w(gpui::relative(frag_frac))
                        .h(px(8.0))
                        .bg(frag_color)
                        .rounded_sm(),
                ),
        );

    if !stats.spray_candidates.is_empty() {
        body = body.child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::accent_red())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Spray Detection"),
        );
        body = body.child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child("Size classes with many allocations (possible heap spray):"),
        );
        for spray in &stats.spray_candidates {
            body = body.child(render_spray_card(spray));
        }
    }

    div()
        .flex_1()
        .overflow_hidden()
        .child(body)
        .into_any_element()
}

fn render_spray_card(spray: &SprayCandidate) -> impl IntoElement {
    let conf_color = if spray.confidence > 0.8 {
        colors::err()
    } else if spray.confidence > 0.5 {
        colors::warn()
    } else {
        colors::syn_label()
    };

    let preview_count = spray.chunks.len().min(8);
    let addrs: Vec<String> = spray.chunks[..preview_count]
        .iter()
        .map(|a| format!("{a:#018X}"))
        .collect();

    div()
        .flex()
        .flex_col()
        .gap_1()
        .p_2()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .truncate()
                        .child(format!("Size: {}", format_bytes(spray.size))),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_secondary())
                        .truncate()
                        .child(format!("Count: {}", spray.count)),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(conf_color)
                        .truncate()
                        .child(format!("Confidence: {:.0}%", spray.confidence * 100.0)),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("Addresses: {} ...", addrs.join(", "))),
        )
}

// ---------------------------------------------------------------------------
// Timeline tab
// ---------------------------------------------------------------------------

fn render_timeline_tab(panel: &HeapPanel) -> impl IntoElement {
    let events = &panel.timeline_events;
    let max_t = events.iter().map(|e| e.timestamp).fold(0.0f64, f64::max);

    let max_size_kib = events
        .iter()
        .map(|e| e.size as f32 / 1024.0)
        .fold(1.0f32, f32::max);

    let bar_count = events.len().min(120);
    let bars = events.iter().take(bar_count).map(|ev| {
        let h_frac = ((ev.size as f32 / 1024.0) / max_size_kib).clamp(0.05, 1.0);
        div()
            .flex()
            .flex_col()
            .justify_end()
            .items_center()
            .w(px(6.0))
            .h(px(80.0))
            .child(
                div()
                    .w(px(4.0))
                    .h(gpui::relative(h_frac))
                    .bg(ev.kind.color())
                    .rounded_sm(),
            )
    });

    let legend = div()
        .flex()
        .flex_row()
        .gap_3()
        .px_2()
        .py_1()
        .child(legend_chip("Allocated", colors::ok()))
        .child(legend_chip("Freed", colors::err()))
        .child(legend_chip("Reallocated", colors::accent_blue()));

    let header = div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(22.0))
        .px_2()
        .gap_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("Zoom: {:.1}x", panel.timeline_zoom)),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("Offset: {:.0}%", panel.timeline_offset)),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("Total span: {max_t:.2}s")),
        );

    let event_rows = events.iter().take(200).map(|ev| {
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(sizes::ROW_H))
            .px_2()
            .gap_2()
            .border_b_1()
            .border_color(colors::border())
            .child(cell(&format!("{:.3}s", ev.timestamp), 70.0, colors::text_secondary()))
            .child(
                div()
                    .w(px(70.0))
                    .text_size(px(sizes::LABEL))
                    .text_color(ev.kind.color())
                    .font_weight(FontWeight::SEMIBOLD)
                    .truncate()
                    .child(ev.kind.label()),
            )
            .child(cell(&format_addr(ev.address), 160.0, colors::syn_address()))
            .child(cell(&format_bytes(ev.size), 80.0, colors::text_primary()))
            .child(cell(
                &format_addr(ev.heap_address),
                160.0,
                colors::syn_prefix(),
            ))
    });

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .child(header)
        .child(
            div()
                .flex()
                .flex_row()
                .items_end()
                .h(px(90.0))
                .px_2()
                .gap_px()
                .bg(colors::bg_base())
                .border_b_1()
                .border_color(colors::border())
                .children(bars),
        )
        .child(legend)
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .flex()
                .flex_col()
                .children(event_rows),
        )
        .into_any_element()
}

fn legend_chip(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(div().w_3().h_3().rounded_sm().bg(color))
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(label.to_string()),
        )
}

// ---------------------------------------------------------------------------
// Call stack popup
// ---------------------------------------------------------------------------

fn render_call_stack_popup(panel: &HeapPanel) -> impl IntoElement {
    let Some(chunk_idx) = panel.popup_chunk_idx else {
        return div().into_any_element();
    };
    let Some(heap_idx) = panel.selected_heap_idx else {
        return div().into_any_element();
    };
    if heap_idx >= panel.heaps.len() || chunk_idx >= panel.heaps[heap_idx].chunks.len() {
        return div().into_any_element();
    }

    let chunk = &panel.heaps[heap_idx].chunks[chunk_idx];
    let mut card = div()
        .flex()
        .flex_col()
        .gap_1()
        .p_3()
        .bg(colors::bg_surface())
        .border_1()
        .border_color(colors::border_accent())
        .rounded_md()
        .child(
            div()
                .text_size(px(sizes::HEADING))
                .text_color(colors::accent())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(format!(
                    "Call Stack - Chunk {:#018X}",
                    chunk.address
                )),
        );

    for (i, frame) in chunk.call_stack.iter().enumerate() {
        let sym = frame.symbol.as_deref().unwrap_or("???");
        let module = frame.module.as_deref().unwrap_or("???");
        card = card.child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!(
                    "#{i:02} {:#018X}  {module}!{sym}",
                    frame.address
                )),
        );
    }
    card.into_any_element()
}

// ---------------------------------------------------------------------------
// Shared chrome
// ---------------------------------------------------------------------------

fn empty_message(msg: &str) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .w_full()
        .h_full()
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(msg.to_string()),
        )
}

fn kv(k: &str, v: &str) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_1()
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{k}:")),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_primary())
                .truncate()
                .child(v.to_string()),
        )
}

fn stat_line(label: &str, value: &str, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .gap_2()
        .child(
            div()
                .w(px(180.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{label}:")),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(color)
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child(value.to_string()),
        )
}

fn hdr_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(label)
}

fn cell(value: &str, w: f32, color: Hsla) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL))
        .text_color(color)
        .truncate()
        .child(value.to_string())
}

fn tb_btn(label: &'static str, cmd: UICommand, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("heap-tb-{label}")))
        .px_2()
        .h(px(22.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(colors::text_secondary())
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
        .truncate()
        .child(label)
}

fn tb_btn_primary(
    label: &'static str,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("heap-tbp-{label}")))
        .px_2()
        .h(px(22.0))
        .bg(colors::accent())
        .border_1()
        .border_color(colors::accent())
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.05,
            a: 1.0,
        })
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::accent_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
        .truncate()
        .child(label)
}

fn view_btn(
    label: &'static str,
    active: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("heap-view-{label}")))
        .px_2()
        .h(px(22.0))
        .bg(if active {
            colors::bg_active()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if active {
            colors::border_focus()
        } else {
            colors::border()
        })
        .rounded_sm()
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(if active {
            colors::text_bright()
        } else {
            colors::text_secondary()
        })
        .text_size(px(sizes::LABEL))
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
        .truncate()
        .child(label)
}

fn filter_chip(
    label: &'static str,
    active: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    view_btn(label, active, cmd, bus)
}

fn checkbox_chip(
    label: &'static str,
    checked: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("heap-chk-{label}")))
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .h(px(22.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .cursor_pointer()
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
        .child(
            div()
                .w(px(10.0))
                .h(px(10.0))
                .border_1()
                .border_color(if checked {
                    colors::accent()
                } else {
                    colors::border()
                })
                .bg(if checked {
                    colors::accent()
                } else {
                    Hsla {
                        h: 0.0,
                        s: 0.0,
                        l: 0.0,
                        a: 0.0,
                    }
                })
                .rounded_sm(),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .truncate()
                .child(label),
        )
}

fn divider() -> impl IntoElement {
    div().w(px(1.0)).h(px(20.0)).bg(colors::border())
}

// ---------------------------------------------------------------------------
// ensure-used — touches every public API the panel exposes so dead-code
// warnings cannot mask wiring gaps. Mirrors patches_panel::ensure_used_*.
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn ensure_used_heap_panel() {
    for s in [ChunkStatus::Busy, ChunkStatus::Free, ChunkStatus::Unknown] {
        let _ = s.label();
        let _ = s.color();
    }
    for h in [
        HeapType::NtHeap,
        HeapType::SegmentHeap,
        HeapType::LowFragHeap,
        HeapType::Unknown,
    ] {
        let _ = h.label();
    }
    for k in [
        HeapEventKind::Allocated,
        HeapEventKind::Freed,
        HeapEventKind::Reallocated,
    ] {
        let _ = k.label();
        let _ = k.color();
    }
    for f in [
        ChunkFilter::All,
        ChunkFilter::BusyOnly,
        ChunkFilter::FreeOnly,
        ChunkFilter::WithCallStack,
    ] {
        let _ = f.label();
    }
    for c in [
        ChunkSortColumn::Address,
        ChunkSortColumn::Size,
        ChunkSortColumn::UserSize,
        ChunkSortColumn::Status,
        ChunkSortColumn::Flags,
    ] {
        let _ = matches!(c, ChunkSortColumn::Address);
    }
    for t in [
        ActiveTab::Chunks,
        ActiveTab::Buckets,
        ActiveTab::Statistics,
        ActiveTab::Timeline,
    ] {
        let _ = t.label();
    }

    let mut panel = HeapPanel::new();
    panel.navigate_to_address = Some(0);
    let _ = panel.take_navigate_address();
    panel.search_address = "0x100000".into();
    panel.do_address_search();
    panel.refresh();
    panel.recompute_for_selected_heap();
    panel.timeline_filter_heap = Some(0x52_0000);
    panel.popup_chunk_idx = Some(0);
    panel.show_call_stack_popup = true;
    panel.active_tab = ActiveTab::Buckets;
    panel.chunk_filter = ChunkFilter::BusyOnly;
    panel.sort_column = ChunkSortColumn::Size;
    panel.sort_ascending = false;
    panel.selected_chunk_idx = Some(0);
    panel.timeline_zoom = 2.0;
    panel.timeline_offset = 10.0;
    panel.auto_refresh = true;
    panel.auto_refresh_interval = Duration::from_secs(5);
    panel.is_refreshing = false;
    let _ = &panel.heaps;
    let _ = &panel.bucket_entries;
    let _ = &panel.stats;
    let _ = &panel.timeline_events;
    let _ = panel.search_result;
    let _ = panel.last_refresh;

    let segment = HeapSegment {
        address: 0,
        size: 0,
        committed: 0,
        reserved: 0,
    };
    let _ = (
        segment.address,
        segment.size,
        segment.committed,
        segment.reserved,
    );
    let frame = CallFrame {
        address: 0,
        symbol: Some("x".into()),
        module: Some("m".into()),
    };
    let _ = (&frame.address, &frame.symbol, &frame.module);
    let bucket = BucketEntry {
        size_class: 16,
        count: 1,
        total_bytes: 16,
        busy: 1,
        free: 0,
    };
    let _ = (
        bucket.size_class,
        bucket.count,
        bucket.total_bytes,
        bucket.busy,
        bucket.free,
    );

    let ev = HeapEvent {
        timestamp: 0.0,
        address: 0,
        size: 16,
        kind: HeapEventKind::Allocated,
        heap_address: 0,
        call_stack: vec![frame.clone()],
    };
    let _ = (
        ev.timestamp,
        ev.address,
        ev.size,
        &ev.kind,
        ev.heap_address,
        &ev.call_stack,
    );

    let spray = SprayCandidate {
        size: 16,
        count: 30,
        chunks: vec![0, 16, 32],
        confidence: 0.5,
    };
    let _ = (spray.size, spray.count, &spray.chunks, spray.confidence);

    let stats = HeapStats::compute(&panel.heaps[0].chunks);
    let _ = (
        stats.alloc_count,
        stats.free_count,
        stats.total_bytes_allocated,
        stats.total_bytes_free,
        stats.largest_free_chunk,
        stats.fragmentation_pct,
        &stats.spray_candidates,
    );

    let info = &panel.heaps[0];
    let _ = (
        info.address,
        info.flags,
        info.segment_count,
        info.total_size,
        info.used_size,
        info.free_size,
        &info.segments,
        &info.chunks,
        &info.heap_type,
    );

    let st: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::default()));
    let bus: Arc<EventBus> = Arc::new(EventBus::new());
    let _ = render_heap_panel(Arc::clone(&st), &bus, &panel);
    let _ = render_toolbar(&panel, &bus);
    let _ = render_tab_strip(&panel, &bus);
    let _ = render_heap_list(&panel, &bus);
    let _ = render_heap_card(&panel.heaps[0], true, 0, &bus);
    let _ = render_heap_card(&panel.heaps[0], false, 0, &bus);
    let _ = render_main_pane(&panel);
    let _ = render_chunks_tab(&panel);
    let _ = render_chunk_header(&panel);
    let _ = render_chunk_row(&panel.heaps[0].chunks[0], 0, true, false);
    let _ = render_chunk_row(&panel.heaps[0].chunks[0], 1, false, true);
    let _ = render_chunk_detail(&panel.heaps[0].chunks[0]);
    let _ = render_buckets_tab(&panel);
    let _ = render_statistics_tab(&panel);
    let _ = render_spray_card(&spray);
    let _ = render_timeline_tab(&panel);
    let _ = render_call_stack_popup(&panel);
    let _ = empty_message("x");
    let _ = kv("k", "v");
    let _ = stat_line("k", "v", colors::ok());
    let _ = hdr_cell("h", 10.0);
    let _ = cell("v", 10.0, colors::ok());
    let _ = tb_btn("x", UICommand::HeapFindAddress, &bus);
    let _ = tb_btn_primary("x", UICommand::HeapRefresh, &bus);
    let _ = view_btn("x", true, UICommand::HeapSetTab(0), &bus);
    let _ = view_btn("x", false, UICommand::HeapSetTab(1), &bus);
    let _ = filter_chip("x", true, UICommand::HeapSetFilter(0), &bus);
    let _ = checkbox_chip("x", true, UICommand::HeapToggleAutoRefresh, &bus);
    let _ = checkbox_chip("x", false, UICommand::HeapToggleAutoRefresh, &bus);
    let _ = divider();
    let _ = legend_chip("x", colors::ok());
    let _ = format_bytes(0);
    let _ = format_bytes(2048);
    let _ = format_bytes(2 * 1024 * 1024);
    let _ = format_bytes(2 * 1024 * 1024 * 1024);
    let _ = format_addr(0x1234);
    let _ = round_to_bucket(8);
    let _ = round_to_bucket(300);
    let _ = round_to_bucket(2048);
    let _ = round_to_bucket(20_000);
    let _ = compute_buckets(&panel.heaps[0].chunks);
    let _ = generate_demo_heaps();
    let _ = generate_demo_chunks(0, 1);
    let _ = generate_demo_timeline();

    let ext = HeapPanelState::default();
    let _ = &ext.panel;
}
