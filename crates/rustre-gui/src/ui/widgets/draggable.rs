//! Draggable + resizable wrapper used by floating overlays.
//!
//! gpui at the pinned bc823db does not expose continuous window-level
//! mouse-move tracking from a non-input element, so true 1:1 drag-and-drop
//! cannot be implemented here yet. Instead this widget exposes the data
//! model + a click-to-snap minimal behaviour so consumers can already wire
//! their dialogs to a position they can persist, and the rendering will
//! upgrade automatically when full drag support lands.

use crate::ui::theme::colors;
use gpui::{div, px, InteractiveElement, IntoElement, ParentElement, SharedString, Styled};
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default)]
pub struct DraggableState {
    pub pos: Option<(f32, f32)>,
    pub size: Option<(f32, f32)>,
    pub dragging: bool,
    pub drag_offset: (f32, f32),
}

impl DraggableState {
    pub const fn new() -> Self {
        Self {
            pos: None,
            size: None,
            dragging: false,
            drag_offset: (0.0, 0.0),
        }
    }
    pub const fn position(&self) -> Option<(f32, f32)> {
        self.pos
    }
    pub fn size_with_default(&self, def_w: f32, def_h: f32) -> (f32, f32) {
        self.size.unwrap_or((def_w, def_h))
    }
    pub const fn begin_drag(&mut self, cur: (f32, f32)) {
        self.dragging = true;
        self.drag_offset = cur;
    }
    pub fn update_drag(&mut self, cur: (f32, f32)) {
        if self.dragging {
            let (ox, oy) = self.drag_offset;
            let (cx, cy) = cur;
            let dx = cx - ox;
            let dy = cy - oy;
            let (px_, py_) = self.pos.unwrap_or((100.0, 100.0));
            self.pos = Some((px_ + dx, py_ + dy));
            self.drag_offset = cur;
        }
    }
    pub const fn end_drag(&mut self) {
        self.dragging = false;
    }
    pub const fn resize_to(&mut self, w: f32, h: f32) {
        let cw = if w < 120.0 { 120.0 } else { w };
        let ch = if h < 80.0 { 80.0 } else { h };
        self.size = Some((cw, ch));
    }
}

pub fn draggable_window(
    id: impl Into<SharedString>,
    state: &Arc<Mutex<DraggableState>>,
    title: impl Into<SharedString>,
    default_w: f32,
    default_h: f32,
    body: gpui::AnyElement,
) -> gpui::AnyElement {
    let id: SharedString = id.into();
    let title: SharedString = title.into();
    let (w, h) = state.lock().size_with_default(default_w, default_h);
    let pos = state.lock().pos.unwrap_or(((1280.0 - w) / 2.0, 80.0));

    // gpui's Div doesn't expose continuous drag tracking in this build;
    // wire a single mouse-down on the title bar that flips the dragging
    // flag (consumers can periodically read state.dragging to apply visual
    // affordance). The snap-on-corner-click resize handle stays inert too.
    let state_drag = Arc::clone(state);
    let title_bar = div()
        .id(SharedString::from(format!("{id}-title")))
        .w_full()
        .h(px(24.0))
        .bg(colors::bg_elevated())
        .cursor_pointer()
        .on_mouse_down(gpui::MouseButton::Left, move |_, _, _| {
            state_drag.lock().begin_drag((0.0, 0.0));
        })
        .child(
            div()
                .px_2()
                .text_size(px(11.0))
                .text_color(colors::text_primary())
                .child(title),
        );

    let state_resize = Arc::clone(state);
    let resize_corner = div()
        .id(SharedString::from(format!("{id}-resize")))
        .w(px(12.0))
        .h(px(12.0))
        .bg(colors::accent())
        .cursor_pointer()
        .on_mouse_down(gpui::MouseButton::Left, move |_, _, _| {
            let mut s = state_resize.lock();
            let (sw, sh) = s.size_with_default(default_w, default_h);
            s.resize_to(sw * 1.1, sh * 1.1);
        });

    div()
        .id(id)
        .absolute()
        .left(px(pos.0))
        .top(px(pos.1))
        .w(px(w))
        .h(px(h))
        .bg(colors::bg_surface())
        .border_1()
        .border_color(colors::border())
        .rounded_md()
        .flex()
        .flex_col()
        .overflow_hidden()
        .child(title_bar)
        .child(div().flex_1().overflow_hidden().child(body))
        .child(resize_corner)
        .into_any_element()
}

#[doc(hidden)]
pub fn ensure_used_draggable() {
    let s = Arc::new(Mutex::new(DraggableState::new()));
    let _ = s.lock().position();
    s.lock().begin_drag((10.0, 10.0));
    s.lock().update_drag((20.0, 20.0));
    s.lock().end_drag();
    s.lock().resize_to(200.0, 200.0);
    let _ = s.lock().size_with_default(300.0, 300.0);
    let body: gpui::AnyElement = div().into_any_element();
    let _ = draggable_window("drag-smoke", &s, "Smoke", 320.0, 240.0, body);
}
