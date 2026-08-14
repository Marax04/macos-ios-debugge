// ============================================================================
// ui/widgets/copyable.rs — Double-click-to-copy address & name tokens
//
// Renders inline text styled with a pointer cursor; a double-click (or higher)
// dispatches `UICommand::CopyToClipboard(text)` through the shared command
// channel. The render loop's `flush_pending_clipboard` mirrors the payload
// into the OS clipboard.
// ============================================================================

use crate::core::event_bus::UICommand;
use crossbeam_channel::Sender;
use gpui::{div, px, Div, InteractiveElement, MouseButton, MouseDownEvent, ParentElement, Stateful, Styled};
use std::sync::OnceLock;

static COPY_TX: OnceLock<Sender<UICommand>> = OnceLock::new();

/// Install the global Sender used by `copyable_addr_global` / `copyable_name_global`.
/// Safe to call multiple times; first wins.
pub fn install_global_sender(tx: Sender<UICommand>) {
    let _ = COPY_TX.set(tx);
}

fn global_tx() -> Option<Sender<UICommand>> {
    COPY_TX.get().cloned()
}

/// Render an address; copies on double-click via the globally-installed Sender.
pub fn copyable_addr_global(addr: u64) -> Stateful<Div> {
    let text = format!("{addr:#018x}");
    let payload = text.clone();
    let tx = global_tx();
    div()
        .id(make_id("addr_g", addr))
        .cursor_pointer()
        .min_h(px(16.0))
        .hover(|s| s.opacity(0.85))
        .child(text)
        .on_mouse_down(MouseButton::Left, move |ev: &MouseDownEvent, _, _| {
            if ev.click_count >= 2 {
                if let Some(tx) = tx.as_ref() {
                    let _ = tx.send(UICommand::CopyToClipboard(payload.clone()));
                }
            }
        })
}

/// Render a symbol name; copies on double-click via the globally-installed Sender.
pub fn copyable_name_global(name: &str) -> Stateful<Div> {
    let text = name.to_owned();
    let key: u64 = name.bytes().fold(0u64, |acc, b| acc.wrapping_mul(131).wrapping_add(u64::from(b)));
    let payload = text.clone();
    let tx = global_tx();
    div()
        .id(make_id("name_g", key))
        .cursor_pointer()
        .min_h(px(16.0))
        .hover(|s| s.opacity(0.85))
        .child(text)
        .on_mouse_down(MouseButton::Left, move |ev: &MouseDownEvent, _, _| {
            if ev.click_count >= 2 {
                if let Some(tx) = tx.as_ref() {
                    let _ = tx.send(UICommand::CopyToClipboard(payload.clone()));
                }
            }
        })
}

/// Element ID for a per-row copyable token. Globally unique enough across a
/// frame so gpui's stateful interactivity can track focus / hover state.
fn make_id(prefix: &'static str, key: u64) -> gpui::ElementId {
    gpui::ElementId::Name(format!("copyable-{prefix}-{key:x}").into())
}

/// Render an address that auto-copies on double-click.
pub fn copyable_addr(addr: u64, tx: Sender<UICommand>) -> Stateful<Div> {
    let text = format!("{addr:#018x}");
    let payload = text.clone();
    div()
        .id(make_id("addr", addr))
        .cursor_pointer()
        .min_h(px(16.0))
        .hover(|s| s.opacity(0.85))
        .child(text)
        .on_mouse_down(MouseButton::Left, move |ev: &MouseDownEvent, _, _| {
            if ev.click_count >= 2 {
                let _ = tx.send(UICommand::CopyToClipboard(payload.clone()));
            }
        })
}

/// Render a symbol name that auto-copies on double-click.
pub fn copyable_name(name: &str, tx: Sender<UICommand>) -> Stateful<Div> {
    let text = name.to_owned();
    let key: u64 = name.bytes().fold(0u64, |acc, b| acc.wrapping_mul(131).wrapping_add(u64::from(b)));
    let payload = text.clone();
    div()
        .id(make_id("name", key))
        .cursor_pointer()
        .child(text)
        .on_mouse_down(MouseButton::Left, move |ev: &MouseDownEvent, _, _| {
            if ev.click_count >= 2 {
                let _ = tx.send(UICommand::CopyToClipboard(payload.clone()));
            }
        })
}

// ── prod ensure-used ──────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_copyable() {
    use crossbeam_channel::unbounded;
    let (tx, _rx) = unbounded::<UICommand>();
    let _ = copyable_addr(0x1000, tx.clone());
    let _ = copyable_name("main", tx);
    let _ = make_id("addr", 0);
    let _ = copyable_addr_global(0x1000);
    let _ = copyable_name_global("main");
}
