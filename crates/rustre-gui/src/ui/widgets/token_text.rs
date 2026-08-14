// ============================================================================
// ui/widgets/token_text.rs — Renders a row of InsnTokens as colored spans
// ============================================================================

use crate::core::types::{InsnToken, TokenKind};
use crate::ui::theme::{colors, sizes, token_color};
use gpui::{div, px, AnyElement, IntoElement, ParentElement, Styled};

/// Compute the x-width of a string in a monospace font at given px size.
/// Using a fixed 0.60 ratio for a 13px monospace font = 7.8px/char.
#[inline]
pub fn char_width(font_size: f32) -> f32 {
    font_size * 0.60
}

/// Sanitize a string for display: strip C0 control characters (except `\t`),
/// strip U+202E (right-to-left override) which can be used to spoof file
/// extensions, and replace any remaining non-printable / replacement-marker
/// chars with a middle dot. Returns the original string when no changes are
/// needed so common-case allocations are avoided.
pub fn sanitize_display(s: &str) -> std::borrow::Cow<'_, str> {
    let needs = s.chars().any(|c| {
        matches!(c, '\u{0}'..='\u{8}' | '\u{B}'..='\u{1F}' | '\u{7F}' | '\u{202E}' | '\u{FFFD}')
    });
    if !needs {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' | '\n' => out.push(c),
            '\u{0}'..='\u{8}' | '\u{B}'..='\u{1F}' | '\u{7F}' | '\u{FFFD}' => out.push('\u{B7}'),
            '\u{202E}' => {} // strip BiDi override
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Format raw bytes as a space-separated hex byte string with a stable
/// two-char width per byte. Used by the listing's optional bytes column to
/// avoid the U+FFFD boxes produced by `String::from_utf8_lossy` on
/// non-printable bytes.
pub fn format_byte_row(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Build a horizontal flex container of colored text spans for a token row.
pub fn render_tokens(tokens: &[InsnToken], font_size: f32) -> impl IntoElement + '_ {
    let mut children: Vec<AnyElement> = Vec::with_capacity(tokens.len());

    for tok in tokens {
        let color = token_color(tok.kind);
        let text = tok.text.clone();
        let el = div()
            .text_color(color)
            .text_size(px(font_size))
            .font_family("JetBrains Mono")
            .child(sanitize_display(&text).into_owned())
            .into_any_element();
        children.push(el);
    }

    div().flex().flex_row().gap_0().children(children)
}

/// Render a token row with a leading address gutter.
pub fn render_listing_row<'a>(
    addr_str: &'a str,
    tokens: &'a [InsnToken],
    is_selected: bool,
    is_hovered: bool,
    is_pc: bool,
    row_h: f32,
) -> impl IntoElement + 'a {
    let bg = if is_selected {
        colors::bg_selection()
    } else if is_pc {
        Hsla {
            h: 60.0 / 360.0,
            s: 0.7,
            l: 0.25,
            a: 0.5,
        }
    } else if is_hovered {
        colors::bg_hover()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    let border_left = if is_selected {
        colors::accent()
    } else if is_pc {
        colors::pc_arrow()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(row_h))
        .bg(bg)
        .border_l_2()
        .border_color(border_left)
        .items_center()
        .gap_0()
        .child(
            // Address gutter
            div()
                .w(px(sizes::GUTTER_W + 16.0))
                .h_full()
                .flex()
                .items_center()
                .px_2()
                .bg(colors::gutter_bg())
                .text_color(colors::syn_address())
                .text_size(px(sizes::CODE - 1.0))
                .font_family("JetBrains Mono")
                .child(addr_str.to_owned()),
        )
        .child(
            // Token content
            div()
                .flex()
                .flex_row()
                .flex_1()
                .h_full()
                .items_center()
                .px_2()
                .children(tokens.iter().map(|tok| {
                    div()
                        .text_color(token_color(tok.kind))
                        .text_size(px(sizes::CODE))
                        .font_family("JetBrains Mono")
                        .child(sanitize_display(&tok.text).into_owned())
                })),
        )
}

// Re-export for convenience
pub use super::super::theme::Hsla;

#[doc(hidden)]
pub fn ensure_used_token_text() {
    // Touch TokenKind so the import is considered used in production code.
    let kind: TokenKind = TokenKind::Mnemonic;
    debug_assert!(matches!(kind, TokenKind::Mnemonic));

    // Touch char_width with a representative font size.
    let w = char_width(13.0);
    debug_assert!(w > 0.0);

    // Touch render_tokens by invoking it with an empty slice; consume via _ binding.
    let tokens: Vec<InsnToken> = Vec::new();
    let _el1 = render_tokens(&tokens, 13.0);

    // Touch render_listing_row with neutral inputs.
    let _el2 = render_listing_row("0x0", &tokens, false, false, false, 16.0);

    // Touch new sanitization / byte-row helpers so they participate in the
    // production binary and aren't flagged dead-code.
    let s = sanitize_display("hello\u{1}\u{202E}world").into_owned();
    debug_assert!(!s.contains('\u{1}'));
    let bs = format_byte_row(&[0u8, 0xFF, 0x41]);
    debug_assert_eq!(bs, "00 ff 41");
}
