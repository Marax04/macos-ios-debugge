// ============================================================================
// ui/theme.rs — Zyphora Reversing palette
//
// Inspired by the Zyphora logo: deep black background, electric purple/blue,
// magenta-red glitch accent, cyan highlights, pure white text. Designed to
// feel like a chromatic-aberration RGB-split monitor.
// ============================================================================

use gpui::Pixels;

// ── Color palette ─────────────────────────────────────────────────────────────

pub mod colors {
    use gpui::Hsla;

    // ── Backgrounds (almost-black with cool tint) ───────────────────────────
    pub const fn bg_base() -> Hsla {
        // #06070C — near black with a barely-perceptible blue undertone.
        hsla(230.0 / 360.0, 0.30, 0.04, 1.0)
    }
    pub const fn bg_surface() -> Hsla {
        // #0C0E18
        hsla(230.0 / 360.0, 0.26, 0.07, 1.0)
    }
    pub const fn bg_elevated() -> Hsla {
        // #14172A
        hsla(230.0 / 360.0, 0.27, 0.11, 1.0)
    }
    pub const fn bg_panel() -> Hsla {
        // Panel chrome, sits between surface and elevated.
        hsla(230.0 / 360.0, 0.24, 0.09, 1.0)
    }
    pub const fn bg_selection() -> Hsla {
        // Translucent electric-blue wash for selected rows.
        hsla(225.0 / 360.0, 0.85, 0.55, 0.32)
    }
    pub const fn bg_hover() -> Hsla {
        // Translucent purple wash for hover.
        hsla(258.0 / 360.0, 0.65, 0.45, 0.18)
    }
    pub const fn bg_active() -> Hsla {
        hsla(258.0 / 360.0, 0.65, 0.45, 0.28)
    }

    // ── Text ────────────────────────────────────────────────────────────────
    pub const fn text_primary() -> Hsla {
        hsla(0.0, 0.0, 0.92, 1.0)
    }
    pub const fn text_secondary() -> Hsla {
        hsla(230.0 / 360.0, 0.12, 0.65, 1.0)
    }
    pub const fn text_muted() -> Hsla {
        hsla(230.0 / 360.0, 0.10, 0.42, 1.0)
    }
    pub const fn text_bright() -> Hsla {
        hsla(0.0, 0.0, 1.00, 1.0)
    }

    // ── Syntax — multi-hue rainbow tuned for dark BG ────────────────────────
    pub const fn syn_mnemonic() -> Hsla {
        // Electric cyan — mnemonics pop.
        hsla(195.0 / 360.0, 0.85, 0.68, 1.0)
    }
    pub const fn syn_register() -> Hsla {
        // Magenta-pink — registers stand out from blue mnemonics.
        hsla(320.0 / 360.0, 0.80, 0.70, 1.0)
    }
    pub const fn syn_immediate() -> Hsla {
        // Mint / lime green — easily distinguished numbers.
        hsla(150.0 / 360.0, 0.65, 0.62, 1.0)
    }
    pub const fn syn_address() -> Hsla {
        // Sky-cyan for memory addresses.
        hsla(190.0 / 360.0, 0.70, 0.62, 1.0)
    }
    pub const fn syn_symbol() -> Hsla {
        // Warm amber — symbol references.
        hsla(38.0 / 360.0, 0.95, 0.66, 1.0)
    }
    pub const fn syn_comment() -> Hsla {
        // Muted blue-grey — comments fade into the BG.
        hsla(225.0 / 360.0, 0.20, 0.48, 1.0)
    }
    pub const fn syn_prefix() -> Hsla {
        // Bright violet — keywords / prefixes.
        hsla(266.0 / 360.0, 0.75, 0.72, 1.0)
    }
    pub const fn syn_label() -> Hsla {
        // Yellow-orange labels.
        hsla(50.0 / 360.0, 0.85, 0.65, 1.0)
    }
    pub const fn syn_punct() -> Hsla {
        hsla(0.0, 0.0, 0.55, 1.0)
    }
    pub const fn syn_unknown() -> Hsla {
        // Glitch-red for unknown/error tokens.
        hsla(348.0 / 360.0, 0.85, 0.62, 1.0)
    }

    // ── Borders ─────────────────────────────────────────────────────────────
    pub const fn border() -> Hsla {
        hsla(230.0 / 360.0, 0.18, 0.18, 1.0)
    }
    pub const fn border_focus() -> Hsla {
        // Electric blue — focused field outline.
        hsla(225.0 / 360.0, 0.95, 0.62, 1.0)
    }
    pub const fn border_accent() -> Hsla {
        // Vibrant violet — the "primary" outline used on Zyphora cards.
        hsla(258.0 / 360.0, 0.85, 0.62, 1.0)
    }

    // ── Accents — the three logo voices ─────────────────────────────────────
    /// Primary brand accent: electric violet — used for the headline,
    /// focused buttons, progress fills.
    pub const fn accent() -> Hsla {
        hsla(260.0 / 360.0, 0.90, 0.62, 1.0)
    }
    pub const fn accent_hover() -> Hsla {
        hsla(260.0 / 360.0, 0.92, 0.72, 1.0)
    }
    /// Cool secondary: electric blue — used for confirm / continue.
    pub const fn accent_blue() -> Hsla {
        hsla(225.0 / 360.0, 0.95, 0.60, 1.0)
    }
    /// Cyan tertiary — used for neutral highlights.
    pub const fn accent_cyan() -> Hsla {
        hsla(190.0 / 360.0, 0.85, 0.60, 1.0)
    }
    /// Magenta-red — the "ghost" channel of the logo glitch.
    pub const fn accent_red() -> Hsla {
        hsla(348.0 / 360.0, 0.88, 0.58, 1.0)
    }

    // ── Status ──────────────────────────────────────────────────────────────
    pub const fn ok() -> Hsla {
        // Cyan-green, matches the rest of the cool palette better than
        // pure green.
        hsla(160.0 / 360.0, 0.75, 0.55, 1.0)
    }
    pub const fn warn() -> Hsla {
        // Amber.
        hsla(38.0 / 360.0, 0.95, 0.58, 1.0)
    }
    pub const fn err() -> Hsla {
        // Magenta-red.
        hsla(348.0 / 360.0, 0.88, 0.58, 1.0)
    }

    // ── Graph edges ─────────────────────────────────────────────────────────
    pub const fn edge_true() -> Hsla {
        // IDA Pro: green for taken/true branch
        hsla(120.0 / 360.0, 0.80, 0.55, 1.0)
    }
    pub const fn edge_false() -> Hsla {
        // IDA Pro: red for fallthrough/false branch
        hsla(0.0 / 360.0, 0.90, 0.58, 1.0)
    }
    pub const fn edge_uncond() -> Hsla {
        hsla(225.0 / 360.0, 0.85, 0.68, 1.0)
    }
    pub const fn edge_call() -> Hsla {
        hsla(266.0 / 360.0, 0.80, 0.66, 1.0)
    }
    pub const fn edge_back() -> Hsla {
        hsla(38.0 / 360.0, 0.90, 0.60, 1.0)
    }

    // ── Graph node highlight states ──────────────────────────────────────────
    pub const fn node_selected_border() -> Hsla {
        // Bright vivid yellow-white — the clicked block's border
        hsla(55.0 / 360.0, 1.0, 0.72, 1.0)
    }
    pub const fn node_selected_bg() -> Hsla {
        // Deep golden tint for selected node header
        hsla(45.0 / 360.0, 0.85, 0.22, 1.0)
    }
    pub const fn node_connected_border() -> Hsla {
        // Soft cyan — nodes directly connected to selected
        hsla(190.0 / 360.0, 0.90, 0.60, 1.0)
    }
    pub const fn node_connected_bg() -> Hsla {
        // Subtle cyan tint for connected node header
        hsla(190.0 / 360.0, 0.60, 0.15, 1.0)
    }
    pub const fn node_dimmed() -> Hsla {
        // When other nodes are selected, unrelated nodes dim
        hsla(225.0 / 360.0, 0.15, 0.25, 0.55)
    }
    pub fn edge_glow_outer(base: Hsla) -> Hsla {
        // Outer glow layer — same hue, very transparent
        Hsla { h: base.h, s: base.s, l: (base.l * 1.3).min(0.95), a: 0.18 }
    }
    pub fn edge_glow_mid(base: Hsla) -> Hsla {
        // Mid glow layer — same hue, semi-transparent
        Hsla { h: base.h, s: base.s, l: (base.l * 1.2).min(0.90), a: 0.42 }
    }

    // ── Gutter ──────────────────────────────────────────────────────────────
    pub const fn gutter_bg() -> Hsla {
        hsla(230.0 / 360.0, 0.30, 0.05, 1.0)
    }
    pub const fn bp_enabled() -> Hsla {
        hsla(348.0 / 360.0, 0.92, 0.58, 1.0)
    }
    pub const fn bp_disabled() -> Hsla {
        hsla(348.0 / 360.0, 0.30, 0.32, 1.0)
    }
    pub const fn pc_arrow() -> Hsla {
        hsla(45.0 / 360.0, 0.95, 0.62, 1.0)
    }

    const fn hsla(h: f32, s: f32, l: f32, a: f32) -> Hsla {
        Hsla { h, s, l, a }
    }
}

// ── Font sizes ────────────────────────────────────────────────────────────────

pub mod sizes {
    pub const CODE: f32 = 13.0;
    pub const LABEL: f32 = 11.5;
    pub const PANEL: f32 = 12.0;
    pub const HEADING: f32 = 14.0;
    pub const STATUS: f32 = 11.0;
    pub const TITLE: f32 = 20.0;
    pub const GUTTER_W: f32 = 64.0;
    pub const ROW_H: f32 = 19.0;
    pub const TAB_H: f32 = 28.0;
    pub const TOOLBAR_H: f32 = 34.0;
    pub const STATUS_H: f32 = 22.0;
}

// ── Theme struct (instance-based for future hot-reload) ───────────────────────

#[derive(Clone)]
pub struct Theme {
    pub name: &'static str,
}

impl Theme {
    pub const fn dark() -> Self {
        Self {
            name: "Zyphora Dark",
        }
    }
}

// ── Token kind → color mapping ────────────────────────────────────────────────

use crate::core::types::TokenKind;

pub const fn token_color(kind: TokenKind) -> Hsla {
    match kind {
        TokenKind::Mnemonic => colors::syn_mnemonic(),
        TokenKind::Register => colors::syn_register(),
        TokenKind::Immediate => colors::syn_immediate(),
        TokenKind::Address => colors::syn_address(),
        TokenKind::Symbol | TokenKind::DataRef => colors::syn_symbol(),
        TokenKind::Comment => colors::syn_comment(),
        TokenKind::Prefix => colors::syn_prefix(),
        TokenKind::Label => colors::syn_label(),
        TokenKind::Punctuation => colors::syn_punct(),
        TokenKind::Whitespace => colors::text_primary(),
        TokenKind::Unknown => colors::syn_unknown(),
    }
}

// GPUI Hsla convenience
const fn hsla(h: f32, s: f32, l: f32, a: f32) -> Hsla {
    Hsla { h, s, l, a }
}
pub use gpui::Hsla;

// Keep the `gpui::*` glob in this module alive by referencing `Pixels`,
// which is only reachable through that glob (no explicit `use gpui::Pixels`).
pub const fn _touch_gpui_glob() -> Option<Pixels> {
    None
}

#[doc(hidden)]
pub const fn ensure_used_theme() {
    let _: Option<Hsla> = Some(hsla(0.0, 0.0, 0.0, 1.0));
    let _ = Theme::dark();
    let t = Theme::dark();
    let _ = t.name;
    let _ = hsla(0.0, 0.0, 0.0, 1.0);
    let _ = colors::accent_blue();
    let _ = colors::accent_cyan();
    let _ = colors::accent_red();
    let _ = colors::edge_back();
    let _ = colors::node_selected_border();
    let _ = colors::node_selected_bg();
    let _ = colors::node_connected_border();
    let _ = colors::node_connected_bg();
    let _ = colors::node_dimmed();
    let _ = sizes::HEADING;
    let _ = sizes::TITLE;
}
