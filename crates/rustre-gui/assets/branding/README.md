# Zyphora — Branding

The Welcome view loads `assets/branding/zyphora_logo.svg` at startup.

To use a custom raster logo (e.g. the official Z-glitch design):

1. Save the PNG as `assets/branding/zyphora_logo.png` (square, ≥ 512 × 512).
2. Update `src/ui/views/welcome.rs` to swap
   `svg().path("branding/zyphora_logo.svg")` for
   `img("branding/zyphora_logo.png")` and rebuild.

The horizontal "ZYPHORA REVERSING" wordmark can be dropped at
`assets/branding/zyphora_wordmark.png` and referenced the same way from the
About dialog (`src/ui/app.rs`, `render_about_dialog`).

Recommended sizes:
- App-icon Z mark    256×256 / 512×512
- Horizontal wordmark 1600×400 (or any 4:1 ratio)
