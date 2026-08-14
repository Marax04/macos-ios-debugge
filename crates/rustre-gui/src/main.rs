// ============================================================================
// main.rs — Zyphora Reversing entry point (GPUI application)
// ============================================================================

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![recursion_limit = "512"]

mod analysis;
mod assets;
mod core;
mod db;
mod debugger;
mod ensure_used;
mod formats;
mod ui;

use core::app_state::AppState;
use gpui::prelude::*;
use ui::app::IDAApp;

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("(unknown panic payload)");
        let location = info
            .location()
            .map_or_else(|| "(unknown location)".to_owned(), ToString::to_string);
        log::error!("PANIC at {location}: {payload}");
        // Best-effort: write a panic.log next to the executable.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let path = dir.join("zyphora_panic.log");
                let _ = std::fs::write(&path, format!("PANIC at {location}\n{payload}\n"));
            }
        }
    }));

    // Reachable-from-main anchor: never executes at runtime but keeps every
    // `ensure_used_*` function in the live-code set.
    if std::env::var_os("IDA_GUI__NEVER_TRUE").is_some() {
        ensure_used::touch_all();
    }

    // ── DirectComposition workaround ──────────────────────────────────────────
    // GPUI's default DirectComposition mode renders a transparent/invisible
    // window on some Windows configs (Intel Iris Xe, Windows 10).
    // Disable it unless the user explicitly opts in.
    if std::env::var("GPUI_FORCE_DIRECT_COMPOSITION").is_err() {
        unsafe { std::env::set_var("GPUI_DISABLE_DIRECT_COMPOSITION", "1") };
    }

    // ── CPU fallback hint ─────────────────────────────────────────────────────
    // When users force CPU rendering on machines with broken GPU drivers, also
    // ask gpui to prefer the llvmpipe software renderer. Mirrors the
    // DirectComposition workaround above.
    if std::env::var_os("IDA_GUI_FORCE_CPU").is_some() {
        unsafe { std::env::set_var("GPUI_PREFER_LLVMPIPE", "1") };
    }

    // ── Logging ───────────────────────────────────────────────────────────────
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("Zyphora Reversing {} starting…", env!("CARGO_PKG_VERSION"));

    // ── CLI parsing ───────────────────────────────────────────────────────────
    // Recognise `--open=<path>` and `--open <path>` so power users can autoload
    // a binary at startup. The parsed value is queued onto the IDAApp and the
    // standard `UICommand::AnalyzeFile` pipeline runs on the first frame.
    let cli_args: Vec<String> = std::env::args().collect();
    eprintln!("[cli] argv = {cli_args:?}");
    log::info!("[cli] argv = {cli_args:?}");
    let autoload_path = parse_open_flag(&cli_args);
    if let Some(p) = &autoload_path {
        eprintln!("[cli] --open requested: {p}");
        log::info!("[cli] --open requested: {p}");
    }

    // ── GPUI application ──────────────────────────────────────────────────────
    let app = gpui_platform::application().with_assets(crate::assets::Assets);
    app.run(move |cx| {
        let app_state = AppState::default();
        let autoload_path = autoload_path.clone();

        let window_options = gpui::WindowOptions {
            window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
                None,
                gpui::Size {
                    width: gpui::px(1280.0),
                    height: gpui::px(780.0),
                },
                cx,
            ))),
            titlebar: Some(gpui::TitlebarOptions {
                title: Some("Zyphora Reversing".into()),
                appears_transparent: false,
                traffic_light_position: None,
            }),
            focus: true,
            show: true,
            kind: gpui::WindowKind::Normal,
            is_movable: true,
            display_id: None,
            // Enforce a sensible lower bound so the responsive layout always
            // has at least the toolbar + a usable center pane visible.
            window_min_size: Some(gpui::Size {
                width: gpui::px(640.0),
                height: gpui::px(420.0),
            }),
            window_background: gpui::WindowBackgroundAppearance::Opaque,
            ..Default::default()
        };

        cx.open_window(window_options, |_, cx| {
            cx.new(|cx| match autoload_path.clone() {
                None => IDAApp::new(app_state, cx),
                Some(path) => IDAApp::new_with_autoload(app_state, cx, Some(path)),
            })
        })
        .expect("Failed to open window");

        cx.activate(true);
    });
}

/// Parse `--open=<path>` and `--open <path>` from a borrowed argv. Returns the
/// last occurrence so the most recently supplied value wins (matches the
/// behavior of typical CLI tools).
fn parse_open_flag(args: &[String]) -> Option<String> {
    let mut out: Option<String> = None;
    let mut iter = args.iter().enumerate().skip(1);
    while let Some((_, arg)) = iter.next() {
        if let Some(rest) = arg.strip_prefix("--open=") {
            if !rest.is_empty() {
                out = Some(rest.to_owned());
            }
        } else if arg == "--open" {
            if let Some((_, next)) = iter.next() {
                if !next.is_empty() {
                    out = Some(next.clone());
                }
            }
        }
    }
    out
}
