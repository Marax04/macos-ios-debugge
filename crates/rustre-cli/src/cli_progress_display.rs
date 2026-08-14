//! CLI progress display: progress bars and spinners.
//!
//! This module provides two visual feedback primitives for long-running
//! CLI operations:
//!
//! * [`ProgressBar`] – a classic `[####----]` percentage bar written to stderr.
//! * [`Spinner`] – an animated spinner (configurable character set) for tasks
//!   where progress cannot be measured.
//!
//! Both types support a quiet mode that suppresses all output, making it easy
//! to honour `--quiet` flags without littering callers with `if !quiet` guards.
//!
//! All writes go to **stderr** so they do not pollute stdout pipelines.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

// ── SpinnerKind ───────────────────────────────────────────────────────────────

/// Character sets for the animated spinner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpinnerKind {
    /// Classic `|/-\` rotation.
    #[default]
    Classic,
    /// Braille dot patterns: `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`.
    Braille,
    /// Trailing dots: `.  `, `.. `, `...`, cycling.
    Dots,
    /// Growing/shrinking bar: `▏▎▍▌▋▊▉█▉▊▋▌▍▎▏`.
    Block,
    /// Simple arrow rotation: `← ↖ ↑ ↗ → ↘ ↓ ↙`.
    Arrow,
}

impl SpinnerKind {
    /// Return the frames for this spinner kind.
    #[must_use]
    pub const fn frames(self) -> &'static [&'static str] {
        match self {
            Self::Classic => &["|", "/", "-", "\\"],
            Self::Braille => &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            Self::Dots => &[".  ", ".. ", "...", "   "],
            Self::Block => &["▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"],
            Self::Arrow => &["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
        }
    }

    /// Number of frames.
    #[must_use]
    pub const fn frame_count(self) -> usize {
        self.frames().len()
    }
}

impl fmt::Display for SpinnerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Classic => "classic",
            Self::Braille => "braille",
            Self::Dots => "dots",
            Self::Block => "block",
            Self::Arrow => "arrow",
        };
        f.write_str(name)
    }
}

// ── ProgressConfig ────────────────────────────────────────────────────────────

/// Configuration shared by both [`ProgressBar`] and [`Spinner`].
#[derive(Debug, Clone)]
pub struct ProgressConfig {
    /// Suppress all output.
    pub quiet: bool,
    /// Show elapsed time in the suffix.
    pub show_elapsed: bool,
    /// Show rate (units/s) in the suffix.
    pub show_rate: bool,
    /// Suffix label appended after the bar/spinner (e.g. `"functions"`).
    pub unit: String,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            quiet: false,
            show_elapsed: true,
            show_rate: false,
            unit: String::new(),
        }
    }
}

// ── ProgressBar ───────────────────────────────────────────────────────────────

/// An ASCII progress bar rendered on a single stderr line using `\r`.
///
/// The bar is rendered as:
/// ```text
/// label: [########--------]  50% (500/1000)  2.3s
/// ```
pub struct ProgressBar {
    label: String,
    total: u64,
    current: u64,
    width: usize,
    start: Instant,
    config: ProgressConfig,
}

impl ProgressBar {
    /// Create a new progress bar.
    #[must_use]
    pub fn new(label: impl Into<String>, total: u64) -> Self {
        Self {
            label: label.into(),
            total,
            current: 0,
            width: 40,
            start: Instant::now(),
            config: ProgressConfig::default(),
        }
    }

    /// Set the bar width in characters (default: 40).
    #[must_use]
    pub const fn with_width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Enable or disable quiet mode.
    #[must_use]
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.config.quiet = quiet;
        self
    }

    /// Set the unit label (e.g. `"bytes"`, `"instructions"`).
    #[must_use]
    pub fn unit(mut self, unit: impl Into<String>) -> Self {
        self.config.unit = unit.into();
        self
    }

    /// Apply a full [`ProgressConfig`].
    #[must_use]
    pub fn with_config(mut self, config: ProgressConfig) -> Self {
        self.config = config;
        self
    }

    /// Return the total step count.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Return the current step count.
    #[must_use]
    pub const fn current(&self) -> u64 {
        self.current
    }

    /// Return the completion fraction in `[0.0, 1.0]`.
    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.current as f64) / (self.total as f64)
        }
    }

    /// Return elapsed time since creation.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Advance the bar by `n` steps (clamped to total).
    pub fn advance(&mut self, n: u64) {
        self.current = self.current.saturating_add(n).min(self.total);
        self.draw();
    }

    /// Set the current step to `n` (clamped to total).
    pub fn set(&mut self, n: u64) {
        self.current = n.min(self.total);
        self.draw();
    }

    /// Mark the bar as finished and print a trailing newline.
    pub fn finish(&mut self) {
        self.current = self.total;
        self.draw();
        if !self.config.quiet {
            let _ = writeln!(io::stderr());
        }
    }

    /// Mark the bar as finished with a custom message on a new line.
    pub fn finish_with_message(&mut self, msg: &str) {
        self.finish();
        if !self.config.quiet {
            eprintln!("{msg}");
        }
    }

    /// Render to a `String` without printing (useful for testing).
    #[must_use]
    pub fn render_string(&self) -> String {
        let frac = self.fraction();
        let filled = ((frac * self.width as f64) as usize).min(self.width);
        let bar: String = std::iter::repeat_n('#', filled)
            .chain(std::iter::repeat_n('-', self.width - filled))
            .collect();
        let pct = (frac * 100.0) as u32;
        let elapsed = self.start.elapsed().as_secs_f32();
        let mut s = format!(
            "{}: [{bar}] {pct:3}% ({}/{})",
            self.label, self.current, self.total
        );
        if self.config.show_elapsed {
            s.push_str(&format!("  {elapsed:.1}s"));
        }
        if !self.config.unit.is_empty() {
            s.push(' ');
            s.push_str(&self.config.unit);
        }
        s
    }

    fn draw(&self) {
        if self.config.quiet {
            return;
        }
        let rendered = self.render_string();
        let _ = write!(io::stderr(), "\r{rendered}");
        let _ = io::stderr().flush();
    }
}

// ── Spinner ───────────────────────────────────────────────────────────────────

/// An animated spinner for tasks where progress cannot be measured.
///
/// The display is:
/// ```text
/// ⠹ Analysing binary...  1.4s
/// ```
///
/// Call [`Spinner::tick`] periodically (e.g. every 100 ms) to advance the frame.
pub struct Spinner {
    label: String,
    kind: SpinnerKind,
    frame: usize,
    start: Instant,
    config: ProgressConfig,
    done: bool,
}

impl Spinner {
    /// Create a new spinner.
    #[must_use]
    pub fn new(label: impl Into<String>, kind: SpinnerKind) -> Self {
        Self {
            label: label.into(),
            kind,
            frame: 0,
            start: Instant::now(),
            config: ProgressConfig::default(),
            done: false,
        }
    }

    /// Create a classic `|/-\` spinner.
    #[must_use]
    pub fn classic(label: impl Into<String>) -> Self {
        Self::new(label, SpinnerKind::Classic)
    }

    /// Create a braille spinner.
    #[must_use]
    pub fn braille(label: impl Into<String>) -> Self {
        Self::new(label, SpinnerKind::Braille)
    }

    /// Enable or disable quiet mode.
    #[must_use]
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.config.quiet = quiet;
        self
    }

    /// Set the spinner's label.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }

    /// Advance the spinner by one frame and redraw.
    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % self.kind.frame_count();
        self.draw();
    }

    /// Return the current frame string without printing.
    #[must_use]
    pub fn render_string(&self) -> String {
        let frames = self.kind.frames();
        let frame = frames[self.frame % frames.len()];
        let elapsed = self.start.elapsed().as_secs_f32();
        if self.config.show_elapsed {
            format!("{frame} {}  {elapsed:.1}s", self.label)
        } else {
            format!("{frame} {}", self.label)
        }
    }

    /// Return elapsed time since creation.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Stop the spinner and print a completion message.
    pub fn finish(&mut self, message: &str) {
        self.done = true;
        if !self.config.quiet {
            let _ = writeln!(io::stderr(), "\r{message}");
        }
    }

    /// Stop without printing anything extra.
    pub fn finish_silent(&mut self) {
        self.done = true;
        if !self.config.quiet {
            let _ = writeln!(io::stderr());
        }
    }

    fn draw(&self) {
        if self.config.quiet || self.done {
            return;
        }
        let rendered = self.render_string();
        let _ = write!(io::stderr(), "\r{rendered}");
        let _ = io::stderr().flush();
    }
}

// ── CliProgressDisplay ────────────────────────────────────────────────────────

/// High-level progress display manager.
///
/// Owns a progress bar or spinner and provides a simplified API for common
/// patterns (e.g. multi-step operations with labelled phases).
pub struct CliProgressDisplay {
    bar: Option<ProgressBar>,
    spinner: Option<Spinner>,
    quiet: bool,
    phase: String,
    phase_start: Instant,
    phases_completed: Vec<(String, Duration)>,
}

impl CliProgressDisplay {
    /// Create a display backed by a progress bar.
    #[must_use]
    pub fn with_bar(label: impl Into<String>, total: u64, quiet: bool) -> Self {
        Self {
            bar: Some(ProgressBar::new(label, total).quiet(quiet)),
            spinner: None,
            quiet,
            phase: String::new(),
            phase_start: Instant::now(),
            phases_completed: Vec::new(),
        }
    }

    /// Create a display backed by a spinner.
    #[must_use]
    pub fn with_spinner(label: impl Into<String>, kind: SpinnerKind, quiet: bool) -> Self {
        Self {
            bar: None,
            spinner: Some(Spinner::new(label, kind).quiet(quiet)),
            quiet,
            phase: String::new(),
            phase_start: Instant::now(),
            phases_completed: Vec::new(),
        }
    }

    /// Advance the progress by `n` steps (bar only; no-op for spinner).
    pub fn advance(&mut self, n: u64) {
        if let Some(bar) = &mut self.bar {
            bar.advance(n);
        }
    }

    /// Tick the spinner (spinner only; no-op for bar).
    pub fn tick(&mut self) {
        if let Some(spinner) = &mut self.spinner {
            spinner.tick();
        }
    }

    /// Begin a named phase.
    pub fn begin_phase(&mut self, name: impl Into<String>) {
        if !self.phase.is_empty() {
            let dur = self.phase_start.elapsed();
            let old_phase = std::mem::take(&mut self.phase);
            self.phases_completed.push((old_phase, dur));
        }
        self.phase = name.into();
        self.phase_start = Instant::now();
        if let Some(spinner) = &mut self.spinner {
            spinner.set_label(self.phase.clone());
        }
    }

    /// Finish all progress and print the summary.
    pub fn finish(&mut self) {
        self.begin_phase(""); // flush the current phase
        if let Some(bar) = &mut self.bar {
            bar.finish();
        }
        if let Some(spinner) = &mut self.spinner {
            spinner.finish_silent();
        }
        self.print_summary();
    }

    /// Return elapsed time since construction.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.bar
            .as_ref()
            .map(ProgressBar::elapsed)
            .or_else(|| self.spinner.as_ref().map(Spinner::elapsed))
            .unwrap_or_default()
    }

    /// Return a summary of completed phases.
    #[must_use]
    pub fn phase_summary(&self) -> &[(String, Duration)] {
        &self.phases_completed
    }

    fn print_summary(&self) {
        if self.quiet || self.phases_completed.is_empty() {
            return;
        }
        eprintln!("\nPhase summary:");
        for (name, dur) in &self.phases_completed {
            if !name.is_empty() {
                eprintln!("  {name:<30} {:.2}s", dur.as_secs_f32());
            }
        }
    }
}

// ── update_progress (free function) ──────────────────────────────────────────

/// Update a progress bar or spinner based on a completion fraction `[0.0, 1.0]`.
///
/// For a bar, sets `current = (fraction * total) as u64`.
/// For a spinner, calls `tick()`.
/// Returns the rendered string for the caller to display (or ignore).
#[must_use]
pub fn update_progress(display: &mut CliProgressDisplay, fraction: f64) -> String {
    if let Some(bar) = &mut display.bar {
        let total = bar.total();
        let n = ((fraction.clamp(0.0, 1.0)) * total as f64) as u64;
        bar.set(n);
        bar.render_string()
    } else if let Some(spinner) = &mut display.spinner {
        spinner.tick();
        spinner.render_string()
    } else {
        format!("{:.0}%", fraction * 100.0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar_fraction_zero_total() {
        let bar = ProgressBar::new("test", 0).quiet(true);
        assert!((bar.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_bar_fraction() {
        let mut bar = ProgressBar::new("test", 100).quiet(true);
        bar.advance(25);
        assert!((bar.fraction() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_bar_overadvance() {
        let mut bar = ProgressBar::new("test", 10).quiet(true);
        bar.advance(1000);
        assert_eq!(bar.current(), 10);
        assert!((bar.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_bar_set() {
        let mut bar = ProgressBar::new("test", 100).quiet(true);
        bar.set(73);
        assert_eq!(bar.current(), 73);
    }

    #[test]
    fn test_progress_bar_render_string_contains_label() {
        let bar = ProgressBar::new("loading", 100).quiet(true);
        assert!(bar.render_string().contains("loading"));
    }

    #[test]
    fn test_progress_bar_render_pct() {
        let mut bar = ProgressBar::new("x", 200).quiet(true);
        bar.set(100);
        let s = bar.render_string();
        assert!(s.contains("50%"));
    }

    #[test]
    fn test_progress_bar_render_bar_chars() {
        let mut bar = ProgressBar::new("x", 100).with_width(10).quiet(true);
        bar.set(50);
        let s = bar.render_string();
        assert!(s.contains('['));
        assert!(s.contains(']'));
    }

    #[test]
    fn test_progress_bar_unit() {
        let bar = ProgressBar::new("x", 100).quiet(true).unit("bytes");
        let s = bar.render_string();
        assert!(s.contains("bytes"));
    }

    #[test]
    fn test_spinner_frame_count() {
        assert_eq!(SpinnerKind::Classic.frame_count(), 4);
        assert_eq!(SpinnerKind::Braille.frame_count(), 10);
        assert_eq!(SpinnerKind::Dots.frame_count(), 4);
    }

    #[test]
    fn test_spinner_frames_non_empty() {
        for kind in [
            SpinnerKind::Classic,
            SpinnerKind::Braille,
            SpinnerKind::Dots,
            SpinnerKind::Block,
            SpinnerKind::Arrow,
        ] {
            assert!(!kind.frames().is_empty());
            assert!(kind.frames().iter().all(|f| !f.is_empty()));
        }
    }

    #[test]
    fn test_spinner_tick_advances_frame() {
        let mut s = Spinner::classic("working").quiet(true);
        assert_eq!(s.frame, 0);
        s.tick();
        assert_eq!(s.frame, 1);
    }

    #[test]
    fn test_spinner_wraps_frame() {
        let mut s = Spinner::new("w", SpinnerKind::Classic).quiet(true);
        for _ in 0..100 {
            s.tick();
        }
        assert!(s.frame < SpinnerKind::Classic.frame_count());
    }

    #[test]
    fn test_spinner_render_contains_label() {
        let s = Spinner::classic("parsing").quiet(true);
        assert!(s.render_string().contains("parsing"));
    }

    #[test]
    fn test_spinner_kind_display() {
        assert_eq!(SpinnerKind::Braille.to_string(), "braille");
        assert_eq!(SpinnerKind::Classic.to_string(), "classic");
    }

    #[test]
    fn test_cli_progress_display_bar_advance() {
        let mut d = CliProgressDisplay::with_bar("test", 100, true);
        d.advance(50);
        if let Some(bar) = &d.bar {
            assert_eq!(bar.current(), 50);
        }
    }

    #[test]
    fn test_cli_progress_display_spinner_tick() {
        let mut d = CliProgressDisplay::with_spinner("test", SpinnerKind::Classic, true);
        d.tick();
        if let Some(s) = &d.spinner {
            assert_eq!(s.frame, 1);
        }
    }

    #[test]
    fn test_cli_progress_display_phases() {
        let mut d = CliProgressDisplay::with_bar("test", 100, true);
        d.begin_phase("load");
        d.begin_phase("parse");
        d.begin_phase(""); // flush parse
        // "load" and "parse" are complete; "" is the current/flush phase.
        assert!(d.phase_summary().iter().any(|(n, _)| n == "load"));
        assert!(d.phase_summary().iter().any(|(n, _)| n == "parse"));
    }

    #[test]
    fn test_update_progress_bar() {
        let mut d = CliProgressDisplay::with_bar("test", 1000, true);
        let s = update_progress(&mut d, 0.5);
        assert!(s.contains("50%") || s.contains("500"));
    }

    #[test]
    fn test_update_progress_spinner() {
        let mut d = CliProgressDisplay::with_spinner("test", SpinnerKind::Classic, true);
        let s = update_progress(&mut d, 0.0);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_progress_bar_elapsed_positive() {
        let bar = ProgressBar::new("test", 10).quiet(true);
        // elapsed is >= 0
        assert!(bar.elapsed().as_nanos() < u128::MAX);
    }

    #[test]
    fn test_progress_config_default() {
        let cfg = ProgressConfig::default();
        assert!(!cfg.quiet);
        assert!(cfg.show_elapsed);
        assert!(!cfg.show_rate);
        assert!(cfg.unit.is_empty());
    }
}
