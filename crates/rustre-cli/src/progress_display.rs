//! `progress_display` — Progress bars, spinners, and status indicators.
//!
//! Multi-bar layouts, ETA calculation, throughput display, nested progress,
//! and log integration for long-running analysis operations.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self};
use std::time::{Duration, Instant};

// ── Units ─────────────────────────────────────────────────────────────────────

/// Human-readable size/throughput formatting.
#[must_use]
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = n as f64;
    let mut unit_idx = 0;
    while val >= 1024.0 && unit_idx + 1 < UNITS.len() {
        val /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 { format!("{n} B") } else { format!("{val:.1} {}", UNITS[unit_idx]) }
}

/// Format a `Duration` as `HH:MM:SS` or `MM:SS` or `<1s`.
#[must_use]
pub fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m{:02}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Format a throughput value.
#[must_use]
pub fn fmt_throughput(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 { format!("{bytes_per_sec:.0} B/s") }
    else if bytes_per_sec < 1024.0 * 1024.0 { format!("{:.1} KiB/s", bytes_per_sec / 1024.0) }
    else { format!("{:.1} MiB/s", bytes_per_sec / (1024.0 * 1024.0)) }
}

// ── Progress bar style ────────────────────────────────────────────────────────

/// Style configuration for a progress bar.
#[derive(Debug, Clone)]
pub struct BarStyle {
    /// Width of the bar in characters.
    pub width: usize,
    /// Character for filled portion.
    pub fill: char,
    /// Character for empty portion.
    pub empty: char,
    /// Left cap.
    pub left_cap: char,
    /// Right cap.
    pub right_cap: char,
    /// Whether to show the percentage.
    pub show_pct: bool,
    /// Whether to show elapsed time.
    pub show_elapsed: bool,
    /// Whether to show ETA.
    pub show_eta: bool,
    /// Whether to show throughput.
    pub show_throughput: bool,
    /// Whether to use ANSI colour.
    pub color: bool,
}

impl Default for BarStyle {
    fn default() -> Self {
        Self {
            width: 40,
            fill: '#',
            empty: '-',
            left_cap: '[',
            right_cap: ']',
            show_pct: true,
            show_elapsed: true,
            show_eta: true,
            show_throughput: false,
            color: true,
        }
    }
}

impl BarStyle {
    /// Braille spinner style (no fill chars, uses spinner frames).
    #[must_use]
    pub fn braille() -> Self {
        Self { width: 0, ..Self::default() }
    }

    /// Unicode block bar.
    #[must_use]
    pub fn blocks() -> Self {
        Self { fill: '█', empty: '░', ..Self::default() }
    }

    /// Minimal ASCII bar.
    #[must_use]
    pub fn ascii() -> Self {
        Self { fill: '=', empty: ' ', left_cap: '|', right_cap: '|', color: false, ..Self::default() }
    }
}

// ── Core progress bar ─────────────────────────────────────────────────────────

/// A single progress bar tracking completion of a task.
pub struct ProgressBar {
    /// Descriptive label.
    pub label: String,
    /// Total work units (0 = indeterminate).
    pub total: u64,
    /// Current work units.
    current: u64,
    /// Bar style.
    style: BarStyle,
    /// When the bar was created.
    start: Instant,
    /// Whether the bar is finished.
    finished: bool,
    /// Optional unit string (e.g. "files", "bytes").
    pub unit: String,
    /// Bytes processed (for throughput).
    bytes_processed: u64,
    /// Sample window for throughput smoothing.
    sample_window: VecDeque<(Instant, u64)>,
    /// Maximum throughput samples.
    window_size: usize,
}

impl ProgressBar {
    /// Create a determinate progress bar.
    #[must_use]
    pub fn new(label: impl Into<String>, total: u64) -> Self {
        Self {
            label: label.into(),
            total,
            current: 0,
            style: BarStyle::default(),
            start: Instant::now(),
            finished: false,
            unit: "items".into(),
            bytes_processed: 0,
            sample_window: VecDeque::new(),
            window_size: 20,
        }
    }

    /// Create an indeterminate spinner.
    #[must_use]
    pub fn spinner(label: impl Into<String>) -> Self {
        let mut bar = Self::new(label, 0);
        bar.style = BarStyle::braille();
        bar
    }

    /// Set the style.
    #[must_use]
    pub const fn with_style(mut self, style: BarStyle) -> Self { self.style = style; self }

    /// Set the unit name.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self { self.unit = unit.into(); self }

    /// Advance by `n` units.
    pub fn advance(&mut self, n: u64) {
        self.current = self.current.saturating_add(n).min(self.total.max(self.current + n));
        let now = Instant::now();
        self.sample_window.push_back((now, self.current));
        while self.sample_window.len() > self.window_size { self.sample_window.pop_front(); }
    }

    /// Advance bytes (for throughput calculation).
    pub fn advance_bytes(&mut self, n: u64) {
        self.bytes_processed = self.bytes_processed.saturating_add(n);
        self.advance(n);
    }

    /// Set absolute progress.
    pub fn set(&mut self, n: u64) {
        let delta = n.saturating_sub(self.current);
        self.advance(delta);
    }

    /// Mark the bar as finished.
    pub const fn finish(&mut self) {
        if self.total > 0 { self.current = self.total; }
        self.finished = true;
    }

    /// Mark the bar as finished with a message.
    pub fn finish_with_message(&mut self, msg: &str, out: &mut dyn io::Write) {
        self.finish();
        let rendered = self.render();
        let _ = writeln!(out, "\r{rendered}  {msg}");
    }

    /// Elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration { self.start.elapsed() }

    /// Fraction complete in [0.0, 1.0].
    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 { 0.0 }
        else { (self.current as f64 / self.total as f64).min(1.0) }
    }

    /// Estimated time to completion.
    #[must_use]
    pub fn eta(&self) -> Option<Duration> {
        if self.total == 0 || self.current == 0 { return None; }
        let frac = self.fraction();
        if frac >= 1.0 { return Some(Duration::ZERO); }
        let elapsed = self.elapsed().as_secs_f64();
        let total_est = elapsed / frac;
        let remaining = total_est - elapsed;
        Some(Duration::from_secs_f64(remaining.max(0.0)))
    }

    /// Smoothed throughput (units/second) over the sample window.
    #[must_use]
    pub fn throughput(&self) -> f64 {
        if self.sample_window.len() < 2 { return 0.0; }
        let (t0, v0) = self.sample_window.front().unwrap();
        let (t1, v1) = self.sample_window.back().unwrap();
        let dt = t1.duration_since(*t0).as_secs_f64();
        if dt < 1e-6 { return 0.0; }
        (v1.saturating_sub(*v0)) as f64 / dt
    }

    /// Render the bar to a string for writing.
    #[must_use]
    pub fn render(&self) -> String {
        let c = |code: &'static str| if self.style.color { code } else { "" };
        let mut out = String::new();

        // Label.
        out.push_str(&format!("  {}{:<32}{} ", c("\x1b[1m"), truncate_label(&self.label, 32), c("\x1b[0m")));

        // Bar body.
        if self.style.width > 0 {
            let filled = (self.fraction() * self.style.width as f64) as usize;
            let empty = self.style.width - filled;
            let bar_color = if self.finished { c("\x1b[32m") } else { c("\x1b[36m") };
            out.push_str(&format!("{bar_color}{}", self.style.left_cap));
            for _ in 0..filled { out.push(self.style.fill); }
            for _ in 0..empty  { out.push(self.style.empty); }
            out.push(self.style.right_cap);
            out.push_str(c("\x1b[0m"));
            out.push(' ');
        }

        // Percentage.
        if self.style.show_pct {
            if self.total > 0 {
                out.push_str(&format!("{:3.0}% ", self.fraction() * 100.0));
            } else {
                out.push_str("  ?% ");
            }
        }

        // Counts.
        if self.total > 0 {
            out.push_str(&format!("{}/{} {} ", self.current, self.total, self.unit));
        }

        // Elapsed.
        if self.style.show_elapsed {
            out.push_str(&format!("[{}]", fmt_duration(self.elapsed())));
        }

        // ETA.
        if self.style.show_eta && !self.finished
            && let Some(eta) = self.eta() {
                out.push_str(&format!(" ETA {}", fmt_duration(eta)));
            }

        // Throughput.
        if self.style.show_throughput {
            let tp = self.throughput();
            if tp > 0.0 {
                out.push_str(&format!(" {}", fmt_throughput(tp)));
            }
        }

        out
    }

    /// Write a carriage-return-prefixed render to `w`.
    pub fn draw(&self, w: &mut dyn io::Write) {
        let rendered = self.render();
        let _ = write!(w, "\r{rendered}");
        let _ = w.flush();
    }

    /// Write a final newline.
    pub fn erase(&self, w: &mut dyn io::Write) {
        let _ = writeln!(w);
    }
}

fn truncate_label(s: &str, max: usize) -> String {
    // Two bugs lived here: `&s[..max - 1]` panics when the cut lands inside a
    // multi-byte character (symbol names and strings pulled out of binaries are
    // routinely non-ASCII), and `max - 1` underflows when `max` is 0. Counting
    // characters also matches the `{:<max$}` padding below, which pads by
    // character count, not by byte length.
    if s.chars().count() <= max {
        format!("{s:<max$}")
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

// ── Spinner ───────────────────────────────────────────────────────────────────

const BRAILLE_FRAMES: &[&str] = &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];
const ASCII_FRAMES:   &[&str] = &["-", "\\", "|", "/"];
const DOTS_FRAMES:    &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BOX_FRAMES:     &[&str] = &["▖", "▘", "▝", "▗"];

/// Spinner animation style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinnerStyle { Braille, Ascii, Dots, Box }

impl SpinnerStyle {
    #[must_use]
    pub const fn frames(self) -> &'static [&'static str] {
        match self {
            Self::Braille => BRAILLE_FRAMES,
            Self::Ascii   => ASCII_FRAMES,
            Self::Dots    => DOTS_FRAMES,
            Self::Box     => BOX_FRAMES,
        }
    }
}

/// A single spinner.
pub struct Spinner {
    pub label: String,
    style: SpinnerStyle,
    frame: usize,
    start: Instant,
    pub color: bool,
    pub suffix: String,
}

impl Spinner {
    /// Create a spinner.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            style: SpinnerStyle::Braille,
            frame: 0,
            start: Instant::now(),
            color: true,
            suffix: String::new(),
        }
    }

    /// Set the spinner style.
    #[must_use]
    pub const fn with_style(mut self, style: SpinnerStyle) -> Self { self.style = style; self }

    /// Advance by one frame and draw to `w`.
    pub fn tick(&mut self, w: &mut dyn io::Write) {
        let frames = self.style.frames();
        let frame = frames[self.frame % frames.len()];
        self.frame = self.frame.wrapping_add(1);
        let elapsed = fmt_duration(self.start.elapsed());
        let c = |code: &'static str| if self.color { code } else { "" };
        let suffix = if self.suffix.is_empty() { String::new() } else { format!(" — {}", self.suffix) };
        let _ = write!(w, "\r  {}{}{} {}{} [{}]",
            c("\x1b[36m"), frame, c("\x1b[0m"),
            self.label, suffix, elapsed,
        );
        let _ = w.flush();
    }

    /// Mark the spinner as done.
    pub fn finish(&self, ok: bool, w: &mut dyn io::Write) {
        let c = |code: &'static str| if self.color { code } else { "" };
        let mark = if ok { format!("{}✓{}", c("\x1b[32m"), c("\x1b[0m")) }
                   else  { format!("{}✗{}", c("\x1b[31m"), c("\x1b[0m")) };
        let elapsed = fmt_duration(self.start.elapsed());
        let _ = writeln!(w, "\r  {mark} {} [{}]", self.label, elapsed);
    }

    /// Elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration { self.start.elapsed() }
}

// ── Multi-bar layout ──────────────────────────────────────────────────────────

/// A set of progress bars rendered in a multi-line block.
pub struct MultiBar {
    bars: Vec<ProgressBar>,
    label: String,
    start: Instant,
    color: bool,
}

impl MultiBar {
    /// Create a multi-bar with a group label.
    #[must_use]
    pub fn new(label: impl Into<String>, color: bool) -> Self {
        Self { bars: Vec::new(), label: label.into(), start: Instant::now(), color }
    }

    /// Add a bar and return its index.
    pub fn add(&mut self, bar: ProgressBar) -> usize {
        let idx = self.bars.len();
        self.bars.push(bar);
        idx
    }

    /// Get a mutable reference to a bar by index.
    #[must_use]
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut ProgressBar> {
        self.bars.get_mut(idx)
    }

    /// Draw all bars, using ANSI cursor-up to overwrite previous renders.
    pub fn draw_all(&self, w: &mut dyn io::Write) {
        let c = |code: &'static str| if self.color { code } else { "" };
        // Move cursor up by the number of bars + 1 header.
        if !self.bars.is_empty() {
            let _ = write!(w, "\x1b[{}A", self.bars.len() + 1);
        }
        let elapsed = fmt_duration(self.start.elapsed());
        let done: usize = self.bars.iter().filter(|b| b.finished).count();
        let _ = writeln!(w, "{}{}  {} — {}/{} done [{}]{}{}",
            c("\x1b[1m"), c("\x1b[35m"), self.label, done, self.bars.len(), elapsed,
            c("\x1b[0m"), c("\x1b[0m"),
        );
        for bar in &self.bars {
            let _ = writeln!(w, "{}", bar.render());
        }
        let _ = w.flush();
    }

    /// Print initial empty rows so future `draw_all` has room.
    pub fn init(&self, w: &mut dyn io::Write) {
        for _ in 0..=self.bars.len() {
            let _ = writeln!(w);
        }
    }

    /// Return `true` if all bars are finished.
    #[must_use]
    pub fn all_done(&self) -> bool {
        self.bars.iter().all(|b| b.finished)
    }

    /// Overall completion fraction.
    #[must_use]
    pub fn overall_fraction(&self) -> f64 {
        if self.bars.is_empty() { return 1.0; }
        let sum: f64 = self.bars.iter().map(ProgressBar::fraction).sum();
        sum / self.bars.len() as f64
    }

    /// Elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration { self.start.elapsed() }
}

// ── Log line integration ──────────────────────────────────────────────────────

/// Severity of a log message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel { Trace, Debug, Info, Warn, Error }

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => f.write_str("TRACE"),
            Self::Debug => f.write_str("DEBUG"),
            Self::Info  => f.write_str("INFO "),
            Self::Warn  => f.write_str("WARN "),
            Self::Error => f.write_str("ERROR"),
        }
    }
}

/// A log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub timestamp_ms: u64,
    pub source: Option<String>,
}

/// A progress-aware log sink that buffers messages.
pub struct ProgressLogger {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
    min_level: LogLevel,
    color: bool,
    start: Instant,
}

impl ProgressLogger {
    /// Create a logger with the given buffer capacity.
    #[must_use]
    pub fn new(max_entries: usize, min_level: LogLevel, color: bool) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
            min_level,
            color,
            start: Instant::now(),
        }
    }

    /// Log a message.
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>, source: Option<String>) {
        if level < self.min_level { return; }
        let ts = self.start.elapsed().as_millis() as u64;
        if self.entries.len() >= self.max_entries { self.entries.pop_front(); }
        self.entries.push_back(LogEntry { level, message: message.into(), timestamp_ms: ts, source });
    }

    /// Convenience methods.
    pub fn info(&mut self, msg: impl Into<String>)  { self.log(LogLevel::Info,  msg, None); }
    pub fn warn(&mut self, msg: impl Into<String>)  { self.log(LogLevel::Warn,  msg, None); }
    pub fn error(&mut self, msg: impl Into<String>) { self.log(LogLevel::Error, msg, None); }
    pub fn debug(&mut self, msg: impl Into<String>) { self.log(LogLevel::Debug, msg, None); }

    /// Flush all buffered entries to `w`.
    pub fn flush(&mut self, w: &mut dyn io::Write) {
        let c = |code: &'static str| if self.color { code } else { "" };
        for e in self.entries.drain(..) {
            let level_color = match e.level {
                LogLevel::Trace | LogLevel::Debug => c("\x1b[2m"),
                LogLevel::Info  => c("\x1b[36m"),
                LogLevel::Warn  => c("\x1b[33m"),
                LogLevel::Error => c("\x1b[31m"),
            };
            let source = e.source.as_deref().unwrap_or("");
            let src_part = if source.is_empty() { String::new() } else { format!(" [{source}]") };
            let _ = writeln!(w, "  {level_color}{}{}{} +{}ms{}{} {}",
                c("\x1b[1m"), e.level, c("\x1b[0m"),
                e.timestamp_ms, level_color, src_part, e.message,
            );
        }
        let _ = w.flush();
    }

    /// Number of buffered entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Entries at or above `level`.
    #[must_use]
    pub fn entries_at_level(&self, level: LogLevel) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.level >= level).collect()
    }
}

// ── Status indicator ──────────────────────────────────────────────────────────

/// A simple named status indicator (used in dashboards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusIndicator {
    Ok,
    Warning(String),
    Error(String),
    Running(String),
    Pending,
}

impl fmt::Display for StatusIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok             => f.write_str("ok"),
            Self::Warning(msg)   => write!(f, "warn: {msg}"),
            Self::Error(msg)     => write!(f, "error: {msg}"),
            Self::Running(phase) => write!(f, "running: {phase}"),
            Self::Pending        => f.write_str("pending"),
        }
    }
}

/// A dashboard of named status indicators.
pub struct StatusDashboard {
    items: Vec<(String, StatusIndicator)>,
    color: bool,
    start: Instant,
}

impl StatusDashboard {
    /// Create a new dashboard.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self { items: Vec::new(), color, start: Instant::now() }
    }

    /// Add or update a status item.
    pub fn set(&mut self, name: impl Into<String>, status: StatusIndicator) {
        let name = name.into();
        if let Some(item) = self.items.iter_mut().find(|(n, _)| n == &name) {
            item.1 = status;
        } else {
            self.items.push((name, status));
        }
    }

    /// Print the dashboard to `w`.
    pub fn print(&self, w: &mut dyn io::Write) {
        let c = |code: &'static str| if self.color { code } else { "" };
        let elapsed = fmt_duration(self.start.elapsed());
        let _ = writeln!(w, "\n{}{}  Status Dashboard [{}]{}{}",
            c("\x1b[1m"), c("\x1b[35m"), elapsed, c("\x1b[0m"), c("\x1b[0m"),
        );
        for (name, status) in &self.items {
            let (marker, color) = match status {
                StatusIndicator::Ok           => ("✓", c("\x1b[32m")),
                StatusIndicator::Warning(_)   => ("!", c("\x1b[33m")),
                StatusIndicator::Error(_)     => ("✗", c("\x1b[31m")),
                StatusIndicator::Running(_)   => ("►", c("\x1b[36m")),
                StatusIndicator::Pending      => ("·", c("\x1b[2m")),
            };
            let _ = writeln!(w, "  {color}{marker}{} {:<24} {}",
                c("\x1b[0m"), name, status,
            );
        }
    }

    /// Return the number of items with `Error` status.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.items.iter().filter(|(_, s)| matches!(s, StatusIndicator::Error(_))).count()
    }

    /// Return the number of items with `Ok` status.
    #[must_use]
    pub fn ok_count(&self) -> usize {
        self.items.iter().filter(|(_, s)| matches!(s, StatusIndicator::Ok)).count()
    }
}

// ── Nested progress ───────────────────────────────────────────────────────────

/// A task with a parent/child nesting structure.
pub struct TaskTree {
    pub name: String,
    pub total: u64,
    pub current: u64,
    pub children: Vec<Self>,
    pub finished: bool,
    pub start: Instant,
}

impl TaskTree {
    /// Create a new task.
    #[must_use]
    pub fn new(name: impl Into<String>, total: u64) -> Self {
        Self { name: name.into(), total, current: 0, children: Vec::new(), finished: false, start: Instant::now() }
    }

    /// Add a child task.
    pub fn add_child(&mut self, child: Self) {
        self.children.push(child);
    }

    /// Advance by `n` units.
    pub fn advance(&mut self, n: u64) {
        self.current = self.current.saturating_add(n).min(self.total.max(self.current + n));
    }

    /// Mark finished.
    pub fn finish(&mut self) {
        if self.total > 0 { self.current = self.total; }
        self.finished = true;
        for child in &mut self.children { child.finish(); }
    }

    /// Fraction (considers children).
    #[must_use]
    pub fn fraction(&self) -> f64 {
        let own = if self.total == 0 { 0.0 } else { (self.current as f64 / self.total as f64).min(1.0) };
        if self.children.is_empty() { return own; }
        let child_avg: f64 = self.children.iter().map(Self::fraction).sum::<f64>() / self.children.len() as f64;
        f64::midpoint(own, child_avg)
    }

    /// Render the tree to `w` with indentation.
    pub fn print_tree(&self, w: &mut dyn io::Write, depth: usize, color: bool) {
        let c = |code: &'static str| if color { code } else { "" };
        let indent = "  ".repeat(depth);
        let pct = (self.fraction() * 100.0) as u32;
        let elapsed = fmt_duration(self.start.elapsed());
        let finished_mark = if self.finished { format!("{}✓{}", c("\x1b[32m"), c("\x1b[0m")) } else { " ".into() };
        let _ = writeln!(w, "{indent}{finished_mark} {}{:<32}{} {:3}% [{}]",
            c("\x1b[1m"), truncate_label(&self.name, 32), c("\x1b[0m"), pct, elapsed,
        );
        for child in &self.children {
            child.print_tree(w, depth + 1, color);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_bytes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn test_fmt_duration() {
        assert_eq!(fmt_duration(Duration::from_secs(5)), "5s");
        assert_eq!(fmt_duration(Duration::from_secs(65)), "1m05s");
        assert_eq!(fmt_duration(Duration::from_secs(3661)), "1h01m01s");
    }

    #[test]
    fn test_progress_fraction() {
        let mut p = ProgressBar::new("test", 100);
        assert!((p.fraction()).abs() < f64::EPSILON);
        p.advance(50);
        assert!((p.fraction() - 0.5).abs() < f64::EPSILON);
        p.advance(50);
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_advance_bytes() {
        let mut p = ProgressBar::new("bytes", 1024).with_unit("bytes");
        p.advance_bytes(512);
        assert_eq!(p.bytes_processed, 512);
        assert!((p.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_eta_none_when_zero() {
        let p = ProgressBar::new("test", 100);
        assert_eq!(p.eta(), None);
    }

    #[test]
    fn test_progress_eta_some() {
        let mut p = ProgressBar::new("test", 100);
        p.advance(50);
        // ETA should be Some (nonzero work done).
        assert!(p.eta().is_some());
    }

    #[test]
    fn test_progress_render() {
        let mut p = ProgressBar::new("analyzing", 100).with_style(BarStyle::ascii());
        p.advance(30);
        let r = p.render();
        assert!(r.contains("analyzing"));
    }

    #[test]
    fn test_spinner_tick() {
        let mut s = Spinner::new("loading");
        let mut buf = Vec::<u8>::new();
        s.tick(&mut buf);
        s.tick(&mut buf);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_multibar_overall_fraction() {
        let mut mb = MultiBar::new("group", false);
        let mut b1 = ProgressBar::new("task1", 100);
        let mut b2 = ProgressBar::new("task2", 100);
        b1.advance(50);
        b2.advance(100);
        mb.add(b1);
        mb.add(b2);
        let frac = mb.overall_fraction();
        assert!((frac - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_multibar_all_done() {
        let mut mb = MultiBar::new("group", false);
        let mut b = ProgressBar::new("t", 10);
        b.finish();
        mb.add(b);
        assert!(mb.all_done());
    }

    #[test]
    fn test_progress_logger_flush() {
        let mut log = ProgressLogger::new(100, LogLevel::Debug, false);
        log.info("hello");
        log.warn("watch out");
        log.error("boom");
        assert_eq!(log.len(), 3);
        let mut buf = Vec::<u8>::new();
        log.flush(&mut buf);
        assert_eq!(log.len(), 0);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("hello"));
        assert!(out.contains("boom"));
    }

    #[test]
    fn test_progress_logger_level_filter() {
        let mut log = ProgressLogger::new(100, LogLevel::Warn, false);
        log.debug("ignored");
        log.warn("kept");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_status_dashboard() {
        let mut dash = StatusDashboard::new(false);
        dash.set("loader", StatusIndicator::Ok);
        dash.set("disasm", StatusIndicator::Running("pass 1".into()));
        dash.set("export", StatusIndicator::Error("disk full".into()));
        assert_eq!(dash.ok_count(), 1);
        assert_eq!(dash.error_count(), 1);
    }

    #[test]
    fn test_task_tree_fraction() {
        let mut root = TaskTree::new("root", 100);
        root.advance(50);
        let mut child = TaskTree::new("child", 100);
        child.advance(100);
        root.add_child(child);
        let frac = root.fraction();
        assert!(frac > 0.5);
    }

    #[test]
    fn test_bar_style_variants() {
        let _ascii = BarStyle::ascii();
        let _blocks = BarStyle::blocks();
        let _braille = BarStyle::braille();
    }

    #[test]
    fn test_fmt_throughput() {
        let s = fmt_throughput(500.0);
        assert!(s.contains("B/s"));
        let s = fmt_throughput(2048.0);
        assert!(s.contains("KiB/s"));
        let s = fmt_throughput(2.0 * 1024.0 * 1024.0);
        assert!(s.contains("MiB/s"));
    }
}
