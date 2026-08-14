//! # shell.rs — ADB Shell Execution
//!
//! Provides structured shell command execution over ADB, including:
//!
//! - `ShellSession` — stateful wrapper around an open `shell:` stream
//! - `run_command()` — one-shot command with captured output
//! - `run_command_v2()` — shell v2 protocol with separate stdout/stderr and
//!   proper exit-code capture
//! - Utility functions: `shell_escape()`, `build_shell_command()`
//! - Interactive session scaffolding
//! - Streaming output via `tokio::sync::mpsc`

use std::fmt;
pub use std::time::Duration;

use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::{AdbError, Result, ShellResult};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Shell protocol v2 message IDs.
pub mod v2 {
    /// Data from stdin (host → device).
    pub const STDIN_DATA: u8 = 0;
    /// Data to stdout (device → host).
    pub const STDOUT_DATA: u8 = 1;
    /// Data to stderr (device → host).
    pub const STDERR_DATA: u8 = 2;
    /// Exit code packet (device → host, 4-byte LE int).
    pub const EXIT_CODE: u8 = 3;
    /// Window size change (host → device).
    pub const WINDOW_SIZE_CHANGE: u8 = 4;
    /// Close stdin (host → device).
    pub const CLOSE_STDIN: u8 = 5;
}

/// Default buffer size for reading shell output.
const SHELL_BUF_SIZE: usize = 8192;

// ─── ShellOutput — streaming chunk ───────────────────────────────────────────

/// A chunk of output produced by a streaming shell command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShellOutput {
    /// A line (or partial line) from stdout.
    Stdout(Vec<u8>),
    /// A line (or partial line) from stderr.
    Stderr(Vec<u8>),
    /// The process exited with the given code.
    ExitCode(i32),
}

impl ShellOutput {
    /// Return the stdout bytes if this is a `Stdout` variant.
    #[must_use]
    pub fn as_stdout(&self) -> Option<&[u8]> {
        if let Self::Stdout(b) = self {
            Some(b)
        } else {
            None
        }
    }

    /// Return the stderr bytes if this is a `Stderr` variant.
    #[must_use]
    pub fn as_stderr(&self) -> Option<&[u8]> {
        if let Self::Stderr(b) = self {
            Some(b)
        } else {
            None
        }
    }

    /// Return the exit code if this is an `ExitCode` variant.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        if let Self::ExitCode(c) = self {
            Some(*c)
        } else {
            None
        }
    }
}

// ─── TerminalSize ─────────────────────────────────────────────────────────────

/// Terminal window dimensions for interactive sessions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            x_pixels: 0,
            y_pixels: 0,
        }
    }
}

impl TerminalSize {
    /// Encode as a shell-v2 `WINDOW_SIZE_CHANGE` payload (8 bytes LE).
    #[must_use]
    pub fn encode_v2(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.rows.to_le_bytes());
        buf[2..4].copy_from_slice(&self.cols.to_le_bytes());
        buf[4..6].copy_from_slice(&self.x_pixels.to_le_bytes());
        buf[6..8].copy_from_slice(&self.y_pixels.to_le_bytes());
        buf
    }
}

// ─── Shell escape ─────────────────────────────────────────────────────────────

/// Escape a string for safe inclusion in a POSIX shell command.
///
/// Wraps the string in single quotes and escapes embedded single quotes
/// using the `'...'  \'  '...'` technique.
///
/// ```
/// use rustre_adb::shell::shell_escape;
/// assert_eq!(shell_escape("it's a test"), "'it'\\''s a test'");
/// assert_eq!(shell_escape("hello"), "'hello'");
/// ```
#[must_use]
pub fn shell_escape(s: &str) -> String {
    // Strategy: wrap in single quotes, replace ' with '\''
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Build a complete shell command from a program name and arguments,
/// with all arguments properly escaped.
///
/// ```
/// use rustre_adb::shell::build_shell_command;
/// let cmd = build_shell_command("ls", &["-la", "/sdcard/my files"]);
/// assert!(cmd.contains("ls"));
/// assert!(cmd.contains("'ls'") || cmd.starts_with("ls "));
/// ```
#[must_use]
pub fn build_shell_command(program: &str, args: &[&str]) -> String {
    let mut parts = vec![shell_escape(program)];
    for arg in args {
        parts.push(shell_escape(arg));
    }
    parts.join(" ")
}

/// Build a pipeline of shell commands.
#[must_use]
pub fn build_pipeline(commands: &[&str]) -> String {
    commands.join(" | ")
}

/// Wrap a command in `timeout <secs> <cmd>` for device-side timeout.
#[must_use]
pub fn with_timeout(cmd: &str, secs: u32) -> String {
    format!("timeout {secs} {cmd}")
}

// ─── ShellSession ─────────────────────────────────────────────────────────────

/// A stateful interactive ADB shell session.
///
/// The session wraps a stream that has already been connected to the device's
/// `shell:` service (either v1 or v2).  The caller is responsible for
/// establishing the transport; this struct handles reading/writing.
pub struct ShellSession<S> {
    stream: S,
    use_v2: bool,
    term_size: TerminalSize,
    buf: BytesMut,
}

impl<S> ShellSession<S> {
    /// Return the internal buffered bytes that have been read but not yet
    /// consumed. Useful for diagnostics and tests.
    pub const fn buffered(&self) -> &BytesMut {
        &self.buf
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ShellSession<S> {
    /// Create a shell v1 session (all output merged into stdout).
    pub fn new_v1(stream: S) -> Self {
        Self {
            stream,
            use_v2: false,
            term_size: TerminalSize::default(),
            buf: BytesMut::with_capacity(SHELL_BUF_SIZE),
        }
    }

    /// Create a shell v2 session (separated stdout/stderr, exit code).
    pub fn new_v2(stream: S, term_size: Option<TerminalSize>) -> Self {
        Self {
            stream,
            use_v2: true,
            term_size: term_size.unwrap_or_default(),
            buf: BytesMut::with_capacity(SHELL_BUF_SIZE),
        }
    }

    /// Write bytes to the shell's stdin.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        if self.use_v2 {
            self.write_v2_packet(v2::STDIN_DATA, data).await
        } else {
            self.stream
                .write_all(data)
                .await
                .map_err(AdbError::Connection)
        }
    }

    /// Send an end-of-input signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn close_stdin(&mut self) -> Result<()> {
        if self.use_v2 {
            self.write_v2_packet(v2::CLOSE_STDIN, &[]).await
        } else {
            Ok(()) // v1: just stop writing
        }
    }

    /// Send a window size change.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn resize(&mut self, size: TerminalSize) -> Result<()> {
        self.term_size = size;
        if self.use_v2 {
            self.write_v2_packet(v2::WINDOW_SIZE_CHANGE, &size.encode_v2())
                .await
        } else {
            Ok(())
        }
    }

    /// Read the next chunk of output.  Returns `None` on EOF.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn read_output(&mut self) -> Result<Option<ShellOutput>> {
        if self.use_v2 {
            self.read_v2_packet().await
        } else {
            self.read_v1_chunk().await
        }
    }

    /// Drain all output into a `ShellResult`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn collect_output(&mut self) -> Result<ShellResult> {
        let mut stdout = Vec::new();
        let mut exit_code = None;
        loop {
            match self.read_output().await? {
                None => break,
                Some(ShellOutput::Stdout(b) | ShellOutput::Stderr(b)) => {
                    stdout.extend_from_slice(&b);
                }
                Some(ShellOutput::ExitCode(c)) => {
                    exit_code = Some(c);
                }
            }
        }
        Ok(ShellResult {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            exit_code,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn write_v2_packet(&mut self, id: u8, data: &[u8]) -> Result<()> {
        // Shell v2 packet: 1-byte ID + 4-byte LE length + data
        let mut hdr = [0u8; 5];
        hdr[0] = id;
        hdr[1..5].copy_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        self.stream
            .write_all(&hdr)
            .await
            .map_err(AdbError::Connection)?;
        if !data.is_empty() {
            self.stream
                .write_all(data)
                .await
                .map_err(AdbError::Connection)?;
        }
        Ok(())
    }

    async fn read_v2_packet(&mut self) -> Result<Option<ShellOutput>> {
        let mut hdr = [0u8; 5];
        match self.stream.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(AdbError::Connection(e)),
        }
        let id = hdr[0];
        let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
        let mut data = vec![0u8; len];
        if len > 0 {
            self.stream
                .read_exact(&mut data)
                .await
                .map_err(AdbError::Connection)?;
        }
        let output = match id {
            v2::STDOUT_DATA => ShellOutput::Stdout(data),
            v2::STDERR_DATA => ShellOutput::Stderr(data),
            v2::EXIT_CODE => {
                let code = if len >= 4 {
                    i32::from_le_bytes(data[..4].try_into().unwrap())
                } else {
                    i32::from(data.first().copied().unwrap_or(0))
                };
                ShellOutput::ExitCode(code)
            }
            other => {
                // Unknown packet type — prepend the packet id so consumers can
                // diagnose without losing the payload.
                let mut tagged = format!("[adb-shellv2 unknown id={other}]\n").into_bytes();
                tagged.extend_from_slice(&data);
                ShellOutput::Stdout(tagged)
            }
        };
        Ok(Some(output))
    }

    async fn read_v1_chunk(&mut self) -> Result<Option<ShellOutput>> {
        let mut buf = vec![0u8; SHELL_BUF_SIZE];
        match self.stream.read(&mut buf).await {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(ShellOutput::Stdout(buf[..n].to_vec()))),
            Err(e) => Err(AdbError::Connection(e)),
        }
    }
}

// ─── run_command — synchronous-style helper over mock transport ───────────────

/// Execute a command on a mock/stub `AsyncRead + AsyncWrite` transport and
/// capture all output as a `ShellResult`.
///
/// The caller provides an already-open stream positioned right after the
/// `OKAY` response from the ADB server.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn run_command<S>(stream: S) -> Result<ShellResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = ShellSession::new_v1(stream);
    session.collect_output().await
}

/// Shell v2 variant: returns stdout, stderr separately and captures exit code.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn run_command_v2<S>(stream: S) -> Result<(String, String, i32)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = ShellSession::new_v2(stream, None);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = 0i32;
    loop {
        match session.read_output().await? {
            None => break,
            Some(ShellOutput::Stdout(b)) => stdout.extend_from_slice(&b),
            Some(ShellOutput::Stderr(b)) => stderr.extend_from_slice(&b),
            Some(ShellOutput::ExitCode(c)) => exit_code = c,
        }
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        exit_code,
    ))
}

// ─── StreamingShellSession ────────────────────────────────────────────────────

/// Runs a shell session and forwards output to a `mpsc` channel so callers
/// can process output asynchronously.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub async fn stream_shell_output<S>(
    stream: S,
    tx: mpsc::Sender<ShellOutput>,
    use_v2: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = if use_v2 {
        ShellSession::new_v2(stream, None)
    } else {
        ShellSession::new_v1(stream)
    };
    loop {
        match session.read_output().await? {
            None => break,
            Some(chunk) => {
                if tx.send(chunk).await.is_err() {
                    break; // receiver dropped
                }
            }
        }
    }
    Ok(())
}

// ─── Command builder ──────────────────────────────────────────────────────────

/// High-level builder for constructing ADB shell commands.
#[derive(Debug, Clone)]
pub struct CommandBuilder {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    timeout_s: Option<u32>,
    as_root: bool,
}

impl CommandBuilder {
    /// Start building a command.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            timeout_s: None,
            as_root: false,
        }
    }

    /// Append a positional argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append multiple arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable for the command.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Wrap the command in `timeout <secs> …`.
    #[must_use]
    pub const fn timeout(mut self, secs: u32) -> Self {
        self.timeout_s = Some(secs);
        self
    }

    /// Run via `su -c '…'`.
    #[must_use]
    pub const fn as_root(mut self) -> Self {
        self.as_root = true;
        self
    }

    /// Build the final shell command string.
    #[must_use]
    pub fn build(&self) -> String {
        // env prefix
        use std::fmt::Write as _;
        let env_prefix: String = self.env.iter().fold(String::new(), |mut acc, (k, v)| {
            write!(acc, "{}={} ", k, shell_escape(v)).expect("writing to String never fails");
            acc
        });

        // program + args
        let arg_refs: Vec<&str> = self.args.iter().map(std::string::String::as_str).collect();
        let inner = format!(
            "{env_prefix}{}",
            build_shell_command(&self.program, &arg_refs)
        );

        // timeout wrapper
        let timed = if let Some(secs) = self.timeout_s {
            with_timeout(&inner, secs)
        } else {
            inner
        };

        // root wrapper
        if self.as_root {
            format!("su -c {}", shell_escape(&timed))
        } else {
            timed
        }
    }
}

impl fmt::Display for CommandBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

// ─── Common command shortcuts ──────────────────────────────────────────────────

/// Build a `getprop <key>` command.
#[must_use]
pub fn cmd_getprop(key: &str) -> String {
    build_shell_command("getprop", &[key])
}

/// Build a `pm install -r <path>` command.
#[must_use]
pub fn cmd_pm_install(remote_apk: &str) -> String {
    build_shell_command("pm", &["install", "-r", remote_apk])
}

/// Build a `pm uninstall <package>` command.
#[must_use]
pub fn cmd_pm_uninstall(package: &str) -> String {
    build_shell_command("pm", &["uninstall", package])
}

/// Build a `am start -n <component>` command.
#[must_use]
pub fn cmd_am_start(component: &str) -> String {
    build_shell_command("am", &["start", "-n", component])
}

/// Build a `am force-stop <package>` command.
#[must_use]
pub fn cmd_am_force_stop(package: &str) -> String {
    build_shell_command("am", &["force-stop", package])
}

/// Build a `dumpsys <service>` command.
#[must_use]
pub fn cmd_dumpsys(service: &str) -> String {
    build_shell_command("dumpsys", &[service])
}

/// Build a `logcat -d -v threadtime *:V` command with optional filters.
#[must_use]
pub fn cmd_logcat(filters: &[&str]) -> String {
    let mut args = vec!["-d", "-v", "threadtime"];
    if filters.is_empty() {
        args.push("*:V");
    } else {
        args.extend_from_slice(filters);
    }
    build_shell_command("logcat", &args)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    // ── shell_escape ──────────────────────────────────────────────────────────

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn test_shell_escape_with_space() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_escape_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_special_chars() {
        let escaped = shell_escape("$(rm -rf /)");
        // Must be wrapped so $ is not expanded
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    // ── build_shell_command ───────────────────────────────────────────────────

    #[test]
    fn test_build_shell_command_no_args() {
        let cmd = build_shell_command("ls", &[]);
        assert_eq!(cmd, "'ls'");
    }

    #[test]
    fn test_build_shell_command_with_args() {
        let cmd = build_shell_command("ls", &["-la", "/sdcard"]);
        assert!(cmd.contains("'-la'"));
        assert!(cmd.contains("'/sdcard'"));
    }

    #[test]
    fn test_build_pipeline() {
        let p = build_pipeline(&["cat /proc/cpuinfo", "grep cores"]);
        assert!(p.contains('|'));
    }

    #[test]
    fn test_with_timeout() {
        let t = with_timeout("ping 8.8.8.8", 5);
        assert!(t.starts_with("timeout 5 "));
        assert!(t.contains("ping"));
    }

    // ── CommandBuilder ────────────────────────────────────────────────────────

    #[test]
    fn test_command_builder_simple() {
        let cmd = CommandBuilder::new("ls").arg("-la").build();
        assert!(cmd.contains("ls"));
        assert!(cmd.contains("-la"));
    }

    #[test]
    fn test_command_builder_multiple_args() {
        let cmd = CommandBuilder::new("pm").args(["list", "packages"]).build();
        assert!(cmd.contains("pm"));
        assert!(cmd.contains("list"));
        assert!(cmd.contains("packages"));
    }

    #[test]
    fn test_command_builder_with_env() {
        let cmd = CommandBuilder::new("app_process")
            .env("CLASSPATH", "/data/local/tmp/test.jar")
            .build();
        assert!(cmd.contains("CLASSPATH="));
    }

    #[test]
    fn test_command_builder_with_timeout() {
        let cmd = CommandBuilder::new("ping")
            .arg("8.8.8.8")
            .timeout(10)
            .build();
        assert!(cmd.starts_with("timeout 10 "));
    }

    #[test]
    fn test_command_builder_as_root() {
        let cmd = CommandBuilder::new("cat")
            .arg("/data/data/pkg/db")
            .as_root()
            .build();
        assert!(cmd.starts_with("su -c "));
    }

    #[test]
    fn test_command_builder_display() {
        let cb = CommandBuilder::new("echo").arg("hello");
        let s = format!("{cb}");
        assert!(s.contains("echo"));
    }

    // ── Command shortcuts ─────────────────────────────────────────────────────

    #[test]
    fn test_cmd_getprop() {
        let c = cmd_getprop("ro.build.version.sdk");
        assert!(c.contains("getprop"));
        assert!(c.contains("ro.build.version.sdk"));
    }

    #[test]
    fn test_cmd_pm_install() {
        let c = cmd_pm_install("/data/local/tmp/app.apk");
        assert!(c.contains("pm"));
        assert!(c.contains("install"));
        assert!(c.contains("-r"));
    }

    #[test]
    fn test_cmd_pm_uninstall() {
        let c = cmd_pm_uninstall("com.example.app");
        assert!(c.contains("pm"));
        assert!(c.contains("uninstall"));
        assert!(c.contains("com.example.app"));
    }

    #[test]
    fn test_cmd_am_start() {
        let c = cmd_am_start("com.example/.MainActivity");
        assert!(c.contains("am"));
        assert!(c.contains("start"));
    }

    #[test]
    fn test_cmd_am_force_stop() {
        let c = cmd_am_force_stop("com.example");
        assert!(c.contains("force-stop"));
    }

    #[test]
    fn test_cmd_dumpsys() {
        let c = cmd_dumpsys("battery");
        assert!(c.contains("dumpsys"));
        assert!(c.contains("battery"));
    }

    #[test]
    fn test_cmd_logcat_no_filter() {
        let c = cmd_logcat(&[]);
        assert!(c.contains("logcat"));
        assert!(c.contains("*:V"));
    }

    #[test]
    fn test_cmd_logcat_with_filter() {
        let c = cmd_logcat(&["ActivityManager:I", "*:S"]);
        assert!(c.contains("ActivityManager:I"));
    }

    // ── TerminalSize ──────────────────────────────────────────────────────────

    #[test]
    fn test_terminal_size_default() {
        let t = TerminalSize::default();
        assert_eq!(t.rows, 24);
        assert_eq!(t.cols, 80);
    }

    #[test]
    fn test_terminal_size_encode_v2() {
        let t = TerminalSize {
            rows: 24,
            cols: 80,
            x_pixels: 0,
            y_pixels: 0,
        };
        let enc = t.encode_v2();
        assert_eq!(u16::from_le_bytes([enc[0], enc[1]]), 24);
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]), 80);
    }

    // ── ShellSession v1 with mock stream ──────────────────────────────────────

    #[tokio::test]
    async fn test_shell_session_v1_collect_output() {
        let response_data = b"hello\nworld\n";
        let (mut client, server) = duplex(256);
        // Write mock response then close
        client.write_all(response_data).await.unwrap();
        drop(client);
        let mut session = ShellSession::new_v1(server);
        let result = session.collect_output().await.unwrap();
        assert_eq!(result.stdout.trim(), "hello\nworld");
        assert!(result.exit_code.is_none());
    }

    #[tokio::test]
    async fn test_shell_session_v1_empty_output() {
        let (client, server) = duplex(256);
        drop(client);
        let mut session = ShellSession::new_v1(server);
        let result = session.collect_output().await.unwrap();
        assert!(result.stdout.is_empty());
    }

    // ── ShellSession v2 with mock stream ──────────────────────────────────────

    fn encode_v2_packet(id: u8, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![id];
        buf.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    #[tokio::test]
    async fn test_shell_session_v2_collect_output() {
        let (mut writer, reader) = duplex(1024);
        let stdout_pkt = encode_v2_packet(v2::STDOUT_DATA, b"output line\n");
        let exit_pkt = encode_v2_packet(v2::EXIT_CODE, &0i32.to_le_bytes());
        writer.write_all(&stdout_pkt).await.unwrap();
        writer.write_all(&exit_pkt).await.unwrap();
        drop(writer);

        let mut session = ShellSession::new_v2(reader, None);
        let result = session.collect_output().await.unwrap();
        assert!(result.stdout.contains("output line"));
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_shell_session_v2_stderr_captured() {
        let (mut writer, reader) = duplex(1024);
        let stderr_pkt = encode_v2_packet(v2::STDERR_DATA, b"error msg\n");
        let exit_pkt = encode_v2_packet(v2::EXIT_CODE, &1i32.to_le_bytes());
        writer.write_all(&stderr_pkt).await.unwrap();
        writer.write_all(&exit_pkt).await.unwrap();
        drop(writer);

        let mut session = ShellSession::new_v2(reader, None);
        let result = session.collect_output().await.unwrap();
        // stderr merged into stdout by collect_output
        assert!(result.stdout.contains("error msg"));
        assert_eq!(result.exit_code, Some(1));
    }

    #[tokio::test]
    async fn test_shell_session_v2_non_zero_exit() {
        let (mut writer, reader) = duplex(1024);
        let exit_pkt = encode_v2_packet(v2::EXIT_CODE, &42i32.to_le_bytes());
        writer.write_all(&exit_pkt).await.unwrap();
        drop(writer);

        let mut session = ShellSession::new_v2(reader, None);
        let result = session.collect_output().await.unwrap();
        assert_eq!(result.exit_code, Some(42));
    }

    // ── ShellOutput helpers ───────────────────────────────────────────────────

    #[test]
    fn test_shell_output_as_stdout() {
        let o = ShellOutput::Stdout(b"data".to_vec());
        assert_eq!(o.as_stdout(), Some(b"data".as_ref()));
        assert!(o.as_stderr().is_none());
        assert!(o.exit_code().is_none());
    }

    #[test]
    fn test_shell_output_as_stderr() {
        let o = ShellOutput::Stderr(b"err".to_vec());
        assert!(o.as_stdout().is_none());
        assert_eq!(o.as_stderr(), Some(b"err".as_ref()));
    }

    #[test]
    fn test_shell_output_exit_code() {
        let o = ShellOutput::ExitCode(0);
        assert_eq!(o.exit_code(), Some(0));
    }
}
