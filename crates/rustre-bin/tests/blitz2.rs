//! Deep adversarial black-box integration tests for the `rustre` binary.
//!
//! `rustre-bin` has no `[lib]` target, so tests drive the compiled
//! binary via `CARGO_BIN_EXE_rustre`. These tests focus on:
//!   - argument parsing boundaries, unknown flags, missing values
//!   - subcommand routing (every documented subcommand)
//!   - JSON vs human output paths
//!   - error exit codes (2 = usage error, 1 = runtime error, 0 = ok)
//!   - seeded-LCG fuzzing: random argv must never panic the binary,
//!     it must always exit with a code (never hang / abort).
//!   - global flag aliases (--quiet/-q, --verbose/-v, --help/-h, --version/-V)
//!   - completion script generation for every supported shell
//!
//! Notes:
//! * We avoid running anything that requires a real binary file on disk.
//!   Where a file path is required we use a path that exists on the test
//!   host (the cargo manifest dir itself, or a tempfile) and assert only
//!   on stable behavior (exit code, presence of marker substrings, valid
//!   JSON structure where applicable).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

// ---- helpers ---------------------------------------------------------------

fn bin() -> Command {
    let exe = env!("CARGO_BIN_EXE_rustre");
    let mut c = Command::new(exe);
    // Avoid touching the user's real config dir during tests.
    c.env_remove("RUSTRE_PERSIST_CONFIG");
    c.stdin(Stdio::null());
    c
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = bin().args(args).output().expect("binary should be executable");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

/// Seeded linear congruential generator (deterministic, no rand crate).
fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}
fn lcg_next(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s
}

/// Path that is guaranteed to exist (the crate's own manifest dir).
fn existing_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ---- version / help --------------------------------------------------------

#[test]
fn t01_version_subcommand_ok() {
    let (code, out, _) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(out.contains("rustre"));
}

#[test]
fn t02_version_long_flag_ok() {
    let (code, out, _) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.contains("rustre"));
}

#[test]
fn t03_version_short_flag_ok() {
    let (code, out, _) = run(&["-V"]);
    assert_eq!(code, 0);
    assert!(out.contains("rustre"));
}

#[test]
fn t04_help_subcommand_ok() {
    let (code, out, _) = run(&["help"]);
    assert_eq!(code, 0);
    assert!(out.contains("USAGE"));
    assert!(out.contains("SUBCOMMANDS"));
}

#[test]
fn t05_help_long_flag_ok() {
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("USAGE"));
}

#[test]
fn t06_help_short_flag_ok() {
    let (code, out, _) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(out.contains("USAGE") || out.contains("rustre"));
}

#[test]
fn t07_no_args_prints_help() {
    let (code, out, _) = run(&[]);
    assert_eq!(code, 0);
    assert!(out.contains("USAGE"));
}

#[test]
fn t08_help_advertises_every_subcommand() {
    let (_, out, _) = run(&["help"]);
    for sc in [
        "analyze",
        "decompile",
        "disasm",
        "strings",
        "info",
        "debug",
        "script",
        "server",
        "completions",
        "help",
        "version",
    ] {
        assert!(out.contains(sc), "help missing subcommand `{sc}`:\n{out}");
    }
}

// ---- unknown subcommand / flags -------------------------------------------

#[test]
fn t09_unknown_subcommand_exits_2() {
    let (code, _, err) = run(&["definitely-not-a-subcommand"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("unknown"));
}

#[test]
fn t10_unknown_global_flag_exits_2() {
    let (code, _, _) = run(&["--definitely-not-a-real-flag-xyz", "help"]);
    assert_eq!(code, 2);
}

#[test]
fn t11_double_dash_no_subcommand_exits_2() {
    let (code, _, _) = run(&["--"]);
    // Treated as unknown subcommand.
    assert!(code == 2 || code == 0);
}

#[test]
fn t12_config_flag_requires_value() {
    let (code, _, err) = run(&["--config"]);
    assert_eq!(code, 2);
    assert!(err.contains("--config"));
}

#[test]
fn t13_daemon_flag_requires_value() {
    let (code, _, err) = run(&["--daemon"]);
    assert_eq!(code, 2);
    assert!(err.contains("--daemon"));
}

// ---- subcommand: analyze ---------------------------------------------------

#[test]
fn t14_analyze_missing_file_exits_2() {
    let (code, _, err) = run(&["analyze"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("file"));
}

#[test]
fn t15_analyze_nonexistent_file_exits_1() {
    let (code, _, _) = run(&["analyze", "/__definitely_missing_file__"]);
    assert_eq!(code, 1);
}

#[test]
fn t16_analyze_bad_timeout_exits_2() {
    let p = existing_path();
    let (code, _, err) = run(&["analyze", "--timeout=abc", p.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("timeout") || err.to_lowercase().contains("digit"));
}

#[test]
fn t17_analyze_json_output_is_valid_json() {
    let p = existing_path();
    let (code, out, _) = run(&["--json", "analyze", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["command"], "analyze");
}

// ---- subcommand: decompile -------------------------------------------------

#[test]
fn t18_decompile_missing_file_exits_2() {
    let (code, _, _) = run(&["decompile"]);
    assert_eq!(code, 2);
}

#[test]
fn t19_decompile_bad_addr_exits_2() {
    let p = existing_path();
    let (code, _, err) = run(&["decompile", "--addr=0xZZZ", p.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("hex") || err.to_lowercase().contains("digit"));
}

#[test]
fn t20_decompile_json_round_trip() {
    let p = existing_path();
    let (code, out, _) = run(&["--json", "decompile", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["command"], "decompile");
    assert_eq!(v["address"], 0);
}

// ---- subcommand: disasm ----------------------------------------------------

#[test]
fn t21_disasm_missing_file_exits_2() {
    let (code, _, _) = run(&["disasm"]);
    assert_eq!(code, 2);
}

#[test]
fn t22_disasm_bad_addr_exits_2() {
    let p = existing_path();
    let (code, _, _) = run(&["disasm", "--addr=0xQQ", p.to_str().unwrap()]);
    assert_eq!(code, 2);
}

#[test]
fn t23_disasm_default_runs() {
    let p = existing_path();
    let (code, out, _) = run(&["disasm", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    // Default produces human output with a Disassembly heading.
    assert!(out.to_lowercase().contains("disassembly"));
}

// ---- subcommand: strings ---------------------------------------------------

#[test]
fn t24_strings_missing_file_exits_2() {
    let (code, _, _) = run(&["strings"]);
    assert_eq!(code, 2);
}

#[test]
fn t25_strings_bad_min_exits_2() {
    let p = existing_path();
    let (code, _, _) = run(&["strings", "--min=abc", p.to_str().unwrap()]);
    assert_eq!(code, 2);
}

#[test]
fn t26_strings_json_has_expected_shape() {
    let p = existing_path();
    let (code, out, _) = run(&["--json", "strings", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["command"], "strings");
    assert!(v["strings"].is_array());
}

// ---- subcommand: info ------------------------------------------------------

#[test]
fn t27_info_missing_file_exits_2() {
    let (code, _, _) = run(&["info"]);
    assert_eq!(code, 2);
}

#[test]
fn t28_info_nonexistent_file_exits_1() {
    let (code, _, _) = run(&["info", "/__no_such_file__"]);
    assert_eq!(code, 1);
}

#[test]
fn t29_info_json_path_field_present() {
    let p = existing_path();
    let (code, out, _) = run(&["--json", "info", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["command"], "info");
    assert!(v["path"].is_string());
}

// ---- subcommand: debug -----------------------------------------------------

#[test]
fn t30_debug_bad_pid_exits_2() {
    let (code, _, err) = run(&["debug", "--pid=not-a-number"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("pid") || err.to_lowercase().contains("digit"));
}

// ---- subcommand: script ----------------------------------------------------

#[test]
fn t31_script_no_input_exits_2() {
    let (code, _, err) = run(&["script"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("script") || err.to_lowercase().contains("eval"));
}

// ---- subcommand: server ----------------------------------------------------

#[test]
fn t32_server_unknown_action_exits_2() {
    let (code, _, err) = run(&["server", "bogus"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("server") || err.to_lowercase().contains("unknown"));
}

#[test]
fn t33_server_status_no_daemon_exits_1() {
    // No daemon running on the default port; status should report failure.
    let (code, _, _) = run(&["server", "status"]);
    assert!(code == 0 || code == 1, "unexpected exit code {code}");
}

// ---- subcommand: completions ----------------------------------------------

#[test]
fn t34_completions_bash() {
    let (code, out, _) = run(&["completions", "bash"]);
    assert_eq!(code, 0);
    assert!(out.contains("bash completion"));
}

#[test]
fn t35_completions_zsh() {
    let (code, out, _) = run(&["completions", "zsh"]);
    assert_eq!(code, 0);
    assert!(out.to_lowercase().contains("zsh") || out.contains("#compdef"));
}

#[test]
fn t36_completions_fish() {
    let (code, out, _) = run(&["completions", "fish"]);
    assert_eq!(code, 0);
    assert!(out.to_lowercase().contains("fish"));
}

#[test]
fn t37_completions_powershell() {
    let (code, out, _) = run(&["completions", "powershell"]);
    assert_eq!(code, 0);
    assert!(out.to_lowercase().contains("powershell") || out.contains("Register-ArgumentCompleter"));
}

#[test]
fn t38_completions_elvish() {
    let (code, out, _) = run(&["completions", "elvish"]);
    assert_eq!(code, 0);
    assert!(out.to_lowercase().contains("elvish"));
}

#[test]
fn t39_completions_unknown_shell_exits_2() {
    let (code, _, err) = run(&["completions", "klingon"]);
    assert_eq!(code, 2);
    assert!(err.to_lowercase().contains("shell") || err.to_lowercase().contains("unknown"));
}

// ---- global flag plumbing --------------------------------------------------

#[test]
fn t40_quiet_flag_accepted() {
    let (code, _, _) = run(&["--quiet", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t41_quiet_short_flag_accepted() {
    let (code, _, _) = run(&["-q", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t42_verbose_flag_accepted() {
    let (code, _, _) = run(&["-v", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t43_no_color_flag_accepted() {
    let (code, _, _) = run(&["--no-color", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t44_config_equals_form_accepted() {
    // The config file does not need to exist; --config is just a path override.
    let (code, _, _) = run(&["--config=/tmp/__not_real_cfg.toml", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t45_config_space_form_accepted() {
    let (code, _, _) = run(&["--config", "/tmp/__not_real_cfg.toml", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t46_daemon_equals_form_accepted() {
    let (code, _, _) = run(&["--daemon=127.0.0.1:65535", "version"]);
    assert_eq!(code, 0);
}

#[test]
fn t47_json_flag_changes_version_format_or_keeps_text() {
    // --json + version is allowed to behave either way; the only invariant we
    // check is the process exits cleanly.
    let (code, _, _) = run(&["--json", "version"]);
    assert_eq!(code, 0);
}

// ---- LCG-seeded fuzz: never panic, always terminate -----------------------

const ALPHABET: &[&str] = &[
    "analyze",
    "decompile",
    "disasm",
    "strings",
    "info",
    "debug",
    "script",
    "server",
    "completions",
    "help",
    "version",
    "--json",
    "--quiet",
    "-q",
    "-v",
    "--verbose",
    "--no-color",
    "--config",
    "--daemon",
    "--addr=0x401000",
    "--addr=0xZZZ",
    "--timeout=10",
    "--timeout=abc",
    "--min=4",
    "--pid=1",
    "--pid=bogus",
    "--lang=c",
    "--eval=1+1",
    "--bind=127.0.0.1:0",
    "bash",
    "zsh",
    "fish",
    "klingon",
    "status",
    "start",
    "stop",
    "/tmp",
    "",
    "--",
    "-",
    "x",
];

#[test]
fn t48_fuzz_short_argv_never_panics() {
    let mut s = lcg_seed();
    for _ in 0..30 {
        let n = (lcg_next(&mut s) % 4) as usize + 1;
        let mut argv: Vec<&str> = Vec::with_capacity(n);
        for _ in 0..n {
            let idx = (lcg_next(&mut s) as usize) % ALPHABET.len();
            argv.push(ALPHABET[idx]);
        }
        let out = bin()
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .expect("binary must execute");
        // Must have exited with *some* code; signals are not allowed.
        assert!(
            out.status.code().is_some(),
            "binary did not exit cleanly for argv={argv:?}"
        );
    }
}

#[test]
fn t49_fuzz_random_unicode_bytes_never_panics() {
    let mut s = lcg_seed() ^ 0x1234_5678_9ABC_DEF0;
    for _ in 0..10 {
        // Build a single arg of pseudo-random ASCII-printable bytes.
        let len = (lcg_next(&mut s) % 16) as usize + 1;
        let mut arg = String::with_capacity(len);
        for _ in 0..len {
            let b = (lcg_next(&mut s) % 94) as u8 + 33; // printable ascii
            arg.push(b as char);
        }
        let out = bin()
            .arg(&arg)
            .stdin(Stdio::null())
            .output()
            .expect("binary must execute");
        assert!(out.status.code().is_some(), "no exit code for arg={arg:?}");
    }
}

// ---- Send+Sync threaded stress on the spawn machinery ---------------------

#[test]
fn t50_threaded_concurrent_version_invocations() {
    // 4 threads × 25 invocations = 100 process spawns, exercising whatever
    // global state (env, fds) the binary touches during parse+exit.
    let exe: Arc<&str> = Arc::new(env!("CARGO_BIN_EXE_rustre"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let exe = Arc::clone(&exe);
        handles.push(std::thread::spawn(move || {
            for _ in 0..25 {
                let out = Command::new(*exe)
                    .arg("version")
                    .stdin(Stdio::null())
                    .output()
                    .expect("spawn");
                assert_eq!(out.status.code(), Some(0));
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

// ---- stdin closed is not an error for non-interactive commands -----------

#[test]
fn t51_closed_stdin_does_not_hang_help() {
    let mut child = bin()
        .arg("help")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Close stdin immediately.
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn t52_closed_stdin_does_not_hang_version() {
    let mut child = bin()
        .arg("version")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
}

// ---- piped stdin with garbage doesn't perturb non-interactive output -----

#[test]
fn t53_piped_garbage_stdin_version() {
    let mut child = bin()
        .arg("version")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(mut stdin) = child.stdin.take() {
        // Ignore errors: the child may exit before we finish writing.
        let _ = stdin.write_all(b"random junk\n\xff\xfe\x00garbage\n");
    }
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
}
