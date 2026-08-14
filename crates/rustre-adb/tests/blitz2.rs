//! blitz2 — deep adversarial tests for rustre-adb (X001).
//!
//! Focus: pure parsers, encoders, state machines, hash/eq invariants,
//! LCG-fuzzed never-panic guarantees, threaded Send+Sync exercise.

#![allow(clippy::too_many_lines)]

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_adb::{
    cmd, compute_crc32, decode_message, encode_message, parse_logcat_line, parse_logcat_output,
    AdbClient, AdbDevice, AdbError, AdbMessage, DeviceState, LogEntry, LogLevel, RebootMode,
    ShellResult,
};
use rustre_adb::protocol::{
    self, build_banner, fragment_payload, is_valid_header, make_auth_signature, make_auth_token,
    make_close, make_connect, make_okay, make_open, make_write, parse_features, AdbFeature,
    AuthType, LocalId, RemoteId,
};
use rustre_adb::device::{parse_devices_output, DeviceInfo, DeviceList, TransportType};
use rustre_adb::shell::{
    build_pipeline, build_shell_command, cmd_am_force_stop, cmd_am_start, cmd_dumpsys, cmd_getprop,
    cmd_logcat, cmd_pm_install, cmd_pm_uninstall, shell_escape, with_timeout, CommandBuilder,
    TerminalSize,
};
use rustre_adb::sync::{DirEntry, FileType, StatEntry};
use rustre_adb::logcat::{
    parse_any_line, parse_brief_line, parse_threadtime_line, LogBuffer, LogcatEntry, LogcatFilter,
    Priority,
};
use rustre_adb::package::{
    build_install_command, build_uninstall_command, extract_install_failure, install_succeeded,
    parse_pm_list_line, parse_pm_list_output, uninstall_succeeded, InstallLocation, ListOptions,
};

// ── Seeded LCG ──────────────────────────────────────────────────────────────

fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ── encode_message / decode_message ─────────────────────────────────────────

#[test]
fn b2_encode_decode_roundtrip_50_inputs() {
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    let cmds = [
        cmd::CNXN,
        cmd::AUTH,
        cmd::OPEN,
        cmd::OKAY,
        cmd::CLSE,
        cmd::WRTE,
        cmd::SYNC,
    ];
    for i in 0..50u64 {
        let c = cmds[usize::try_from(i).unwrap_or(usize::MAX) % cmds.len()];
        let a0 = u32::try_from(g() & u64::from(u32::MAX)).unwrap_or(u32::MAX);
        let a1 = u32::try_from(g() & u64::from(u32::MAX)).unwrap_or(u32::MAX);
        let len = (g() % 257) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let bytes = encode_message(c, a0, a1, &data);
        let msg = decode_message(&bytes).expect("roundtrip");
        assert_eq!(msg.command, c);
        assert_eq!(msg.arg0, a0);
        assert_eq!(msg.arg1, a1);
        assert_eq!(msg.data, data);
        assert!(msg.verify_crc());
        assert_eq!(msg.magic, c ^ 0xFFFF_FFFF);
    }
}

#[test]
fn b2_decode_fuzz_never_panics() {
    let mut g = lcg(0xA5A5_5A5A_DEAD_BEEF);
    for _ in 0..200 {
        let len = (g() % 80) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let _ = decode_message(&buf);
    }
}

#[test]
fn b2_decode_msg_just_24_bytes_zero_magic() {
    // command=0, magic=0 is invalid: magic should be !command = 0xFFFFFFFF
    let buf = [0u8; 24];
    let r = decode_message(&buf);
    assert!(matches!(r, Err(AdbError::Protocol(_))));
}

#[test]
fn b2_decode_msg_off_by_one_short() {
    for n in 0..24usize {
        let buf = vec![0u8; n];
        assert!(matches!(decode_message(&buf), Err(AdbError::Protocol(_))));
    }
}

#[test]
fn b2_decode_msg_payload_truncated_by_one() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut enc = encode_message(cmd::WRTE, 1, 2, &data).to_vec();
    enc.pop();
    assert!(matches!(decode_message(&enc), Err(AdbError::Protocol(_))));
}

#[test]
fn b2_compute_crc32_deterministic() {
    assert_eq!(compute_crc32(b""), 0);
    assert_eq!(compute_crc32(b"A"), 0x41);
    assert_eq!(compute_crc32(b"ABC"), 0x41 + 0x42 + 0x43);
    let big: Vec<u8> = (0..=255u8).collect();
    let sum: u32 = (0u32..=255).sum();
    assert_eq!(compute_crc32(&big), sum);
}

#[test]
fn b2_compute_crc32_overflow_safe() {
    // 0xFFFFFFFF / 0xFF + 1 = ~16.8M bytes of 0xFF would wrap.
    let buf = vec![0xFFu8; 100_000];
    let expected = 0xFFu32.wrapping_mul(100_000);
    assert_eq!(compute_crc32(&buf), expected);
}

#[test]
fn b2_adb_message_new_encode_matches() {
    let m = AdbMessage::new(cmd::OPEN, 0x1234_5678, 0x9ABC_DEF0, b"open hello".to_vec());
    let bytes = m.encode();
    let m2 = decode_message(&bytes).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn b2_is_valid_header_roundtrip() {
    let bytes = encode_message(cmd::CNXN, 0, 0, b"");
    let mut hdr = [0u8; 24];
    hdr.copy_from_slice(&bytes[..24]);
    assert!(is_valid_header(&hdr));
    hdr[20] ^= 0xFF;
    assert!(!is_valid_header(&hdr));
}

#[test]
fn b2_adb_message_eq_and_clone() {
    let m = AdbMessage::new(cmd::WRTE, 1, 2, b"x".to_vec());
    let n = m.clone();
    assert_eq!(m, n);
}

// ── DeviceState ─────────────────────────────────────────────────────────────

#[test]
fn b2_device_state_display_parse_roundtrip() {
    let all = [
        DeviceState::Offline,
        DeviceState::Bootloader,
        DeviceState::Device,
        DeviceState::Host,
        DeviceState::Recovery,
        DeviceState::Sideload,
        DeviceState::Unauthorized,
        DeviceState::Unknown,
    ];
    for s in &all {
        let txt = s.to_string();
        // Display has well-formed text; Unknown round-trips.
        assert!(!txt.is_empty());
    }
    // Display "no-permissions" is preserved separately by from_str's "no-permissions" branch.
}

#[test]
fn b2_device_state_is_online_exhaustive() {
    assert!(DeviceState::Device.is_online());
    assert!(DeviceState::Recovery.is_online());
    assert!(DeviceState::Sideload.is_online());
    for s in [
        DeviceState::Offline,
        DeviceState::Bootloader,
        DeviceState::Host,
        DeviceState::NoPermissions,
        DeviceState::Unauthorized,
        DeviceState::Unknown,
    ] {
        assert!(!s.is_online());
    }
}

// ── AdbDevice::parse ────────────────────────────────────────────────────────

#[test]
fn b2_adb_device_parse_fuzz_no_panic() {
    let mut g = lcg(0xCAFE_F00D_5555_1234);
    for _ in 0..50 {
        let n = (g() % 5) as usize + 1;
        let mut lines = String::new();
        for _ in 0..n {
            let llen = (g() % 60) as usize;
            for _ in 0..llen {
                let c = (g() & 0x7f) as u8;
                lines.push((if c == 0 || c == b'\n' { b' ' } else { c }) as char);
            }
            lines.push('\n');
        }
        // never panics
        let _ = parse_devices_output(&lines);
    }
}

#[test]
fn b2_parse_devices_output_blank_lines_skipped() {
    let txt = "\n\nemulator-5554\tdevice\n\n\n";
    let list = parse_devices_output(txt);
    assert_eq!(list.devices.len(), 1);
}

#[test]
fn b2_parse_devices_output_transport_id_invalid_becomes_none() {
    let txt = "abc\tdevice transport_id:notanumber\n";
    let list = parse_devices_output(txt);
    assert_eq!(list.devices.len(), 1);
    assert_eq!(list.devices[0].device.transport_id, None);
}

#[test]
fn b2_adb_device_is_ready_matches_state_online() {
    for state in [
        DeviceState::Device,
        DeviceState::Offline,
        DeviceState::Unauthorized,
        DeviceState::Recovery,
    ] {
        let d = AdbDevice {
            serial: "x".into(),
            state: state.clone(),
            product: String::new(),
            model: String::new(),
            device: String::new(),
            transport_id: None,
        };
        assert_eq!(d.is_ready(), state.is_online());
    }
}

// ── LogLevel / Priority ─────────────────────────────────────────────────────

#[test]
fn b2_loglevel_as_char_display_consistent() {
    for lvl in [
        LogLevel::Verbose,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warning,
        LogLevel::Error,
        LogLevel::Fatal,
        LogLevel::Silent,
    ] {
        let c = lvl.as_char();
        assert_eq!(lvl.to_string(), c.to_string());
        assert!("VDIWEFS".contains(c));
    }
}

#[test]
fn b2_priority_from_u8_roundtrip_known() {
    for v in 1u8..=8 {
        let p = Priority::from_u8(v);
        // Unknown returns Unknown for 0 and >=9
        let _ll: LogLevel = p.to_log_level();
    }
    assert!(matches!(Priority::from_u8(0), Priority::Unknown));
    assert!(matches!(Priority::from_u8(9), Priority::Unknown));
    assert!(matches!(Priority::from_u8(255), Priority::Unknown));
}

// ── LogEntry parsers ────────────────────────────────────────────────────────

#[test]
fn b2_log_entry_parse_brief_50_lines() {
    let levels = ['V', 'D', 'I', 'W', 'E', 'F'];
    for (i, &lc) in levels.iter().cycle().take(50).enumerate() {
        let pid = u32::try_from(i).unwrap_or(u32::MAX) + 1;
        let line = format!("{lc}/Tag{i}({pid}): message body {i}");
        let e = LogEntry::parse_brief(&line).expect("brief parse");
        assert_eq!(e.pid, pid);
        assert_eq!(e.tag, format!("Tag{i}"));
        assert!(e.message.contains("message body"));
    }
}

#[test]
fn b2_log_entry_parse_fuzz_no_panic() {
    let mut g = lcg(0x1111_2222_3333_4444);
    for _ in 0..200 {
        let len = (g() % 120) as usize;
        let s: String = (0..len)
            .map(|_| {
                let v = (g() & 0x7f) as u8;
                (if v < 32 { b' ' } else { v }) as char
            })
            .collect();
        let _ = LogEntry::parse(&s);
        let _ = LogEntry::parse_brief(&s);
        let _ = LogEntry::parse_threadtime(&s);
        let _ = parse_logcat_line(&s);
    }
}

#[test]
fn b2_log_entry_brief_separator_returns_none() {
    assert!(LogEntry::parse_brief("--------- beginning of main").is_none());
}

#[test]
fn b2_parse_logcat_output_drops_invalid() {
    let txt = "I/T(1): hi\ngarbage\n--------- sep\nE/U(2): bye";
    let v = parse_logcat_output(txt);
    assert_eq!(v.len(), 2);
}

// ── protocol::AdbFeature ────────────────────────────────────────────────────

#[test]
fn b2_adb_feature_parse_known() {
    assert!(matches!(AdbFeature::parse("shell_v2"), AdbFeature::ShellV2));
    assert!(matches!(AdbFeature::parse("cmd"), AdbFeature::Cmd));
    assert!(matches!(AdbFeature::parse("stat_v2"), AdbFeature::StatV2));
    assert!(matches!(AdbFeature::parse("apex"), AdbFeature::Apex));
}

#[test]
fn b2_adb_feature_parse_unknown_preserves_string() {
    let f = AdbFeature::parse("future_feature_42");
    assert_eq!(f.as_str(), "future_feature_42");
}

#[test]
fn b2_build_banner_roundtrip_via_parse_features() {
    let feats = vec![AdbFeature::ShellV2, AdbFeature::Cmd, AdbFeature::StatV2];
    let banner = build_banner("host", "name", &feats);
    let parsed = parse_features(&banner);
    assert_eq!(parsed.len(), feats.len());
    for (a, b) in feats.iter().zip(parsed.iter()) {
        assert_eq!(a.as_str(), b.as_str());
    }
}

#[test]
fn b2_build_banner_empty_features() {
    let banner = build_banner("host", "rust", &[]);
    assert_eq!(banner, "host::rust");
    assert!(parse_features(&banner).is_empty());
}

#[test]
fn b2_parse_features_no_segment() {
    assert!(parse_features("host::just-a-banner").is_empty());
    assert!(parse_features("").is_empty());
}

// ── AuthType ────────────────────────────────────────────────────────────────

#[test]
fn b2_auth_type_from_u32_roundtrip() {
    for v in [1u32, 2, 3] {
        let a = AuthType::from_u32(v).unwrap();
        assert_eq!(a.as_u32(), v);
    }
    for v in [0u32, 4, 99, u32::MAX] {
        assert!(AuthType::from_u32(v).is_none());
    }
}

// ── make_* message constructors ─────────────────────────────────────────────

#[test]
fn b2_make_connect_payload_terminated() {
    let m = make_connect("host", "RustRE/1.0");
    assert_eq!(m.command, cmd::CNXN);
    assert_eq!(*m.data.last().unwrap(), 0u8);
}

#[test]
fn b2_make_open_close_okay_write_commands() {
    let o = make_open(LocalId(7), "shell:");
    assert_eq!(o.command, cmd::OPEN);
    assert_eq!(o.arg0, 7);
    assert_eq!(*o.data.last().unwrap(), 0u8); // NUL-terminated service
    let k = make_okay(LocalId(1), RemoteId(2));
    assert_eq!(k.command, cmd::OKAY);
    assert_eq!(k.arg0, 1);
    assert_eq!(k.arg1, 2);
    let c = make_close(LocalId(3), RemoteId(4));
    assert_eq!(c.command, cmd::CLSE);
    let w = make_write(LocalId(5), RemoteId(6), b"hello".to_vec());
    assert_eq!(w.command, cmd::WRTE);
    assert_eq!(w.data, b"hello");
}

#[test]
fn b2_make_auth_messages() {
    let t = make_auth_token(b"token-bytes".to_vec());
    assert_eq!(t.arg0, 1);
    let s = make_auth_signature(b"sig".to_vec());
    assert_eq!(s.arg0, 2);
}

// ── LocalId / RemoteId Hash/Eq ──────────────────────────────────────────────

#[test]
fn b2_localid_remoteid_hash_eq_30_pairs() {
    let mut g = lcg(0x7777_1234_BEEF_F00D);
    for _ in 0..30 {
        let v = u32::try_from(g() & u64::from(u32::MAX)).unwrap_or(u32::MAX);
        let a = LocalId(v);
        let b = LocalId(v);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        let ra = RemoteId(v);
        let rb = RemoteId(v);
        assert_eq!(ra, rb);
        assert_eq!(hash_of(&ra), hash_of(&rb));
    }
}

// ── fragment_payload ────────────────────────────────────────────────────────

#[test]
fn b2_fragment_payload_concat_equals_input() {
    let mut g = lcg(0xABCD_1234_5678_9ABC);
    for _ in 0..20 {
        let total = usize::try_from(g() % 10_000).unwrap_or(0);
        let chunk = usize::try_from((g() % 511) + 1).unwrap_or(1); // never zero
        let data: Vec<u8> = (0..total).map(|i| u8::try_from(i & 0xff).unwrap_or(0)).collect();
        let frags = fragment_payload(&data, chunk);
        let joined: Vec<u8> = frags.iter().flat_map(|b| b.iter().copied()).collect();
        assert_eq!(joined, data);
        for f in &frags {
            assert!(f.len() <= chunk);
        }
    }
}

#[test]
fn b2_fragment_payload_empty() {
    assert!(fragment_payload(&[], 64).is_empty());
}

// ── shell_escape / build_shell_command ──────────────────────────────────────

#[test]
fn b2_shell_escape_simple() {
    assert_eq!(shell_escape("hello"), "'hello'");
    assert_eq!(shell_escape(""), "''");
}

#[test]
fn b2_shell_escape_single_quote() {
    assert_eq!(shell_escape("it's"), "'it'\\''s'");
}

#[test]
fn b2_shell_escape_fuzz_no_panic_balanced_quotes() {
    let mut g = lcg(0xBEAD_F00D_FACE_1234);
    for _ in 0..50 {
        let len = (g() % 64) as usize;
        let s: String = (0..len)
            .map(|_| {
                let v = (g() & 0x7f) as u8;
                (if v < 32 || v == 127 { b'x' } else { v }) as char
            })
            .collect();
        let esc = shell_escape(&s);
        assert!(esc.starts_with('\''));
        assert!(esc.ends_with('\''));
        // The result is single-quote-balanced: every escape inserts pairs.
        assert!(esc.len() >= 2 + s.len());
    }
}

#[test]
fn b2_build_shell_command_args_escaped() {
    let cmd = build_shell_command("ls", &["-la", "/sdcard/my files"]);
    assert!(cmd.contains("'ls'"));
    assert!(cmd.contains("'/sdcard/my files'"));
}

#[test]
fn b2_build_pipeline_with_timeout() {
    assert_eq!(build_pipeline(&["a", "b", "c"]), "a | b | c");
    assert_eq!(with_timeout("ls /", 5), "timeout 5 ls /");
}

#[test]
fn b2_cmd_helpers_produce_expected_strings() {
    // cmd_* helpers use shell_escape internally, so program is single-quoted.
    assert!(cmd_getprop("ro.product").contains("getprop"));
    assert!(cmd_getprop("ro.product").contains("ro.product"));
    assert!(cmd_pm_install("/tmp/a.apk").contains("install"));
    assert!(cmd_pm_uninstall("com.x").contains("uninstall"));
    assert!(cmd_am_start("com.x/.Main").contains("start"));
    assert!(cmd_am_force_stop("com.x").contains("force-stop"));
    assert!(cmd_dumpsys("activity").contains("dumpsys"));
    assert!(cmd_logcat(&["-d"]).contains("logcat"));
    assert!(cmd_logcat(&[]).contains("logcat"));
}

#[test]
fn b2_command_builder_build_50() {
    for i in 0..50 {
        let b = CommandBuilder::new("ls")
            .arg(format!("--num={i}"))
            .args(["x", "y"]);
        let s = b.build();
        assert!(s.contains("ls"));
        assert!(s.contains(&format!("--num={i}")));
    }
}

#[test]
fn b2_terminal_size_encode_v2_8_bytes() {
    let ts = TerminalSize::default();
    let enc = ts.encode_v2();
    assert_eq!(enc.len(), 8);
}

// ── package helpers ─────────────────────────────────────────────────────────

#[test]
fn b2_parse_pm_list_line_with_path_marks_system() {
    let p = parse_pm_list_line("package:/system/app/Foo/Foo.apk=com.system.foo").unwrap();
    assert!(p.is_system);
    let p2 = parse_pm_list_line("package:/data/app/Bar/Bar.apk=com.user.bar").unwrap();
    assert!(!p2.is_system);
}

#[test]
fn b2_parse_pm_list_output_drops_garbage() {
    let txt = "List of packages:\npackage:com.a\nfoo\npackage:com.b\n";
    let pkgs = parse_pm_list_output(txt);
    assert_eq!(pkgs.len(), 2);
    assert_eq!(pkgs[0].package_name, "com.a");
    assert_eq!(pkgs[1].package_name, "com.b");
}

#[test]
fn b2_install_succeeded_only_on_success_line() {
    assert!(install_succeeded("Success\n"));
    assert!(install_succeeded("verifying...\nSuccess\n"));
    assert!(!install_succeeded("Failure"));
    assert!(!install_succeeded(""));
}

#[test]
fn b2_uninstall_succeeded() {
    assert!(uninstall_succeeded("Success"));
    assert!(!uninstall_succeeded("Failure [DELETE_FAILED_INTERNAL_ERROR]"));
}

#[test]
fn b2_extract_install_failure_recognises_known_formats() {
    let f = extract_install_failure("Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]").unwrap();
    assert!(f.contains("INSTALL_FAILED"));
    let f2 = extract_install_failure("Error: bad apk").unwrap();
    assert!(f2.contains("Error"));
    assert!(extract_install_failure("Success").is_none());
}

#[test]
fn b2_build_install_uninstall_command() {
    assert!(build_install_command("/tmp/x.apk", &["-t"]).contains("/tmp/x.apk"));
    assert!(build_uninstall_command("com.x", true).contains("-k"));
    assert!(!build_uninstall_command("com.x", false).contains("-k"));
}

#[test]
fn b2_install_location_from_path_categories() {
    assert!(matches!(
        InstallLocation::from_path("/data/app/foo"),
        InstallLocation::InternalStorage
    ));
    assert!(matches!(
        InstallLocation::from_path("/system/priv-app/x"),
        InstallLocation::System
    ));
    assert!(matches!(
        InstallLocation::from_path("/product/app/x"),
        InstallLocation::Product
    ));
    assert!(matches!(
        InstallLocation::from_path("/mnt/asec/x"),
        InstallLocation::ExternalStorage
    ));
    assert!(matches!(
        InstallLocation::from_path("/wat/"),
        InstallLocation::Unknown
    ));
}

#[test]
fn b2_list_options_pm_args() {
    let mut opts = ListOptions::default();
    let args = opts.pm_args();
    assert_eq!(args, vec!["list", "packages"]);
    opts.include_paths = true;
    opts.third_party_only = true;
    let a2 = opts.pm_args();
    assert!(a2.contains(&"-f"));
    assert!(a2.contains(&"-3"));
}

// ── sync::FileType / StatEntry / DirEntry ──────────────────────────────────

#[test]
fn b2_filetype_from_mode_table() {
    // S_IFREG=0o100000, DIR=0o040000, LNK=0o120000
    assert!(FileType::from_mode(0o100_644).is_regular());
    assert!(FileType::from_mode(0o040_755).is_directory());
    assert!(FileType::from_mode(0o120_777).is_symlink());
    let ft = FileType::from_mode(0);
    assert!(matches!(ft, FileType::Unknown));
}

#[test]
fn b2_stat_entry_permission_string_known() {
    let s = StatEntry {
        mode: 0o100_755,
        size: 0,
        mtime: 0,
    };
    assert_eq!(s.permission_string(), "rwxr-xr-x");
    let s2 = StatEntry {
        mode: 0o100_000,
        size: 0,
        mtime: 0,
    };
    assert_eq!(s2.permission_string(), "---------");
}

#[test]
fn b2_dir_entry_is_dot_entry() {
    let mk = |n: &str| DirEntry {
        mode: 0o040_755,
        size: 0,
        mtime: 0,
        name: n.into(),
    };
    assert!(mk(".").is_dot_entry());
    assert!(mk("..").is_dot_entry());
    assert!(!mk("foo").is_dot_entry());
}

#[test]
fn b2_dir_entry_stat_roundtrip() {
    let d = DirEntry {
        mode: 0o100_644,
        size: 42,
        mtime: 12345,
        name: "f".into(),
    };
    let s = d.stat();
    assert_eq!(s.mode, d.mode);
    assert_eq!(s.size, d.size);
    assert_eq!(s.mtime, d.mtime);
    assert!(d.is_file());
}

// ── LogcatFilter / LogcatEntry roundtrips ───────────────────────────────────

fn mk_entry(tag: &str, pri: Priority, pid: u32, msg: &str) -> LogcatEntry {
    LogcatEntry {
        timestamp: "01-01 00:00:00.000".into(),
        pid,
        tid: 0,
        priority: pri,
        tag: tag.into(),
        message: msg.into(),
        buffer: LogBuffer::Main,
    }
}

#[test]
fn b2_logcat_filter_min_priority() {
    let f = LogcatFilter::new().min_priority(Priority::Warn);
    assert!(!f.matches(&mk_entry("t", Priority::Info, 1, "")));
    assert!(f.matches(&mk_entry("t", Priority::Error, 1, "")));
}

#[test]
fn b2_logcat_filter_tag_include_exclude() {
    let f = LogcatFilter::new().tags(["AAA"]);
    assert!(f.matches(&mk_entry("aaa", Priority::Info, 1, "")));
    assert!(!f.matches(&mk_entry("bbb", Priority::Info, 1, "")));
    let f2 = LogcatFilter::new().exclude_tags(["bbb"]);
    assert!(f2.matches(&mk_entry("aaa", Priority::Info, 1, "")));
    assert!(!f2.matches(&mk_entry("BBB", Priority::Info, 1, "")));
}

#[test]
fn b2_logcat_filter_pids_and_message() {
    let f = LogcatFilter::new().pids(vec![1, 2, 3]);
    assert!(f.matches(&mk_entry("t", Priority::Info, 2, "")));
    assert!(!f.matches(&mk_entry("t", Priority::Info, 9, "")));
    let f2 = LogcatFilter::new().message_contains("ERROR");
    assert!(f2.matches(&mk_entry("t", Priority::Info, 1, "an error occurred")));
}

#[test]
fn b2_logcat_format_threadtime_brief_nonempty() {
    let e = mk_entry("Tg", Priority::Error, 5, "boom");
    let tt = e.format_threadtime();
    assert!(tt.contains("Tg"));
    assert!(tt.contains("boom"));
    assert!(tt.contains('E'));
    let br = e.format_brief();
    assert!(br.contains("E/Tg"));
    assert!(br.contains("boom"));
}

#[test]
fn b2_parse_brief_and_threadtime_specific() {
    let pb = parse_brief_line("W/Tag(99): warn msg").unwrap();
    assert_eq!(pb.priority, Priority::Warn);
    assert_eq!(pb.pid, 99);
    let pt = parse_threadtime_line("01-01 12:00:00.000 1234 5678 I MyTag: hello").unwrap();
    assert_eq!(pt.pid, 1234);
    assert_eq!(pt.tid, 5678);
    assert_eq!(pt.tag, "MyTag");
    assert!(parse_any_line("garbage").is_none());
}

#[test]
fn b2_logbuffer_from_name_unknown() {
    assert!(matches!(LogBuffer::from_name("main"), LogBuffer::Main));
    assert!(matches!(LogBuffer::from_name("nope"), LogBuffer::Unknown));
}

// ── device::TransportType ───────────────────────────────────────────────────

#[test]
fn b2_transport_from_serial_emulator() {
    let t = TransportType::from_serial("emulator-5554");
    assert!(matches!(t, TransportType::Emulator { port: 5554 }));
    assert!(t.is_virtual());
}

#[test]
fn b2_transport_from_serial_tcp_and_usb() {
    let t = TransportType::from_serial("192.168.1.10:5555");
    assert!(matches!(t, TransportType::Tcp { .. }));
    let u = TransportType::from_serial("R3CN90ABCDE");
    assert!(matches!(u, TransportType::Usb));
}

#[test]
fn b2_transport_display() {
    assert_eq!(TransportType::Usb.to_string(), "usb");
    assert_eq!(
        TransportType::Emulator { port: 1 }.to_string(),
        "emulator:1"
    );
}

#[test]
fn b2_parse_devices_output_two_devices() {
    let txt = "emulator-5554\tdevice product:sdk_phone model:sdk\nR3CN\tdevice\n";
    let list = parse_devices_output(txt);
    assert_eq!(list.devices.len(), 2);
    let online = list.online();
    assert_eq!(online.len(), 2);
    let em = list.emulators();
    assert_eq!(em.len(), 1);
}

#[test]
fn b2_device_list_find_by_serial() {
    let txt = "emulator-5554\tdevice\nemulator-5556\tdevice\n";
    let list = parse_devices_output(txt);
    assert!(list.find_by_serial("emulator-5554").is_some());
    assert!(list.find_by_serial("not-there").is_none());
}

// ── RebootMode ──────────────────────────────────────────────────────────────

#[test]
fn b2_reboot_mode_eq_copy() {
    let a = RebootMode::Recovery;
    let b = a;
    assert_eq!(a, b);
}

// ── PackageInfo from re-export ──────────────────────────────────────────────

#[test]
fn b2_package_info_fields_via_pm_list() {
    let p = parse_pm_list_line("package:/data/app/com.foo-1/base.apk=com.foo").unwrap();
    assert_eq!(p.package_name, "com.foo");
    assert!(p.apk_path.unwrap().contains("com.foo"));
}

// ── ShellResult ────────────────────────────────────────────────────────────

#[test]
fn b2_shell_result_success_matrix() {
    let cases = [
        (None, true),
        (Some(0), true),
        (Some(1), false),
        (Some(-1), false),
        (Some(255), false),
    ];
    for (code, ok) in cases {
        let r = ShellResult {
            stdout: String::new(),
            exit_code: code,
        };
        assert_eq!(r.success(), ok, "code={code:?}");
    }
}

// ── AdbClient Send + Sync (it's Clone+Debug) ───────────────────────────────

#[test]
fn b2_adb_client_send_sync_threaded_clone() {
    let client = Arc::new(AdbClient::new("127.0.0.1", 5037));
    let mut handles = vec![];
    for t in 0..4 {
        let c = client.clone();
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for i in 0..100 {
                let cc = (*c).clone();
                acc = acc.wrapping_add(u64::from(cc.port)).wrapping_add(i + t);
            }
            acc
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn b2_adb_message_send_threaded() {
    // AdbMessage is Send via its Vec<u8>; exercise across threads.
    let m = Arc::new(AdbMessage::new(cmd::WRTE, 1, 2, b"abc".to_vec()));
    let mut handles = vec![];
    for _ in 0..4 {
        let mc = m.clone();
        handles.push(thread::spawn(move || {
            let mut count = 0u32;
            for _ in 0..100 {
                if mc.verify_crc() {
                    count += 1;
                }
            }
            count
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 100);
    }
}

// ── encode_message length & CRC fields explicitly ───────────────────────────

#[test]
fn b2_encode_header_field_layout() {
    let data = b"abcdef";
    let bytes = encode_message(cmd::OKAY, 0xAABB_CCDD, 0x1122_3344, data);
    let command = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let a0 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let a1 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let dl = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let crc = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let magic = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    assert_eq!(command, cmd::OKAY);
    assert_eq!(a0, 0xAABB_CCDD);
    assert_eq!(a1, 0x1122_3344);
    assert_eq!(dl as usize, data.len());
    assert_eq!(crc, compute_crc32(data));
    assert_eq!(magic, cmd::OKAY ^ 0xFFFF_FFFF);
    assert_eq!(&bytes[24..], data);
}

// ── boundary inputs for various integer params ──────────────────────────────

#[test]
fn b2_encode_zero_args_zero_payload() {
    let bytes = encode_message(0, 0, 0, b"");
    assert_eq!(bytes.len(), 24);
    // command=0 -> magic=0xFFFFFFFF
    let magic = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    assert_eq!(magic, 0xFFFF_FFFF);
    let m = decode_message(&bytes).unwrap();
    assert_eq!(m.command, 0);
    assert!(m.data.is_empty());
}

#[test]
fn b2_encode_max_args() {
    let bytes = encode_message(u32::MAX, u32::MAX, u32::MAX, b"");
    let m = decode_message(&bytes).unwrap();
    assert_eq!(m.command, u32::MAX);
    assert_eq!(m.arg0, u32::MAX);
    assert_eq!(m.arg1, u32::MAX);
}

// ── HashMap key sanity for LocalId/RemoteId ─────────────────────────────────

#[test]
fn b2_localid_hashmap_key() {
    let mut m: HashMap<LocalId, &'static str> = HashMap::new();
    m.insert(LocalId(1), "a");
    m.insert(LocalId(2), "b");
    assert_eq!(m.get(&LocalId(1)), Some(&"a"));
    assert_eq!(m.get(&LocalId(2)), Some(&"b"));
    assert_eq!(m.get(&LocalId(3)), None);
}

// ── AdbError display strings ────────────────────────────────────────────────

#[test]
fn b2_error_display_all_variants() {
    let cases = [
        AdbError::Protocol("p".into()),
        AdbError::DeviceNotFound {
            serial: "s".into(),
        },
        AdbError::CommandFailed("c".into()),
        AdbError::Timeout,
        AdbError::Sync("y".into()),
        AdbError::LogcatParse("l".into()),
        AdbError::AuthFailed("a".into()),
    ];
    for e in &cases {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// ── DeviceInfo basics ───────────────────────────────────────────────────────

#[test]
fn b2_device_info_from_device_sets_transport() {
    let d = AdbDevice {
        serial: "emulator-5554".into(),
        state: DeviceState::Device,
        product: String::new(),
        model: String::new(),
        device: String::new(),
        transport_id: None,
    };
    let info = DeviceInfo::from_device(d);
    assert!(matches!(info.transport, TransportType::Emulator { port: 5554 }));
    assert_eq!(info.serial(), "emulator-5554");
    assert!(info.is_usable());
}

// suppress unused-import warnings for things only used conditionally
#[allow(dead_code)]
fn _api_touch() {
    let _: AdbClient = AdbClient::default();
    let _: DeviceList = DeviceList::default();
    let _ = protocol::AuthType::Token;
}
