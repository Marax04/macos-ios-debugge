//! Blitz test suite for rustre-adb. Aims to surface bugs in public API.

use rustre_adb::*;
use rustre_adb::device::{DeviceInfo, DeviceList, DeviceSelector, TransportType, parse_devices_output};
use rustre_adb::logcat::{
    BinaryLogEntry, LogBuffer, LogcatEntry, LogcatFilter, LogcatFormat, LogcatReader,
    LogcatStats, Priority, filter_by_pid, filter_by_priority,
    format_unix_timestamp, parse_any_line, parse_binary_log, parse_brief_line,
    parse_tag_line, parse_text_output, parse_threadtime_line, parse_threadtime_output,
};
use rustre_adb::package::{
    AdbPackageManager, InstallLocation, ListOptions, PackageFlags,
    build_install_command, build_uninstall_command, extract_install_failure,
    install_succeeded, parse_pm_dump, parse_pm_list_line, parse_pm_list_output,
    uninstall_succeeded,
};
use rustre_adb::protocol::{
    AdbFeature, AdbRsaKey, AuthType, HandshakeState, LocalId, RemoteId, build_banner,
    make_auth_public_key, make_auth_signature, make_auth_token, make_close,
    make_connect, make_okay, make_open, make_write, parse_features,
};
use rustre_adb::shell::{
    CommandBuilder, build_pipeline, build_shell_command, cmd_am_force_stop,
    cmd_am_start, cmd_dumpsys, cmd_getprop, cmd_logcat, cmd_pm_install,
    cmd_pm_uninstall, shell_escape, with_timeout,
};
use rustre_adb::sync::{DirEntry as SyncDirEntry, FileType, StatEntry as SyncStatEntry};

// ── encode_message / decode_message ────────────────────────────────────────────

#[test]
fn t_encode_message_includes_payload() {
    let bytes = encode_message(cmd::WRTE, 1, 2, b"abc");
    assert_eq!(bytes.len(), 24 + 3);
    assert_eq!(&bytes[24..], b"abc");
}

#[test]
fn t_decode_truncated_24() {
    assert!(decode_message(&[]).is_err());
    assert!(decode_message(&[0u8; 23]).is_err());
}

#[test]
fn t_decode_oversized_declared_len() {
    // Build a 24-byte header that declares 1_000_000 bytes payload but supply 0 bytes.
    let bytes = encode_message(cmd::WRTE, 0, 0, &[0u8; 0]);
    let mut tampered = bytes.to_vec();
    // overwrite data_len field (bytes 12..16) with huge value
    tampered[12..16].copy_from_slice(&1_000_000u32.to_le_bytes());
    let r = decode_message(&tampered);
    assert!(matches!(r, Err(AdbError::Protocol(_))));
}

#[test]
fn t_compute_crc32_max_byte() {
    assert_eq!(compute_crc32(&[0xFFu8; 4]), 0xFF * 4);
}

#[test]
fn t_compute_crc32_wrap() {
    // 1 + 256*(0xFF)*0 ... ensure wrapping_add is used: no actual overflow on 4 bytes.
    let v = vec![0xFFu8; 100];
    let s: u32 = v.iter().map(|&b| u32::from(b)).sum();
    assert_eq!(compute_crc32(&v), s);
}

#[test]
fn t_adb_message_roundtrip_large_payload() {
    let data = vec![0xABu8; 4096];
    let m = AdbMessage::new(cmd::WRTE, 7, 8, data.clone());
    let enc = m.encode();
    let dec = decode_message(&enc).unwrap();
    assert_eq!(dec.data, data);
    assert!(dec.verify_crc());
}

// ── DeviceState ────────────────────────────────────────────────────────────────

#[test]
fn t_device_state_sideload_online() {
    assert!(DeviceState::Sideload.is_online());
    assert!(!DeviceState::Bootloader.is_online());
}

#[test]
fn t_device_state_display_no_permissions() {
    assert_eq!(DeviceState::NoPermissions.to_string(), "no-permissions");
}

// ── AdbDevice parse ────────────────────────────────────────────────────────────

#[test]
fn t_adb_device_parse_via_devices_output() {
    // Exercise AdbDevice::parse through the public parse_devices_output helper
    let out = "abc\tdevice transport_id:notanumber\n";
    let list = parse_devices_output(out);
    assert_eq!(list.len(), 1);
    assert!(list.devices[0].device.transport_id.is_none());
}

#[test]
fn t_adb_device_parse_whitespace_serial_skipped() {
    let out = "   \tdevice\n";
    let list = parse_devices_output(out);
    assert!(list.is_empty());
}

// ── LogLevel ──────────────────────────────────────────────────────────────────

#[test]
fn t_loglevel_silent_severity_max() {
    assert!(LogLevel::Silent.severity() > LogLevel::Fatal.severity());
}

#[test]
fn t_loglevel_as_char_roundtrip() {
    for l in [LogLevel::Verbose, LogLevel::Debug, LogLevel::Info, LogLevel::Warning,
              LogLevel::Error, LogLevel::Fatal, LogLevel::Silent] {
        // Self-check: as_char produces expected single chars
        assert!(['V','D','I','W','E','F','S'].contains(&l.as_char()));
    }
}

// ── PackageInfo: use parse_pm_list_line (public) ──────────────────────────────

#[test]
fn t_packageinfo_pm_line_with_equals_in_path() {
    let line = "package:/data/app/=weird=path=com.x";
    let p = parse_pm_list_line(line).unwrap();
    assert_eq!(p.package_name, "com.x");
}

#[test]
fn t_packageinfo_pm_line_empty_after_prefix() {
    assert!(parse_pm_list_line("package:").is_none());
}

// ── ShellResult ───────────────────────────────────────────────────────────────

#[test]
fn t_shellresult_negative_exit_code_failure() {
    let r = ShellResult { stdout: String::new(), exit_code: Some(-1) };
    assert!(!r.success());
}

// ── shell.rs ──────────────────────────────────────────────────────────────────

#[test]
fn t_shell_escape_no_special() {
    assert_eq!(shell_escape("hello"), "'hello'");
}

#[test]
fn t_shell_escape_single_quote() {
    assert_eq!(shell_escape("it's"), "'it'\\''s'");
}

#[test]
fn t_shell_escape_empty() {
    assert_eq!(shell_escape(""), "''");
}

#[test]
fn t_build_shell_command_args() {
    let s = build_shell_command("ls", &["-la", "/tmp"]);
    assert!(s.contains("'ls'"));
    assert!(s.contains("'-la'"));
    assert!(s.contains("'/tmp'"));
}

#[test]
fn t_build_pipeline_basic() {
    assert_eq!(build_pipeline(&["cat x", "grep y"]), "cat x | grep y");
}

#[test]
fn t_with_timeout_format() {
    assert_eq!(with_timeout("ls", 5), "timeout 5 ls");
}

#[test]
fn t_cmd_getprop() {
    let c = cmd_getprop("ro.product.model");
    assert!(c.contains("getprop"));
    assert!(c.contains("ro.product.model"));
}

#[test]
fn t_cmd_pm_install_uninstall() {
    assert!(cmd_pm_install("/tmp/a.apk").contains("install"));
    assert!(cmd_pm_uninstall("com.x").contains("uninstall"));
}

#[test]
fn t_cmd_am_start_force_stop() {
    assert!(cmd_am_start("com.x/.Main").contains("start"));
    assert!(cmd_am_force_stop("com.x").contains("force-stop"));
}

#[test]
fn t_cmd_dumpsys_logcat() {
    assert!(cmd_dumpsys("battery").contains("battery"));
    let l = cmd_logcat(&[]);
    assert!(l.contains("threadtime"));
    assert!(l.contains("*:V"));
    let l2 = cmd_logcat(&["MyTag:I"]);
    assert!(l2.contains("MyTag:I"));
}

#[test]
fn t_command_builder_basic() {
    let s = CommandBuilder::new("ls").arg("-la").build();
    assert!(s.contains("ls"));
    assert!(s.contains("-la"));
}

#[test]
fn t_command_builder_env_root_timeout() {
    let s = CommandBuilder::new("echo")
        .arg("hi")
        .env("K", "V")
        .timeout(10)
        .as_root()
        .build();
    assert!(s.starts_with("su -c"));
    assert!(s.contains("timeout 10"));
    assert!(s.contains("K="));
}

#[test]
fn t_command_builder_display() {
    let b = CommandBuilder::new("ls");
    assert_eq!(format!("{b}"), b.build());
}

#[test]
fn t_command_builder_args_iter() {
    let s = CommandBuilder::new("p").args(["a", "b", "c"]).build();
    for a in ["a", "b", "c"] {
        assert!(s.contains(a));
    }
}

// ── package.rs ────────────────────────────────────────────────────────────────

#[test]
fn t_install_location_from_path() {
    assert_eq!(InstallLocation::from_path("/data/app/x"), InstallLocation::InternalStorage);
    assert_eq!(InstallLocation::from_path("/system/app/x"), InstallLocation::System);
    assert_eq!(InstallLocation::from_path("/product/app/x"), InstallLocation::Product);
    assert_eq!(InstallLocation::from_path("/mnt/asec/x"), InstallLocation::ExternalStorage);
    assert_eq!(InstallLocation::from_path("/weird/path"), InstallLocation::Unknown);
}

#[test]
fn t_list_options_pm_args() {
    let opts = ListOptions { third_party_only: true, include_paths: true, ..Default::default() };
    let a = opts.pm_args();
    assert!(a.contains(&"-f"));
    assert!(a.contains(&"-3"));
}

#[test]
fn t_list_options_system_excludes_third_party() {
    // both set: implementation uses else if, so third_party wins
    let opts = ListOptions { third_party_only: true, system_only: true, ..Default::default() };
    let a = opts.pm_args();
    assert!(a.contains(&"-3"));
    assert!(!a.contains(&"-s"));
}

#[test]
fn t_parse_pm_list_line_system() {
    let p = parse_pm_list_line("package:/system/app/X.apk=com.sys").unwrap();
    assert!(p.is_system);
}

#[test]
fn t_parse_pm_list_line_non_system() {
    let p = parse_pm_list_line("package:/data/app/X.apk=com.user").unwrap();
    assert!(!p.is_system);
}

#[test]
fn t_parse_pm_list_output_skips_garbage() {
    let out = "garbage\npackage:com.a\npackage:/data/app/X=com.b\n";
    let v = parse_pm_list_output(out);
    assert_eq!(v.len(), 2);
}

#[test]
fn t_build_install_command_options() {
    let s = build_install_command("/tmp/a.apk", &["-t", "-g"]);
    assert!(s.contains("-t"));
    assert!(s.contains("-g"));
    assert!(s.contains("/tmp/a.apk"));
    assert!(s.starts_with("pm install -r"));
}

#[test]
fn t_build_uninstall_command_keep_data() {
    assert!(build_uninstall_command("com.x", true).contains("-k"));
    assert!(!build_uninstall_command("com.x", false).contains("-k"));
}

#[test]
fn t_install_succeeded_basic() {
    assert!(install_succeeded("Success\n"));
    assert!(!install_succeeded("Failure [INSTALL_FAILED_X]\n"));
}

#[test]
fn t_uninstall_succeeded_basic() {
    assert!(uninstall_succeeded("Success"));
    assert!(!uninstall_succeeded("Failure"));
}

#[test]
fn t_extract_install_failure_failure_bracket() {
    let f = extract_install_failure("Failure [INSTALL_FAILED_NO_SPACE]");
    assert_eq!(f.as_deref(), Some("Failure [INSTALL_FAILED_NO_SPACE]"));
}

#[test]
fn t_extract_install_failure_install_failed_prefix() {
    let f = extract_install_failure("INSTALL_FAILED_VERSION_DOWNGRADE");
    assert!(f.is_some());
}

#[test]
fn t_extract_install_failure_none() {
    assert!(extract_install_failure("Success").is_none());
}

#[test]
fn t_parse_pm_dump_extracts_versions() {
    let dump = "    versionCode=42 targetSdk=33\n    versionName=1.2.3\n    userId=10080\n";
    let base = PackageInfo {
        package_name: "com.x".into(),
        apk_path: Some("/data/app/x".into()),
        version_code: None,
        version_name: None,
        is_system: false,
    };
    let d = parse_pm_dump("com.x", dump, base);
    assert_eq!(d.info.version_code, Some(42));
    assert_eq!(d.info.version_name.as_deref(), Some("1.2.3"));
    assert_eq!(d.target_sdk, Some(33));
    assert_eq!(d.uid, Some(10080));
    assert!(d.enabled);
    assert_eq!(d.install_location, InstallLocation::InternalStorage);
}

#[test]
fn t_parse_pm_dump_disabled() {
    let dump = "enabled=false\n";
    let base = PackageInfo {
        package_name: "p".into(), apk_path: None, version_code: None, version_name: None, is_system: false,
    };
    let d = parse_pm_dump("p", dump, base);
    assert!(!d.enabled);
}

#[test]
fn t_package_flags_bits() {
    let f = PackageFlags::SYSTEM | PackageFlags::DEBUGGABLE;
    assert!(f.contains(PackageFlags::SYSTEM));
    assert!(f.contains(PackageFlags::DEBUGGABLE));
    assert!(!f.contains(PackageFlags::PERSISTENT));
}

#[test]
fn t_adb_package_manager_construct() {
    let pm = AdbPackageManager::new(AdbClient::default(), "abc");
    assert_eq!(pm.serial, "abc");
}

// ── device.rs ─────────────────────────────────────────────────────────────────

#[test]
fn t_transport_from_serial_usb() {
    assert_eq!(TransportType::from_serial("R3CN90"), TransportType::Usb);
}

#[test]
fn t_transport_from_serial_emulator() {
    assert_eq!(TransportType::from_serial("emulator-5554"), TransportType::Emulator { port: 5554 });
}

#[test]
fn t_transport_from_serial_tcp() {
    let t = TransportType::from_serial("192.168.1.5:5555");
    match t {
        TransportType::Tcp { address, port } => {
            assert_eq!(address, "192.168.1.5");
            assert_eq!(port, 5555);
        }
        _ => panic!("expected TCP"),
    }
}

#[test]
fn t_transport_label_and_virtual() {
    assert_eq!(TransportType::Usb.label(), "usb");
    assert!(TransportType::Emulator { port: 1 }.is_virtual());
    assert!(!TransportType::Usb.is_virtual());
}

#[test]
fn t_transport_display() {
    assert_eq!(TransportType::Usb.to_string(), "usb");
    assert_eq!(TransportType::Tcp { address: "1.2.3.4".into(), port: 5555 }.to_string(), "tcp:1.2.3.4:5555");
    assert_eq!(TransportType::Emulator { port: 5554 }.to_string(), "emulator:5554");
}

#[test]
fn t_device_info_property_helpers() {
    let mut di = DeviceInfo::from_device(AdbDevice {
        serial: "x".into(), state: DeviceState::Device,
        product: String::new(), model: String::new(), device: String::new(),
        transport_id: None,
    });
    di.set_property("ro.product.model", "Pixel");
    di.set_property("ro.build.version.sdk", "33");
    assert_eq!(di.model(), "Pixel");
    assert_eq!(di.sdk_version(), Some(33));
    assert_eq!(di.android_version(), "unknown");
}

#[test]
fn t_device_info_populate_getprop() {
    let mut di = DeviceInfo::from_device(AdbDevice {
        serial: "x".into(), state: DeviceState::Device,
        product: String::new(), model: String::new(), device: String::new(),
        transport_id: None,
    });
    let out = "[ro.product.model]: [Pixel 5]\n[ro.build.version.sdk]: [33]\n";
    di.populate_properties_from_getprop(out);
    assert_eq!(di.get_property("ro.product.model"), Some("Pixel 5"));
    assert_eq!(di.sdk_version(), Some(33));
}

#[test]
fn t_device_list_filtering() {
    let devs = vec![
        AdbDevice { serial: "emulator-5554".into(), state: DeviceState::Device, product: "p".into(), model: "Emu".into(), device: "d".into(), transport_id: None },
        AdbDevice { serial: "R3CN".into(), state: DeviceState::Offline, product: "p".into(), model: "Pixel".into(), device: "d".into(), transport_id: None },
        AdbDevice { serial: "1.2.3.4:5555".into(), state: DeviceState::Device, product: "p".into(), model: "Tab".into(), device: "d".into(), transport_id: None },
    ];
    let list = DeviceList::from_adb_devices(devs);
    assert_eq!(list.len(), 3);
    assert_eq!(list.emulators().len(), 1);
    assert_eq!(list.tcp_devices().len(), 1);
    assert_eq!(list.usb_devices().len(), 1);
    assert_eq!(list.online().len(), 2);
}

#[test]
fn t_device_list_single_online_multi_err() {
    let devs = vec![
        AdbDevice { serial: "a".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
        AdbDevice { serial: "b".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
    ];
    let list = DeviceList::from_adb_devices(devs);
    assert!(list.single_online().is_err());
}

#[test]
fn t_device_list_single_online_none_err() {
    let list = DeviceList::default();
    assert!(list.single_online().is_err());
    assert!(list.is_empty());
}

#[test]
fn t_device_list_find_by_model_case_insensitive() {
    let mut di = DeviceInfo::from_device(AdbDevice {
        serial: "x".into(), state: DeviceState::Device,
        product: String::new(), model: "Pixel_5".into(), device: String::new(), transport_id: None,
    });
    di.set_property("ro.product.model", "Pixel_5");
    let list = DeviceList { devices: vec![di] };
    assert_eq!(list.find_by_model("pixel").len(), 1);
}

#[test]
fn t_device_list_summary_lengths() {
    let devs = vec![
        AdbDevice { serial: "a".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
    ];
    let list = DeviceList::from_adb_devices(devs);
    assert_eq!(list.summary().len(), 1);
}

#[test]
fn t_device_selector_by_serial() {
    let devs = vec![
        AdbDevice { serial: "abc".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
    ];
    let list = DeviceList::from_adb_devices(devs);
    let sel = DeviceSelector::BySerial("abc".into());
    assert!(sel.resolve(&list).is_ok());
    let sel2 = DeviceSelector::BySerial("nope".into());
    assert!(matches!(sel2.resolve(&list), Err(AdbError::DeviceNotFound { .. })));
}

#[test]
fn t_device_selector_first_emulator_first_usb() {
    let devs = vec![
        AdbDevice { serial: "emulator-5554".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
        AdbDevice { serial: "ABCDEF".into(), state: DeviceState::Device, product: String::new(), model: String::new(), device: String::new(), transport_id: None },
    ];
    let list = DeviceList::from_adb_devices(devs);
    assert!(DeviceSelector::FirstEmulator.resolve(&list).is_ok());
    assert!(DeviceSelector::FirstUsb.resolve(&list).is_ok());
}

#[test]
fn t_parse_devices_output_strips_header() {
    let out = "List of devices attached\nemulator-5554\tdevice\n";
    let list = parse_devices_output(out);
    assert_eq!(list.len(), 1);
}

// ── logcat.rs ─────────────────────────────────────────────────────────────────

#[test]
fn t_priority_from_u8() {
    assert_eq!(Priority::from_u8(2), Priority::Verbose);
    assert_eq!(Priority::from_u8(7), Priority::Fatal);
    assert_eq!(Priority::from_u8(99), Priority::Unknown);
}

#[test]
fn t_priority_ordering() {
    assert!(Priority::Fatal > Priority::Error);
    assert!(Priority::Error > Priority::Warn);
    assert!(Priority::Verbose < Priority::Info);
}

#[test]
fn t_logbuffer_from_name() {
    assert_eq!(LogBuffer::from_name("main"), LogBuffer::Main);
    assert_eq!(LogBuffer::from_name("crash"), LogBuffer::Crash);
    assert_eq!(LogBuffer::from_name("garbage"), LogBuffer::Unknown);
}

#[test]
fn t_logbuffer_as_str_roundtrip() {
    for buf in [LogBuffer::Main, LogBuffer::System, LogBuffer::Radio, LogBuffer::Events,
                LogBuffer::Crash, LogBuffer::Kernel] {
        assert_eq!(LogBuffer::from_name(buf.as_str()), buf);
    }
}

#[test]
fn t_logcat_format_as_str() {
    assert_eq!(LogcatFormat::Threadtime.as_str(), "threadtime");
    assert_eq!(LogcatFormat::Brief.as_str(), "brief");
}

#[test]
fn t_parse_threadtime_line_ok() {
    let line = "01-15 12:00:00.123  1234  5678 I MyTag: hello";
    let e = parse_threadtime_line(line).unwrap();
    assert_eq!(e.pid, 1234);
    assert_eq!(e.tid, 5678);
    assert_eq!(e.priority, Priority::Info);
    assert_eq!(e.tag, "MyTag");
    assert_eq!(e.message, "hello");
}

#[test]
fn t_parse_threadtime_line_separator() {
    assert!(parse_threadtime_line("--------- beginning of main").is_none());
}

#[test]
fn t_parse_brief_line_valid() {
    let e = parse_brief_line("E/AndroidRuntime(1234): FATAL").unwrap();
    assert_eq!(e.priority, Priority::Error);
    assert_eq!(e.pid, 1234);
    assert_eq!(e.tag, "AndroidRuntime");
}

#[test]
fn t_parse_brief_line_invalid_level() {
    assert!(parse_brief_line("X/Tag(1): m").is_none());
}

#[test]
fn t_parse_tag_line() {
    let e = parse_tag_line("I/MyTag: msg here").unwrap();
    assert_eq!(e.priority, Priority::Info);
    assert_eq!(e.tag, "MyTag");
    assert_eq!(e.message, "msg here");
}

#[test]
fn t_parse_any_falls_through() {
    let e = parse_any_line("I/Tag(1): m").unwrap();
    assert_eq!(e.priority, Priority::Info);
}

#[test]
fn t_parse_text_output_multiple() {
    let txt = "I/A(1): one\nE/B(2): two\n";
    let v = parse_text_output(txt);
    assert_eq!(v.len(), 2);
}

#[test]
fn t_parse_threadtime_output() {
    let txt = "01-15 12:00:00.123  1  2 I T: msg\n";
    let v = parse_threadtime_output(txt);
    assert_eq!(v.len(), 1);
}

#[test]
fn t_logcat_filter_min_priority() {
    let f = LogcatFilter::new().min_priority(Priority::Error);
    let info_e = LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "T".into(), message: "m".into(), buffer: LogBuffer::Main };
    let err_e = LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Error, tag: "T".into(), message: "m".into(), buffer: LogBuffer::Main };
    assert!(!f.matches(&info_e));
    assert!(f.matches(&err_e));
}

#[test]
fn t_logcat_filter_tags_pids_msg() {
    let f = LogcatFilter::new()
        .tags(["TagA"])
        .pids(vec![1])
        .message_contains("hello");
    let e = LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "tagA".into(), message: "Hello world".into(), buffer: LogBuffer::Main };
    assert!(f.matches(&e));
    let e2 = LogcatEntry { pid: 2, ..e };
    assert!(!f.matches(&e2));
}

#[test]
fn t_logcat_filter_exclude_tags() {
    let f = LogcatFilter::new().exclude_tags(["Noisy"]);
    let e = LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "noisy".into(), message: String::new(), buffer: LogBuffer::Main };
    assert!(!f.matches(&e));
}

#[test]
fn t_logcat_filter_buffer() {
    let f = LogcatFilter::new().buffer(LogBuffer::System);
    let e = LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "T".into(), message: String::new(), buffer: LogBuffer::Main };
    assert!(!f.matches(&e));
}

#[test]
fn t_logcat_filter_to_logcat_args_empty() {
    let f = LogcatFilter::new();
    assert!(f.to_logcat_args().is_empty());
}

#[test]
fn t_logcat_filter_to_logcat_args_tags() {
    let f = LogcatFilter::new().tags(["A", "B"]).min_priority(Priority::Info);
    let args = f.to_logcat_args();
    assert!(args.contains(&"A:I".to_string()));
    assert!(args.contains(&"B:I".to_string()));
    assert!(args.contains(&"*:S".to_string()));
}

#[test]
fn t_logcat_entry_to_log_entry() {
    let e = LogcatEntry { timestamp: "ts".into(), pid: 1, tid: 2, priority: Priority::Warn, tag: "T".into(), message: "m".into(), buffer: LogBuffer::Main };
    let l = e.to_log_entry();
    assert_eq!(l.level, LogLevel::Warning);
    assert_eq!(l.pid, 1);
    assert_eq!(l.tid, 2);
}

#[test]
fn t_logcat_entry_format() {
    let e = LogcatEntry { timestamp: "T".into(), pid: 1, tid: 2, priority: Priority::Info, tag: "Tag".into(), message: "hi".into(), buffer: LogBuffer::Main };
    let s = e.format_threadtime();
    assert!(s.contains("Tag"));
    assert!(s.contains("hi"));
    let b = e.format_brief();
    assert!(b.starts_with("I/Tag"));
}

#[test]
fn t_logcat_stats() {
    let entries = vec![
        LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "A".into(), message: String::new(), buffer: LogBuffer::Main },
        LogcatEntry { timestamp: String::new(), pid: 2, tid: 0, priority: Priority::Error, tag: "A".into(), message: String::new(), buffer: LogBuffer::Main },
        LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Fatal, tag: "B".into(), message: String::new(), buffer: LogBuffer::Main },
    ];
    let s = LogcatStats::from_entries(&entries);
    assert_eq!(s.total, 3);
    assert_eq!(s.tag_count, 2);
    assert_eq!(s.pid_count, 2);
    assert_eq!(s.severe_count(), 2);
}

#[test]
fn t_logcat_reader_feed_drain() {
    let mut r = LogcatReader::new(LogcatFormat::Threadtime);
    r.feed("01-15 12:00:00.123  1  2 I T: msg\n");
    r.feed("01-15 12:00:00.124  3  4 E T2: bad\n");
    let v = r.drain();
    assert_eq!(v.len(), 2);
    // drain clears
    assert!(r.drain().is_empty());
}

#[test]
fn t_logcat_reader_partial_line_buffered() {
    let mut r = LogcatReader::new(LogcatFormat::Threadtime);
    r.feed("01-15 12:00:00.123  1  2 I T: ms");
    assert!(r.drain().is_empty());
    r.feed("g\n");
    assert_eq!(r.drain().len(), 1);
}

#[test]
fn t_filter_by_priority_pid() {
    let entries = vec![
        LogcatEntry { timestamp: String::new(), pid: 1, tid: 0, priority: Priority::Info, tag: "A".into(), message: String::new(), buffer: LogBuffer::Main },
        LogcatEntry { timestamp: String::new(), pid: 2, tid: 0, priority: Priority::Error, tag: "B".into(), message: String::new(), buffer: LogBuffer::Main },
    ];
    assert_eq!(filter_by_priority(&entries, Priority::Error).len(), 1);
    assert_eq!(filter_by_pid(&entries, 1).len(), 1);
}

#[test]
fn t_format_unix_timestamp_zero() {
    let s = format_unix_timestamp(0, 0);
    assert!(s.contains("00:00:00"));
}

#[test]
fn t_binary_log_entry_parse_payload() {
    // priority byte + tag\0 + message\0
    let mut payload = vec![4u8]; // Info
    payload.extend_from_slice(b"MyTag\0Hello\0");
    let (prio, tag, msg) = BinaryLogEntry::parse_payload(&payload).unwrap();
    assert_eq!(prio, Priority::Info);
    assert_eq!(tag, "MyTag");
    assert_eq!(msg, "Hello");
}

#[test]
fn t_binary_log_entry_parse_empty_payload() {
    assert!(BinaryLogEntry::parse_payload(&[]).is_none());
}

#[test]
fn t_binary_log_entry_parse_full_record() {
    let mut payload_body = vec![4u8]; // Info priority
    payload_body.extend_from_slice(b"Tag\0Msg\0");
    let payload_len = u16::try_from(payload_body.len()).unwrap_or(u16::MAX);
    let mut record = Vec::new();
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes()); // hdr size
    record.extend_from_slice(&100i32.to_le_bytes()); // pid
    record.extend_from_slice(&200i32.to_le_bytes()); // tid
    record.extend_from_slice(&1000i32.to_le_bytes()); // sec
    record.extend_from_slice(&0i32.to_le_bytes()); // nsec
    record.extend_from_slice(&payload_body);
    let (e, n) = BinaryLogEntry::parse(&record).unwrap();
    assert_eq!(e.pid, 100);
    assert_eq!(e.tid, 200);
    assert_eq!(e.tag, "Tag");
    assert_eq!(e.message, "Msg");
    assert_eq!(n, record.len());
}

#[test]
fn t_binary_log_entry_parse_too_short() {
    assert!(BinaryLogEntry::parse(&[0u8; 19]).is_none());
}

#[test]
fn t_parse_binary_log_truncated_stops() {
    // 20 bytes header declaring 100 bytes payload but only header
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&100u16.to_le_bytes());
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&[0u8; 16]);
    let v = parse_binary_log(&hdr);
    assert!(v.is_empty());
}

// ── sync.rs ───────────────────────────────────────────────────────────────────

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

#[test]
fn t_filetype_from_mode() {
    assert_eq!(FileType::from_mode(S_IFREG | 0o644), FileType::Regular);
    assert_eq!(FileType::from_mode(S_IFDIR | 0o755), FileType::Directory);
    assert_eq!(FileType::from_mode(S_IFLNK | 0o777), FileType::Symlink);
    assert_eq!(FileType::from_mode(0), FileType::Unknown);
}

#[test]
fn t_filetype_predicates_and_display() {
    assert!(FileType::Regular.is_regular());
    assert!(FileType::Directory.is_directory());
    assert!(FileType::Symlink.is_symlink());
    assert_eq!(FileType::Regular.to_string(), "-");
    assert_eq!(FileType::Directory.to_string(), "d");
    assert_eq!(FileType::Symlink.to_string(), "l");
}

#[test]
fn t_stat_entry_helpers() {
    let st = SyncStatEntry { mode: S_IFREG | 0o644, size: 100, mtime: 0 };
    assert!(st.is_file());
    assert!(!st.is_dir());
    assert_eq!(st.permissions(), 0o644);
    assert_eq!(st.file_type(), FileType::Regular);
}

#[test]
fn t_stat_entry_permission_string() {
    let st = SyncStatEntry { mode: 0o755, size: 0, mtime: 0 };
    assert_eq!(st.permission_string(), "rwxr-xr-x");
    let st2 = SyncStatEntry { mode: 0o644, size: 0, mtime: 0 };
    assert_eq!(st2.permission_string(), "rw-r--r--");
}

#[test]
fn t_dir_entry_dot_and_helpers() {
    let d = SyncDirEntry { mode: S_IFDIR | 0o755, size: 0, mtime: 0, name: ".".into() };
    assert!(d.is_dot_entry());
    assert!(d.is_dir());
    let d2 = SyncDirEntry { mode: S_IFREG, size: 0, mtime: 0, name: "f".into() };
    assert!(!d2.is_dot_entry());
    assert!(d2.is_file());
}

#[test]
fn t_dir_entry_display() {
    let d = SyncDirEntry { mode: S_IFREG | 0o644, size: 1024, mtime: 0, name: "x".into() };
    let s = format!("{d}");
    assert!(s.contains('x'));
    assert!(s.contains("1024"));
}

// ── protocol.rs ───────────────────────────────────────────────────────────────

#[test]
fn t_auth_type_roundtrip() {
    assert_eq!(AuthType::from_u32(1), Some(AuthType::Token));
    assert_eq!(AuthType::from_u32(2), Some(AuthType::Signature));
    assert_eq!(AuthType::from_u32(3), Some(AuthType::RsaPublicKey));
    assert_eq!(AuthType::from_u32(99), None);
    assert_eq!(AuthType::Token.as_u32(), 1);
}

#[test]
fn t_make_connect_has_cnxn_cmd() {
    let m = make_connect("host", "RustRE/1.0");
    assert_eq!(m.command, cmd::CNXN);
    assert_eq!(m.arg0, ADB_VERSION);
    assert_eq!(m.arg1, ADB_MAX_PAYLOAD);
    // Banner ends with NUL
    assert_eq!(*m.data.last().unwrap(), 0);
}

#[test]
fn t_make_auth_messages() {
    let t = make_auth_token(vec![1, 2, 3]);
    assert_eq!(t.command, cmd::AUTH);
    assert_eq!(t.arg0, 1);
    let s = make_auth_signature(vec![4, 5]);
    assert_eq!(s.arg0, 2);
    let k = make_auth_public_key("PEMDATA");
    assert_eq!(k.arg0, 3);
    assert_eq!(*k.data.last().unwrap(), 0);
}

#[test]
fn t_make_open_okay_close_write() {
    let o = make_open(LocalId(7), "shell:ls");
    assert_eq!(o.command, cmd::OPEN);
    assert_eq!(o.arg0, 7);
    assert_eq!(*o.data.last().unwrap(), 0);

    let k = make_okay(LocalId(1), RemoteId(2));
    assert_eq!(k.command, cmd::OKAY);
    assert_eq!(k.arg0, 1);
    assert_eq!(k.arg1, 2);

    let c = make_close(LocalId(1), RemoteId(2));
    assert_eq!(c.command, cmd::CLSE);

    let w = make_write(LocalId(1), RemoteId(2), vec![0xAA; 16]);
    assert_eq!(w.command, cmd::WRTE);
    assert_eq!(w.data.len(), 16);
}

#[test]
#[should_panic(expected = "payload")]
fn t_make_write_oversized_panics() {
    // ADB_MAX_PAYLOAD = 256 * 1024
    let _ = make_write(LocalId(0), RemoteId(0), vec![0u8; (ADB_MAX_PAYLOAD as usize) + 1]);
}

#[test]
fn t_adb_feature_parse_known_and_other() {
    assert_eq!(AdbFeature::parse("shell_v2"), AdbFeature::ShellV2);
    assert_eq!(AdbFeature::parse("cmd"), AdbFeature::Cmd);
    match AdbFeature::parse("custom_xyz") {
        AdbFeature::Other(s) => assert_eq!(s, "custom_xyz"),
        _ => panic!(),
    }
}

#[test]
fn t_adb_feature_as_str_roundtrip() {
    for f in [AdbFeature::ShellV2, AdbFeature::Cmd, AdbFeature::StatV2, AdbFeature::LsV2,
              AdbFeature::FixedPushMkdir, AdbFeature::Apex, AdbFeature::Abb, AdbFeature::PushSyncSendV2] {
        let s = f.as_str();
        assert_eq!(AdbFeature::parse(s), f);
    }
}

#[test]
fn t_parse_features_empty() {
    assert!(parse_features("host::banner").is_empty());
    assert!(parse_features("").is_empty());
}

#[test]
fn t_parse_features_present() {
    let v = parse_features("device::name;features=shell_v2,cmd,stat_v2");
    assert!(v.contains(&AdbFeature::ShellV2));
    assert!(v.contains(&AdbFeature::Cmd));
    assert!(v.contains(&AdbFeature::StatV2));
}

#[test]
fn t_build_banner_no_features() {
    assert_eq!(build_banner("host", "x", &[]), "host::x");
}

#[test]
fn t_build_banner_with_features_roundtrip() {
    let feats = vec![AdbFeature::ShellV2, AdbFeature::Cmd];
    let b = build_banner("host", "x", &feats);
    assert!(b.contains("features=shell_v2,cmd"));
    let parsed = parse_features(&b);
    assert_eq!(parsed, feats);
}

#[test]
fn t_adb_rsa_key_from_der_and_format() {
    let k = AdbRsaKey::from_der(vec![0xDE, 0xAD], vec![0xBE, 0xEF], "test@host");
    assert!(k.has_private_key());
    let s = k.public_key_adb_format();
    assert!(s.ends_with("test@host\n"));
}

#[test]
fn t_adb_rsa_key_load_from_pem() {
    let k = AdbRsaKey::load_from_pem("PUB", "PRIV", "n").unwrap();
    assert!(k.has_private_key());
}

#[test]
fn t_adb_rsa_key_generate_stub_sizes() {
    let k = AdbRsaKey::generate_stub("u@h");
    assert_eq!(k.public_key_der.len(), 294);
    assert_eq!(k.private_key_der.len(), 1218);
    let sig = k.sign_token(b"token").unwrap();
    assert_eq!(sig.len(), 256);
}

#[test]
fn t_adb_rsa_key_sign_without_priv_errors() {
    let k = AdbRsaKey::from_der(vec![1, 2], vec![], "n");
    assert!(!k.has_private_key());
    let r = k.sign_token(b"x");
    assert!(matches!(r, Err(AdbError::AuthFailed(_))));
}

#[test]
fn t_handshake_state_variants() {
    let s = HandshakeState::Connected { device_banner: "x".into() };
    match s {
        HandshakeState::Connected { device_banner } => assert_eq!(device_banner, "x"),
        _ => panic!(),
    }
}

// ── async tokio I/O smoke tests ───────────────────────────────────────────────

#[tokio::test]
async fn t_protocol_read_write_message_roundtrip() {
    use tokio::io::duplex;
    let (mut a, mut b) = duplex(1024);
    let msg = AdbMessage::new(cmd::WRTE, 1, 2, b"hello".to_vec());
    rustre_adb::protocol::write_message(&mut a, &msg).await.unwrap();
    let got = rustre_adb::protocol::read_message(&mut b).await.unwrap();
    assert_eq!(got.command, cmd::WRTE);
    assert_eq!(got.data, b"hello");
}

#[tokio::test]
async fn t_protocol_read_rejects_bad_crc() {
    use tokio::io::{duplex, AsyncWriteExt};
    let (mut a, mut b) = duplex(1024);
    // Build valid encoding then flip CRC byte
    let mut enc = encode_message(cmd::WRTE, 0, 0, b"hi").to_vec();
    enc[16] ^= 0xFF;
    a.write_all(&enc).await.unwrap();
    let r = rustre_adb::protocol::read_message(&mut b).await;
    assert!(matches!(r, Err(AdbError::Protocol(_))));
}

#[tokio::test]
async fn t_protocol_read_rejects_oversized() {
    use tokio::io::{duplex, AsyncWriteExt};
    let (mut a, mut b) = duplex(64);
    // Construct a header that declares len > ADB_MAX_PAYLOAD
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&cmd::WRTE.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&(ADB_MAX_PAYLOAD + 1).to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&(cmd::WRTE ^ 0xFFFF_FFFF).to_le_bytes());
    a.write_all(&hdr).await.unwrap();
    let r = rustre_adb::protocol::read_message(&mut b).await;
    assert!(matches!(r, Err(AdbError::Protocol(_))));
}
