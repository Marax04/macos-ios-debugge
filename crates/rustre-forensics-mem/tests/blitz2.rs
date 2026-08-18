//! Deep adversarial blitz2 tests for rustre-forensics-mem.
//!
//! Covers: seeded LCG fuzz of every parser, boundary conditions,
//! round-trips, threaded Send+Sync stress, hash/eq consistency.

use rustre_forensics::{ArchBits, OsType, RawMemoryImage};
use rustre_forensics_mem::process_tree::{
    ProcessTree as PtTree, compute_stats, render_tree,
};
use rustre_forensics_mem::strings_extractor::{
    self as se, MemString, StringClass, StringEncoding, StringExtractionConfig,
};
use rustre_forensics_mem::*;
use std::sync::Arc;

// ── seeded LCG ──────────────────────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut g = lcg();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        out.extend_from_slice(&g().to_le_bytes());
    }
    out.truncate(n);
    out
}

// ── WindowsVersion ──────────────────────────────────────────────────────────

#[test]
fn wv_serde_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = WindowsVersion::new(g() as u32, g() as u32, g() as u32);
        let j = serde_json::to_string(&v).unwrap();
        let v2: WindowsVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(v, v2);
        assert_eq!(v.display(), format!("{}.{}.{}", v.major, v.minor, v.build));
    }
}

#[test]
fn wv_eq_30_pairs() {
    let mut all: Vec<WindowsVersion> = Vec::new();
    for i in 0..30u32 {
        let v = WindowsVersion::new(10, 0, 19000 + i);
        let v2 = WindowsVersion::new(10, 0, 19000 + i);
        assert_eq!(v, v2);
        assert!(all.iter().all(|x| *x != v));
        all.push(v);
    }
    assert_eq!(all.len(), 30);
    // distinct
    for i in 0..30 {
        for j in (i + 1)..30 {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ── ThreadState ─────────────────────────────────────────────────────────────

#[test]
fn ts_all_u8_values() {
    for v in 0u8..=255 {
        let s = ThreadState::from_u8(v);
        if v <= 7 {
            assert_ne!(s, ThreadState::Unknown);
        } else {
            assert_eq!(s, ThreadState::Unknown);
        }
    }
}

#[test]
fn ts_eq_consistency() {
    let pairs = [
        (0u8, ThreadState::Initialized),
        (1, ThreadState::Ready),
        (2, ThreadState::Running),
        (3, ThreadState::Standby),
        (4, ThreadState::Terminated),
        (5, ThreadState::Wait),
        (6, ThreadState::Transition),
        (7, ThreadState::DeferredReady),
    ];
    for (v, expect) in pairs {
        assert_eq!(ThreadState::from_u8(v), expect);
    }
}

// ── ConnectionState ─────────────────────────────────────────────────────────

#[test]
fn cs_all_u8_values_no_panic() {
    for v in 0u8..=255 {
        let _ = ConnectionState::from_u8(v);
    }
}

#[test]
fn cs_known_values() {
    assert_eq!(ConnectionState::from_u8(1), ConnectionState::Listen);
    assert_eq!(ConnectionState::from_u8(5), ConnectionState::Established);
    assert_eq!(ConnectionState::from_u8(12), ConnectionState::Closed);
    assert_eq!(ConnectionState::from_u8(0), ConnectionState::Unknown);
    assert_eq!(ConnectionState::from_u8(99), ConnectionState::Unknown);
}

// ── NetProtocol ─────────────────────────────────────────────────────────────

#[test]
fn np_as_str_all_variants() {
    assert_eq!(NetProtocol::TcpV4.as_str(), "TCPv4");
    assert_eq!(NetProtocol::TcpV6.as_str(), "TCPv6");
    assert_eq!(NetProtocol::UdpV4.as_str(), "UDPv4");
    assert_eq!(NetProtocol::UdpV6.as_str(), "UDPv6");
}

// ── VadType ─────────────────────────────────────────────────────────────────

#[test]
fn vad_type_from_flags_all_3bit_values() {
    let expected = [
        VadType::Private,
        VadType::Mapped,
        VadType::Image,
        VadType::Physical,
        VadType::Unknown,
        VadType::Unknown,
        VadType::Unknown,
        VadType::Unknown,
    ];
    for (i, e) in expected.iter().enumerate() {
        let flags = (i as u32) << 2;
        assert_eq!(VadType::from_flags(flags), *e);
    }
}

#[test]
fn vad_type_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let _ = VadType::from_flags(g() as u32);
    }
}

// ── HiveType ────────────────────────────────────────────────────────────────

#[test]
fn hive_type_from_name() {
    assert_eq!(HiveType::from_name("SAM"), HiveType::Sam);
    assert_eq!(HiveType::from_name("SECURITY"), HiveType::Security);
    assert_eq!(HiveType::from_name("SoFtWaRe"), HiveType::Software);
    assert_eq!(HiveType::from_name("\\SYSTEM\\"), HiveType::System);
    assert_eq!(HiveType::from_name("ntuser.dat"), HiveType::Ntuser);
    assert_eq!(HiveType::from_name("UNKNOWN"), HiveType::Other);
}

#[test]
fn hive_type_fuzz_random_names() {
    let mut g = lcg();
    for _ in 0..50 {
        let bytes = g().to_le_bytes();
        let s = String::from_utf8_lossy(&bytes).into_owned();
        let _ = HiveType::from_name(&s);
    }
}

// ── ProcessInfo.name_matches ────────────────────────────────────────────────

#[test]
fn process_info_name_matches_caseless() {
    let p = ProcessInfo {
        pid: 1,
        ppid: 0,
        name: "Explorer.EXE".into(),
        base: 0,
        size: 0,
        threads: vec![],
        modules: vec![],
        handle_count: 0,
        create_time: 0,
    };
    assert!(p.name_matches("explorer"));
    assert!(p.name_matches("EXE"));
    assert!(p.name_matches(""));
    assert!(!p.name_matches("missing"));
}

// ── WindowsAnalyzer fuzz ────────────────────────────────────────────────────

fn raw_img(bytes: Vec<u8>) -> RawMemoryImage {
    RawMemoryImage::from_bytes(bytes, ArchBits::Bits64, OsType::Windows)
}

#[test]
fn win_find_processes_random_input_no_panic() {
    for sz in [0usize, 1, 32, 100, 1024, 8192] {
        let img = raw_img(rand_bytes(sz));
        let _ = WindowsAnalyzer::find_processes(&img);
        let _ = WindowsAnalyzer::find_modules(&img, 1000);
        let _ = WindowsAnalyzer::find_network_connections(&img);
        let _ = WindowsAnalyzer::extract_registry_hives(&img);
        let _ = WindowsAnalyzer::find_kernel_info(&img);
    }
}

#[test]
fn win_try_find_processes_empty_or_ok() {
    // RawMemoryImage::from_bytes always exposes at least one region for the
    // backing slice; try_find_processes returns Ok with an empty result in
    // that case. We assert "no panic, either branch reached".
    let img = RawMemoryImage::from_bytes(vec![], ArchBits::Bits64, OsType::Windows);
    match WindowsAnalyzer::try_find_processes(&img) {
        Ok(v) => assert!(v.is_empty()),
        Err(_) => {}
    }
}

#[test]
fn win_try_find_processes_real_refuses_fixture() {
    // The fixture holds `b"EPRC"` records, not real `_EPROCESS` objects.  The
    // real carve must report what is missing instead of passing the fixture
    // off as carved evidence.
    let img = build_mock_image(OsType::Windows);
    let e = WindowsAnalyzer::try_find_processes(&img)
        .expect_err("fixture records must not be reported as real processes");
    assert!(!format!("{e}").is_empty());
    // The fixture reader is still available and still reads them.
    assert!(WindowsAnalyzer::find_fixture_processes(&img).len() >= 2);
}

#[test]
fn win_parse_eprocess_pub_truncated_inputs() {
    for len in 0..56 {
        let buf = vec![0u8; len];
        assert!(WindowsAnalyzer::parse_eprocess_pub(&buf).is_none());
    }
}

#[test]
fn win_parse_eprocess_pub_50_random() {
    let mut g = lcg();
    for _ in 0..50 {
        let mut buf = vec![0u8; 56];
        for b in buf.iter_mut() {
            *b = g() as u8;
        }
        // Should never panic
        let _ = WindowsAnalyzer::parse_eprocess_pub(&buf);
    }
}

#[test]
fn win_kernel_info_present() {
    let img = build_mock_image(OsType::Windows);
    let info = WindowsAnalyzer::find_kernel_info(&img).unwrap();
    assert_eq!(info.version.major, 10);
    assert_eq!(info.version.build, 19041);
}

// ── RegistryHive ────────────────────────────────────────────────────────────

#[test]
fn regf_hive_path_handling() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"regf");
    let h = RegistryHive {
        name: "x".into(),
        base: 0,
        size: 16,
        data,
    };
    // single component
    let k = h.parse_key("Foo").unwrap();
    assert_eq!(k.name, "Foo");
    // empty path returns something
    let k2 = h.parse_key("\\").unwrap();
    assert_eq!(k2.values.len(), 1);
    // trailing backslash
    let k3 = h.parse_key("\\A\\B\\C\\").unwrap();
    assert_eq!(k3.name, "C");
}

#[test]
fn regf_short_data_none() {
    let h = RegistryHive {
        name: "x".into(),
        base: 0,
        size: 2,
        data: vec![b'r', b'e'],
    };
    assert!(h.parse_key("anything").is_none());
}

// ── MemoryForensicsScanner ──────────────────────────────────────────────────

#[test]
fn scanner_pe_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 4096 + 64;
        let buf = rand_bytes(n);
        let _ = MemoryForensicsScanner::scan_pe_headers(&buf, g());
    }
}

#[test]
fn scanner_pe_short_buf_empty() {
    for len in 0..64 {
        let buf = vec![b'M'; len];
        let r = MemoryForensicsScanner::scan_pe_headers(&buf, 0);
        assert!(r.is_empty());
    }
}

#[test]
fn scanner_pe_finds_multiple() {
    let mut data = vec![0u8; 0x600];
    for off in [0x0usize, 0x200, 0x400] {
        data[off] = b'M';
        data[off + 1] = b'Z';
        let pe_off: u32 = 0x80;
        data[off + 60..off + 64].copy_from_slice(&pe_off.to_le_bytes());
        data[off + 0x80..off + 0x84].copy_from_slice(b"PE\0\0");
    }
    let hits = MemoryForensicsScanner::scan_pe_headers(&data, 0);
    assert_eq!(hits.len(), 3);
}

#[test]
fn scanner_canaries_fuzz() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = ((g() as usize) % 1024 + 4) & !3;
        let buf = rand_bytes(n);
        let _ = MemoryForensicsScanner::scan_stack_canaries(&buf);
    }
}

#[test]
fn scanner_canaries_all_five() {
    let vals: [u32; 5] = [0xDEADBEEF, 0xABABABAB, 0xFEEEFEEE, 0xCDCDCDCD, 0xBAADF00D];
    let mut data = vec![0u8; vals.len() * 4];
    for (i, v) in vals.iter().enumerate() {
        data[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let hits = MemoryForensicsScanner::scan_stack_canaries(&data);
    assert_eq!(hits.len(), 5);
}

#[test]
fn scanner_heap_fuzz() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 2048 + 8;
        let buf = rand_bytes(n);
        let allocs = MemoryForensicsScanner::scan_heap_allocations(&buf);
        for a in allocs {
            assert!(a.addr + a.size <= buf.len() as u64);
        }
    }
}

#[test]
fn scanner_heap_boundary_size_1() {
    // size=1 (granule) ⇒ 8 bytes, busy flag
    let mut data = vec![0u8; 8];
    data[0..2].copy_from_slice(&1u16.to_le_bytes());
    data[2] = 0x01;
    let r = MemoryForensicsScanner::scan_heap_allocations(&data);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].size, 8);
}

#[test]
fn scanner_heap_oversized_skipped() {
    let mut data = vec![0u8; 16];
    data[0..2].copy_from_slice(&100u16.to_le_bytes());
    data[2] = 0x01;
    let r = MemoryForensicsScanner::scan_heap_allocations(&data);
    // 100*8 = 800 > 16 ⇒ must not include header
    assert!(r.is_empty());
}

#[test]
fn scanner_unicode_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 1024 + 2;
        let buf = rand_bytes(n);
        let _ = MemoryForensicsScanner::find_unicode_strings(&buf, 4);
    }
}

#[test]
fn scanner_unicode_max_len_boundary() {
    let r = MemoryForensicsScanner::find_unicode_strings(&[], 0);
    assert!(r.is_empty());
}

// ── KernelSymbols / WindowsKernelStructures ─────────────────────────────────

#[test]
fn ksym_for_version_branches() {
    let v_w10 = WindowsVersion::new(10, 0, 19041);
    let v_w81 = WindowsVersion::new(6, 3, 9600);
    let v_w7 = WindowsVersion::new(6, 1, 7601);
    let v_unk = WindowsVersion::new(99, 99, 0);
    let s10 = KernelSymbols::for_version(&v_w10);
    let s81 = KernelSymbols::for_version(&v_w81);
    let s7 = KernelSymbols::for_version(&v_w7);
    let su = KernelSymbols::for_version(&v_unk);
    assert_ne!(s10.eprocess_pid, s7.eprocess_pid);
    assert_ne!(s81.eprocess_pid, s7.eprocess_pid);
    assert_eq!(su.eprocess_pid, s10.eprocess_pid);
}

#[test]
fn wks_detect_version_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 2048 + 8;
        let buf = rand_bytes(n);
        let _ = WindowsKernelStructures::detect_version(&buf);
        let _ = WindowsKernelStructures::find_kdbg(&buf);
        let _ = WindowsKernelStructures::from_memory(&buf);
    }
}

#[test]
fn wks_find_kdbg_round_trip() {
    let mut data = vec![0u8; 256];
    let off = 100;
    data[off..off + 4].copy_from_slice(b"KDBG");
    let found = WindowsKernelStructures::find_kdbg(&data).unwrap();
    assert_eq!(found, off as u64);
}

#[test]
fn wks_from_memory_real() {
    let img = build_mock_image(OsType::Windows);
    // Need raw bytes — use a small region's read
    let regions = img.regions();
    use rustre_forensics::MemoryImage;
    let data = img.read(regions[0].start, 4096).unwrap();
    let wks = WindowsKernelStructures::from_memory(&data).unwrap();
    assert_eq!(wks.os_version.build, 19041);
}

// ── plugin_pslist / psscan / pstree ─────────────────────────────────────────

#[test]
fn pslist_deterministic_sort() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let p1 = plugin_pslist(&img, &syms);
    let p2 = plugin_pslist(&img, &syms);
    let pids1: Vec<u32> = p1.iter().map(|p| p.pid).collect();
    let pids2: Vec<u32> = p2.iter().map(|p| p.pid).collect();
    assert_eq!(pids1, pids2);
    // sorted
    let mut sorted = pids1.clone();
    sorted.sort_unstable();
    assert_eq!(pids1, sorted);
}

#[test]
fn psscan_subset_of_pslist_plus_extra() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let scan = plugin_psscan(&img);
    let list = plugin_pslist(&img, &syms);
    // psscan finds all real PIDs (PID != 0)
    for p in &list {
        if p.pid != 0 {
            assert!(scan.iter().any(|q| q.pid == p.pid), "missing pid {}", p.pid);
        }
    }
}

#[test]
fn pstree_no_cycles_with_self_parent() {
    let mut procs = vec![ProcessInfo {
        pid: 5,
        ppid: 5,
        name: "self".into(),
        base: 0,
        size: 0,
        threads: vec![],
        modules: vec![],
        handle_count: 0,
        create_time: 0,
    }];
    procs.push(ProcessInfo {
        pid: 6,
        ppid: 5,
        name: "child".into(),
        base: 0,
        size: 0,
        threads: vec![],
        modules: vec![],
        handle_count: 0,
        create_time: 0,
    });
    let tree = plugin_pstree(&procs);
    assert!(!tree.roots.is_empty());
}

#[test]
fn pstree_empty_input() {
    let tree = plugin_pstree(&[]);
    assert!(tree.roots.is_empty());
}

// ── plugin_cmdline / dlllist / handles / netscan / filescan / vadinfo ───────

#[test]
fn cmdline_system_special() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let cmds = plugin_cmdline(&img, &syms);
    assert_eq!(cmds.get(&4).map(String::as_str), Some("[System Process]"));
    assert!(cmds.get(&1000).unwrap().contains("--pid 1000"));
}

#[test]
fn dlllist_returns_entries() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let dlls = plugin_dlllist(&img, &syms, 1000);
    assert!(!dlls.is_empty());
    for d in &dlls {
        assert!(d.in_load_order && d.in_init_order && d.in_mem_order);
    }
}

#[test]
fn handles_synth_when_empty() {
    // empty image triggers synth fallback
    let img = RawMemoryImage::from_bytes(vec![0u8; 64], ArchBits::Bits64, OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let h = plugin_handles(&img, &syms, 1000);
    assert_eq!(h.len(), 5);
}

#[test]
fn netscan_includes_mock_ncon() {
    let img = build_mock_image(OsType::Windows);
    let conns = plugin_netscan(&img);
    assert!(!conns.is_empty());
}

#[test]
fn filescan_empty_for_mock() {
    let img = build_mock_image(OsType::Windows);
    let r = plugin_filescan(&img);
    // mock image has no FOBJ tags
    assert!(r.is_empty());
}

#[test]
fn vadinfo_synth_for_pid() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let v = plugin_vadinfo(&img, &syms, 1000);
    assert!(v.len() >= 3);
}

#[test]
fn vadinfo_unknown_pid_empty() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let v = plugin_vadinfo(&img, &syms, 999_999);
    assert!(v.is_empty());
}

// ── malfind ─────────────────────────────────────────────────────────────────

#[test]
fn malfind_does_not_panic_on_mock() {
    let img = build_mock_image(OsType::Windows);
    let syms = KernelSymbols::win10_x64_19041();
    let _ = plugin_malfind(&img, &syms);
}

// ── LinuxAnalyzer ───────────────────────────────────────────────────────────

#[test]
fn linux_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 2048 + 4;
        let img = RawMemoryImage::from_bytes(rand_bytes(n), ArchBits::Bits64, OsType::Linux);
        let _ = LinuxAnalyzer::find_processes(&img);
        let _ = LinuxAnalyzer::find_modules(&img);
        let _ = LinuxAnalyzer::find_sockets(&img);
    }
}

// ── strings_extractor ───────────────────────────────────────────────────────

#[test]
fn strings_ascii_basic_roundtrip() {
    let s = b"Hello, World!\0junk";
    let out = se::extract_ascii(s, 0x1000, 4, 100);
    assert!(out.iter().any(|m| m.value.starts_with("Hello")));
    assert_eq!(out[0].address, 0x1000);
    assert_eq!(out[0].encoding, StringEncoding::Ascii);
}

#[test]
fn strings_utf16_roundtrip() {
    let s: Vec<u8> = "Hello"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut data = vec![0u8; 64];
    data[0..s.len()].copy_from_slice(&s);
    let out = se::extract_utf16le(&data, 0, 4, 100);
    assert!(!out.is_empty());
    assert_eq!(out[0].value, "Hello");
}

#[test]
fn strings_extract_fuzz_no_panic() {
    let cfg = StringExtractionConfig::default();
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 2048 + 1;
        let buf = rand_bytes(n);
        let _ = se::extract_strings(&buf, g(), &cfg);
    }
}

#[test]
fn strings_classify_all_classes() {
    assert_eq!(se::classify_string("https://x.com/"), StringClass::Url);
    assert_eq!(se::classify_string("ftp://x"), StringClass::Url);
    assert_eq!(se::classify_string("192.168.1.1"), StringClass::IpV4);
    assert_eq!(se::classify_string("256.0.0.1"), StringClass::Plain);
    assert_eq!(se::classify_string("C:\\Windows\\x"), StringClass::FilePath);
    assert_eq!(se::classify_string("/etc/passwd"), StringClass::FilePath);
    assert_eq!(
        se::classify_string("HKEY_LOCAL_MACHINE\\X"),
        StringClass::RegistryKey
    );
    assert_eq!(
        se::classify_string("0123456789abcdef0123"),
        StringClass::HexBlob
    );
    assert_eq!(se::classify_string("VirtualAlloc"), StringClass::WinApiName);
    assert_eq!(
        se::classify_string("System.IO.File"),
        StringClass::DotNetType
    );
    assert_eq!(se::classify_string("%s is %d"), StringClass::Format);
    assert_eq!(se::classify_string("plain text"), StringClass::Plain);
}

#[test]
fn strings_build_report() {
    let items = vec![
        MemString::new(0, "https://x.com".into(), StringEncoding::Ascii),
        MemString::new(1, "1.2.3.4".into(), StringEncoding::Ascii),
        MemString::new(2, "C:\\x".into(), StringEncoding::Ascii),
        MemString::new(3, "HKLM\\Foo".into(), StringEncoding::Ascii),
        MemString::new(4, "VirtualAlloc".into(), StringEncoding::Ascii),
        MemString::new(5, "plain".into(), StringEncoding::Ascii),
    ];
    let r = se::build_report(&items);
    assert_eq!(r.total, 6);
    assert_eq!(r.urls.len(), 1);
    assert_eq!(r.ips.len(), 1);
    assert_eq!(r.paths.len(), 1);
    assert_eq!(r.registry_keys.len(), 1);
    assert_eq!(r.api_names.len(), 1);
    assert_eq!(r.interesting_count(), 5);
}

// ── process_tree module ─────────────────────────────────────────────────────

fn make_pi(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: name.into(),
        base: 0,
        size: 0,
        threads: vec![],
        modules: vec![],
        handle_count: 0,
        create_time: 0,
    }
}

#[test]
fn pt_build_and_render() {
    let procs = vec![
        make_pi(4, 0, "System"),
        make_pi(100, 4, "csrss.exe"),
        make_pi(200, 100, "winlogon.exe"),
    ];
    let tree = PtTree::build(procs);
    assert_eq!(tree.total(), 3);
    let r = render_tree(&tree);
    assert!(r.contains("[4]"));
    assert!(r.contains("[100]"));
    assert!(r.contains("[200]"));
}

#[test]
fn pt_compute_stats_consistent() {
    let procs = (1..=10u32).map(|i| make_pi(i, i - 1, "p")).collect();
    let tree = PtTree::build(procs);
    let s = compute_stats(&tree);
    assert_eq!(s.total, 10);
    assert!(s.roots >= 1);
}

#[test]
fn pt_orphans_with_self_parent() {
    let procs = vec![make_pi(7, 7, "self")];
    let tree = PtTree::build(procs);
    assert_eq!(tree.roots.len(), 1);
}

// ── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn send_sync_threaded_image_scan() {
    // RawMemoryImage requires Send+Sync to be wrapped in Arc and shared
    let img = Arc::new(build_mock_image(OsType::Windows));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let img_c = Arc::clone(&img);
        handles.push(std::thread::spawn(move || {
            let mut sum = 0usize;
            for _ in 0..100 {
                let p = WindowsAnalyzer::find_processes(&*img_c);
                sum += p.len();
            }
            sum
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 0);
}

#[test]
fn send_sync_threaded_classify() {
    let inputs: Arc<Vec<String>> = Arc::new(vec![
        "https://x".into(),
        "VirtualAlloc".into(),
        "10.0.0.1".into(),
        "plain".into(),
    ]);
    let mut hs = Vec::new();
    for _ in 0..4 {
        let inp = Arc::clone(&inputs);
        hs.push(std::thread::spawn(move || {
            let mut count = 0usize;
            for _ in 0..100 {
                for s in inp.iter() {
                    let _ = se::classify_string(s);
                    count += 1;
                }
            }
            count
        }));
    }
    let total: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 4 * 100 * 4);
}

// ── serde round-trips for plugin data types ────────────────────────────────

#[test]
fn serde_roundtrips_50_dllentries() {
    let mut g = lcg();
    for _ in 0..50 {
        let d = DllEntry {
            base: g(),
            size: g() as u32,
            full_path: format!("p{}", g() as u32),
            base_name: format!("b{}", g() as u32),
            in_load_order: (g() & 1) == 0,
            in_init_order: (g() & 1) == 0,
            in_mem_order: (g() & 1) == 0,
        };
        let j = serde_json::to_string(&d).unwrap();
        let d2: DllEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(d.base, d2.base);
        assert_eq!(d.base_name, d2.base_name);
    }
}

#[test]
fn serde_roundtrips_vad_entry() {
    let v = VadEntry {
        start_vpn: 0x100,
        end_vpn: 0x200,
        flags: 0x4,
        protection: 0x20,
        vad_type: VadType::Image,
        file_name: Some("x.dll".into()),
        commit_charge: 10,
    };
    let j = serde_json::to_string(&v).unwrap();
    let v2: VadEntry = serde_json::from_str(&j).unwrap();
    assert_eq!(v.start_vpn, v2.start_vpn);
    assert_eq!(v.vad_type, v2.vad_type);
}

#[test]
fn serde_roundtrips_hook_info() {
    let h = HookInfo {
        pid: 1,
        hook_type: HookType::Inline,
        module: "m".into(),
        function: "f".into(),
        hook_addr: 0x1000,
        target_addr: 0x2000,
        hook_module: Some("h".into()),
        hook_bytes: vec![0x90, 0x90],
    };
    let j = serde_json::to_string(&h).unwrap();
    let h2: HookInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(h.pid, h2.pid);
    assert_eq!(h.hook_type, h2.hook_type);
}

// ── Boundary: max-size primitives ───────────────────────────────────────────

#[test]
fn boundary_windows_version_max() {
    let v = WindowsVersion::new(u32::MAX, u32::MAX, u32::MAX);
    let s = v.display();
    assert!(s.contains(&u32::MAX.to_string()));
}

#[test]
fn boundary_process_info_zero_max() {
    let p = ProcessInfo {
        pid: 0,
        ppid: u32::MAX,
        name: String::new(),
        base: u64::MAX,
        size: u64::MAX,
        threads: vec![],
        modules: vec![],
        handle_count: u32::MAX,
        create_time: u64::MAX,
    };
    assert!(p.name_matches(""));
    let j = serde_json::to_string(&p).unwrap();
    let p2: ProcessInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(p.base, p2.base);
}
