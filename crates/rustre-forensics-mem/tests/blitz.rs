//! Exhaustive blitz tests for rustre-forensics-mem.

use rustre_forensics::{ArchBits, OsType, RawMemoryImage};
use rustre_forensics_mem::*;

// ───── helpers ────────────────────────────────────────────────────────────────

fn win_img() -> RawMemoryImage {
    build_mock_image(OsType::Windows)
}
fn lin_img() -> RawMemoryImage {
    build_mock_image(OsType::Linux)
}
fn empty_img() -> RawMemoryImage {
    RawMemoryImage::from_bytes(vec![0u8; 256], ArchBits::Bits64, OsType::Windows)
}
fn zero_img() -> RawMemoryImage {
    RawMemoryImage::from_bytes(vec![], ArchBits::Bits64, OsType::Windows)
}

// ───── WindowsVersion ─────────────────────────────────────────────────────────

#[test]
fn wv_display_zero() {
    assert_eq!(WindowsVersion::new(0, 0, 0).display(), "0.0.0");
}

#[test]
fn wv_display_max() {
    assert_eq!(
        WindowsVersion::new(u32::MAX, u32::MAX, u32::MAX).display(),
        format!("{}.{}.{}", u32::MAX, u32::MAX, u32::MAX)
    );
}

#[test]
fn wv_copy_semantics() {
    let a = WindowsVersion::new(10, 0, 1);
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn wv_serde_roundtrip() {
    let v = WindowsVersion::new(10, 0, 19041);
    let j = serde_json::to_string(&v).unwrap();
    let v2: WindowsVersion = serde_json::from_str(&j).unwrap();
    assert_eq!(v, v2);
}

// ───── ThreadState ────────────────────────────────────────────────────────────

#[test]
fn ts_all_known_variants() {
    use ThreadState::*;
    let pairs = [
        (0u8, Initialized),
        (1, Ready),
        (2, Running),
        (3, Standby),
        (4, Terminated),
        (5, Wait),
        (6, Transition),
        (7, DeferredReady),
    ];
    for (v, expected) in pairs {
        assert_eq!(ThreadState::from_u8(v), expected, "for v={v}");
    }
}

#[test]
fn ts_unknown_boundary() {
    assert_eq!(ThreadState::from_u8(8), ThreadState::Unknown);
    assert_eq!(ThreadState::from_u8(u8::MAX), ThreadState::Unknown);
}

// ───── ConnectionState ────────────────────────────────────────────────────────

#[test]
fn cs_all_known() {
    use ConnectionState::*;
    let pairs = [
        (1u8, Listen),
        (2, SynSent),
        (3, SynReceived),
        (5, Established),
        (6, FinWait1),
        (7, FinWait2),
        (8, CloseWait),
        (9, LastAck),
        (11, TimeWait),
        (12, Closed),
    ];
    for (v, expected) in pairs {
        assert_eq!(ConnectionState::from_u8(v), expected, "for v={v}");
    }
}

#[test]
fn cs_unknown_values() {
    assert_eq!(ConnectionState::from_u8(0), ConnectionState::Unknown);
    assert_eq!(ConnectionState::from_u8(4), ConnectionState::Unknown);
    assert_eq!(ConnectionState::from_u8(10), ConnectionState::Unknown);
    assert_eq!(ConnectionState::from_u8(13), ConnectionState::Unknown);
    assert_eq!(ConnectionState::from_u8(255), ConnectionState::Unknown);
}

// ───── NetProtocol ────────────────────────────────────────────────────────────

#[test]
fn np_as_str_all() {
    assert_eq!(NetProtocol::TcpV4.as_str(), "TCPv4");
    assert_eq!(NetProtocol::TcpV6.as_str(), "TCPv6");
    assert_eq!(NetProtocol::UdpV4.as_str(), "UDPv4");
    assert_eq!(NetProtocol::UdpV6.as_str(), "UDPv6");
}

// ───── ProcessInfo::name_matches ──────────────────────────────────────────────

fn pi(name: &str) -> ProcessInfo {
    ProcessInfo {
        pid: 1, ppid: 0, name: name.into(), base: 0, size: 0,
        threads: vec![], modules: vec![], handle_count: 0, create_time: 0,
    }
}

#[test]
fn pi_name_matches_empty_pattern() {
    // empty substring always matches
    assert!(pi("svchost").name_matches(""));
}

#[test]
fn pi_name_matches_full() {
    assert!(pi("svchost.exe").name_matches("SVCHOST.EXE"));
}

#[test]
fn pi_name_matches_no_match() {
    assert!(!pi("svchost.exe").name_matches("explorer"));
}

#[test]
fn pi_name_matches_unicode() {
    // Lowercase Turkish "I" issue is real but only with locale; ASCII OK.
    assert!(pi("FÖÖ").name_matches("föö"));
}

// ───── WindowsAnalyzer::find_processes ────────────────────────────────────────

#[test]
fn wa_find_processes_in_windows_image() {
    let procs = WindowsAnalyzer::find_processes(&win_img());
    assert!(procs.len() >= 2);
    assert!(procs.iter().any(|p| p.pid == 4 && p.name == "System"));
    assert!(procs.iter().any(|p| p.pid == 1000));
}

#[test]
fn wa_find_processes_linux_image_no_eprc() {
    // Linux image uses TSKB tags, NOT EPRC — Windows analyzer should find no procs.
    let procs = WindowsAnalyzer::find_processes(&lin_img());
    assert!(
        procs.is_empty(),
        "Windows analyzer found EPRC procs in Linux image: {procs:?}"
    );
}

#[test]
fn wa_find_processes_empty_image() {
    assert!(WindowsAnalyzer::find_processes(&empty_img()).is_empty());
}

#[test]
fn wa_try_find_processes_empty_regions() {
    // RawMemoryImage with no bytes — regions() should be empty.
    let img = zero_img();
    let regions = rustre_forensics::MemoryImage::regions(&img);
    if regions.is_empty() {
        let r = WindowsAnalyzer::try_find_processes(&img);
        assert!(r.is_err(), "expected error for empty regions, got {r:?}");
    } else {
        // If RawMemoryImage always exposes at least one region, ok must succeed.
        assert!(WindowsAnalyzer::try_find_processes(&img).is_ok());
    }
}

#[test]
fn wa_try_find_processes_ok_for_real_image() {
    let r = WindowsAnalyzer::try_find_processes(&win_img());
    assert!(r.is_ok());
    assert!(!r.unwrap().is_empty());
}

// ───── WindowsAnalyzer::find_modules ──────────────────────────────────────────

#[test]
fn wa_find_modules_finds_ntdll() {
    let mods = WindowsAnalyzer::find_modules(&win_img(), 1000);
    assert!(mods.iter().any(|m| m.name == "ntdll.dll"));
}

#[test]
fn wa_find_modules_path_present() {
    let mods = WindowsAnalyzer::find_modules(&win_img(), 1000);
    let m = mods.iter().find(|m| m.name == "ntdll.dll").unwrap();
    assert!(m.path.contains("ntdll.dll"));
}

#[test]
fn wa_find_modules_pid_arg_ignored() {
    // Doc says "real tool would find EPROCESS for pid first"; current impl
    // ignores pid and returns same modules. Just check it doesn't panic for any pid.
    let a = WindowsAnalyzer::find_modules(&win_img(), 0);
    let b = WindowsAnalyzer::find_modules(&win_img(), u32::MAX);
    assert_eq!(a.len(), b.len());
}

// ───── WindowsAnalyzer::find_network_connections ──────────────────────────────

#[test]
fn wa_find_netconn_fields() {
    let conns = WindowsAnalyzer::find_network_connections(&win_img());
    assert!(!conns.is_empty());
    let c = &conns[0];
    assert_eq!(c.protocol, NetProtocol::TcpV4);
    assert_eq!(c.state, ConnectionState::Established);
    assert_eq!(c.local_port, 443);
    assert_eq!(c.remote_port, 80);
    assert_eq!(c.pid, 1000);
    assert_eq!(c.local_addr, "192.168.1.1");
    assert_eq!(c.remote_addr, "1.2.3.4");
}

// ───── WindowsAnalyzer::extract_registry_hives ────────────────────────────────

#[test]
fn wa_extract_hives_name() {
    let hives = WindowsAnalyzer::extract_registry_hives(&win_img());
    assert!(!hives.is_empty());
    assert!(hives.iter().any(|h| h.name.contains("SYSTEM")));
}

#[test]
fn wa_extract_hives_have_regf_data() {
    let hives = WindowsAnalyzer::extract_registry_hives(&win_img());
    for h in &hives {
        assert!(h.data.len() >= 4);
        assert_eq!(&h.data[0..4], b"regf");
    }
}

// ───── RegistryHive::parse_key ────────────────────────────────────────────────

#[test]
fn rh_parse_key_empty_data() {
    let h = RegistryHive { name: "x".into(), base: 0, size: 0, data: vec![] };
    assert!(h.parse_key("foo").is_none());
}

#[test]
fn rh_parse_key_short_data() {
    let h = RegistryHive { name: "x".into(), base: 0, size: 0, data: vec![b'r', b'e'] };
    assert!(h.parse_key("foo").is_none());
}

#[test]
fn rh_parse_key_wrong_magic() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"REGF"); // wrong case
    let h = RegistryHive { name: "x".into(), base: 0, size: 16, data };
    assert!(h.parse_key("foo").is_none());
}

#[test]
fn rh_parse_key_last_segment() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"regf");
    let h = RegistryHive { name: "x".into(), base: 0, size: 16, data };
    let k = h.parse_key("\\HKLM\\SOFTWARE\\Microsoft").unwrap();
    assert_eq!(k.name, "Microsoft");
}

#[test]
fn rh_parse_key_no_separator() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"regf");
    let h = RegistryHive { name: "x".into(), base: 0, size: 16, data };
    let k = h.parse_key("Standalone").unwrap();
    assert_eq!(k.name, "Standalone");
}

// ───── WindowsAnalyzer::find_kernel_info ──────────────────────────────────────

#[test]
fn wa_kernel_info_build_version() {
    let info = WindowsAnalyzer::find_kernel_info(&win_img()).unwrap();
    assert_eq!(info.version.major, 10);
    assert_eq!(info.version.minor, 0);
    assert_eq!(info.version.build, 19041);
    assert_eq!(info.ntoskrnl_base, 0xFFFF_F800_0000_0000);
    assert!(info.kdbg.is_some());
}

#[test]
fn wa_kernel_info_none_for_empty() {
    assert!(WindowsAnalyzer::find_kernel_info(&empty_img()).is_none());
}

// ───── LinuxAnalyzer ──────────────────────────────────────────────────────────

#[test]
fn la_find_processes_linux() {
    let procs = LinuxAnalyzer::find_processes(&lin_img());
    assert!(procs.len() >= 2);
    assert!(procs.iter().any(|p| p.pid == 4));
}

#[test]
fn la_find_processes_windows_image_no_tskb() {
    let procs = LinuxAnalyzer::find_processes(&win_img());
    assert!(procs.is_empty(), "Linux analyzer found TSKB in win image: {procs:?}");
}

#[test]
fn la_find_modules_linux() {
    let mods = LinuxAnalyzer::find_modules(&lin_img());
    assert!(mods.iter().any(|m| m.name == "ntdll.dll"));
}

#[test]
fn la_find_sockets_delegates_to_windows() {
    let a = LinuxAnalyzer::find_sockets(&win_img());
    let b = WindowsAnalyzer::find_network_connections(&win_img());
    assert_eq!(a.len(), b.len());
}

// ───── MemoryForensicsScanner::scan_pe_headers ────────────────────────────────

fn pe_stub(pe_off: u32) -> Vec<u8> {
    let len = (pe_off as usize + 4).max(0x100);
    let mut d = vec![0u8; len];
    d[0] = b'M';
    d[1] = b'Z';
    d[60..64].copy_from_slice(&pe_off.to_le_bytes());
    if (pe_off as usize) + 4 <= d.len() {
        d[pe_off as usize..pe_off as usize + 4].copy_from_slice(b"PE\0\0");
    }
    d
}

#[test]
fn pe_scan_finds_at_zero() {
    let d = pe_stub(0x80);
    let h = MemoryForensicsScanner::scan_pe_headers(&d, 0x1_0000);
    assert_eq!(h, vec![0x1_0000]);
}

#[test]
fn pe_scan_lfanew_below_min_rejected() {
    let mut d = pe_stub(0x40);
    // Set e_lfanew to 0x3F (below min 0x40)
    d[60..64].copy_from_slice(&0x3F_u32.to_le_bytes());
    let h = MemoryForensicsScanner::scan_pe_headers(&d, 0);
    assert!(h.is_empty());
}

#[test]
fn pe_scan_lfanew_at_min_accepted() {
    let mut d = vec![0u8; 0x100];
    d[0] = b'M'; d[1] = b'Z';
    d[60..64].copy_from_slice(&0x40_u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    let h = MemoryForensicsScanner::scan_pe_headers(&d, 0);
    assert_eq!(h, vec![0]);
}

#[test]
fn pe_scan_lfanew_at_max_accepted() {
    let mut d = vec![0u8; 0x2000];
    d[0] = b'M'; d[1] = b'Z';
    d[60..64].copy_from_slice(&0x1000_u32.to_le_bytes());
    d[0x1000..0x1004].copy_from_slice(b"PE\0\0");
    let h = MemoryForensicsScanner::scan_pe_headers(&d, 0);
    assert_eq!(h, vec![0]);
}

#[test]
fn pe_scan_lfanew_above_max_rejected() {
    let mut d = vec![0u8; 0x3000];
    d[0] = b'M'; d[1] = b'Z';
    d[60..64].copy_from_slice(&0x1001_u32.to_le_bytes());
    d[0x1001..0x1005].copy_from_slice(b"PE\0\0");
    let h = MemoryForensicsScanner::scan_pe_headers(&d, 0);
    assert!(h.is_empty());
}

#[test]
fn pe_scan_no_pe_signature() {
    let mut d = pe_stub(0x80);
    d[0x80..0x84].copy_from_slice(b"NOPE");
    assert!(MemoryForensicsScanner::scan_pe_headers(&d, 0).is_empty());
}

#[test]
fn pe_scan_empty_memory() {
    assert!(MemoryForensicsScanner::scan_pe_headers(&[], 0).is_empty());
}

#[test]
fn pe_scan_short_memory_below_64() {
    let d = vec![b'M', b'Z'];
    assert!(MemoryForensicsScanner::scan_pe_headers(&d, 0).is_empty());
}

// ───── MemoryForensicsScanner::scan_stack_canaries ────────────────────────────

fn put_u32(d: &mut [u8], off: usize, v: u32) {
    d[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn canary_all_known() {
    for v in [0xDEAD_BEEFu32, 0xABAB_ABAB, 0xFEEE_FEEE, 0xCDCD_CDCD, 0xBAAD_F00D] {
        let mut d = vec![0u8; 8];
        put_u32(&mut d, 0, v);
        let h = MemoryForensicsScanner::scan_stack_canaries(&d);
        assert!(h.contains(&0), "{v:#x} not found");
    }
}

#[test]
fn canary_multiple_hits() {
    let mut d = vec![0u8; 32];
    put_u32(&mut d, 0, 0xDEAD_BEEF);
    put_u32(&mut d, 8, 0xBAAD_F00D);
    put_u32(&mut d, 16, 0xFEEE_FEEE);
    let h = MemoryForensicsScanner::scan_stack_canaries(&d);
    assert_eq!(h.len(), 3);
    assert!(h.contains(&0) && h.contains(&8) && h.contains(&16));
}

#[test]
fn canary_short_buffer() {
    assert!(MemoryForensicsScanner::scan_stack_canaries(&[0; 3]).is_empty());
}

#[test]
fn canary_no_match() {
    let d = vec![0u8; 64];
    assert!(MemoryForensicsScanner::scan_stack_canaries(&d).is_empty());
}

// ───── MemoryForensicsScanner::scan_heap_allocations ──────────────────────────

#[test]
fn heap_busy_block_detected() {
    let mut d = vec![0u8; 32];
    d[0..2].copy_from_slice(&2u16.to_le_bytes()); // 2 granules = 16 bytes
    d[2] = 0x01; // BUSY
    let a = MemoryForensicsScanner::scan_heap_allocations(&d);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].size, 16);
}

#[test]
fn heap_not_busy_skipped() {
    let mut d = vec![0u8; 16];
    d[0..2].copy_from_slice(&2u16.to_le_bytes());
    d[2] = 0x02; // EXTRA_PRESENT, NOT BUSY
    assert!(MemoryForensicsScanner::scan_heap_allocations(&d).is_empty());
}

#[test]
fn heap_size_zero_skipped() {
    let mut d = vec![0u8; 16];
    d[0..2].copy_from_slice(&0u16.to_le_bytes());
    d[2] = 0x01;
    assert!(MemoryForensicsScanner::scan_heap_allocations(&d).is_empty());
}

#[test]
fn heap_size_overflows_buffer_skipped() {
    let mut d = vec![0u8; 16];
    d[0..2].copy_from_slice(&10u16.to_le_bytes()); // 80 bytes > 16
    d[2] = 0x01;
    assert!(MemoryForensicsScanner::scan_heap_allocations(&d).is_empty());
}

#[test]
fn heap_empty() {
    assert!(MemoryForensicsScanner::scan_heap_allocations(&[]).is_empty());
}

// ───── MemoryForensicsScanner::find_unicode_strings ───────────────────────────

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn us_basic() {
    let mut d = vec![0u8; 32];
    let s = utf16le("Hello");
    d[0..s.len()].copy_from_slice(&s);
    let r = MemoryForensicsScanner::find_unicode_strings(&d, 4);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1, "Hello");
    assert_eq!(r[0].0, 0);
}

#[test]
fn us_min_len_excludes_short() {
    let mut d = vec![0u8; 16];
    let s = utf16le("Hi");
    d[0..s.len()].copy_from_slice(&s);
    assert!(MemoryForensicsScanner::find_unicode_strings(&d, 5).is_empty());
}

#[test]
fn us_min_len_zero_returns_anything_printable() {
    let mut d = vec![0u8; 8];
    let s = utf16le("A");
    d[0..s.len()].copy_from_slice(&s);
    let r = MemoryForensicsScanner::find_unicode_strings(&d, 1);
    assert!(!r.is_empty());
    assert_eq!(r[0].1, "A");
}

#[test]
fn us_offset_addr() {
    let mut d = vec![0u8; 64];
    let s = utf16le("ABCDE");
    d[8..8 + s.len()].copy_from_slice(&s);
    let r = MemoryForensicsScanner::find_unicode_strings(&d, 3);
    assert!(r.iter().any(|(off, st)| *off == 8 && st == "ABCDE"));
}

#[test]
fn us_empty() {
    assert!(MemoryForensicsScanner::find_unicode_strings(&[], 1).is_empty());
}

#[test]
fn us_non_printable_terminates() {
    let mut d = vec![0u8; 32];
    let s = utf16le("Hello");
    d[0..s.len()].copy_from_slice(&s);
    // Place "World" after, no separator — should still terminate at first non-printable.
    // Insert a high byte that breaks UTF-16 ASCII run.
    d[10] = 0x01; d[11] = 0x01;
    let r = MemoryForensicsScanner::find_unicode_strings(&d, 3);
    assert!(r.iter().any(|(_, s)| s == "Hello"));
}

// ───── KernelSymbols ──────────────────────────────────────────────────────────

#[test]
fn ks_win10_basic_offsets() {
    let s = KernelSymbols::win10_x64_19041();
    assert_eq!(s.eprocess_pid, 0x2E8);
    assert_eq!(s.eprocess_image_file_name, 0x450);
}

#[test]
fn ks_for_version_win10() {
    let s = KernelSymbols::for_version(&WindowsVersion::new(10, 0, 19041));
    assert_eq!(s.eprocess_pid, 0x2E8);
}

#[test]
fn ks_for_version_win81() {
    let s = KernelSymbols::for_version(&WindowsVersion::new(6, 3, 9600));
    assert_eq!(s.eprocess_pid, 0x2E0);
    assert_eq!(s.eprocess_image_file_name, 0x438);
}

#[test]
fn ks_for_version_win7() {
    let s = KernelSymbols::for_version(&WindowsVersion::new(6, 1, 7601));
    assert_eq!(s.eprocess_pid, 0x180);
    assert_eq!(s.eprocess_image_file_name, 0x2D0);
}

#[test]
fn ks_for_version_unknown_falls_back() {
    let s = KernelSymbols::for_version(&WindowsVersion::new(99, 99, 99));
    // Falls back to win10
    assert_eq!(s.eprocess_pid, KernelSymbols::win10_x64_19041().eprocess_pid);
}

// ───── WindowsKernelStructures ────────────────────────────────────────────────

#[test]
fn wks_find_kdbg_present() {
    // build_mock_image embeds KDBG at offset 0
    let img = win_img();
    let bytes = rustre_forensics::MemoryImage::read(&img, 0, 4096).unwrap();
    let off = WindowsKernelStructures::find_kdbg(&bytes);
    assert_eq!(off, Some(0));
}

#[test]
fn wks_find_kdbg_absent() {
    let d = vec![0u8; 256];
    assert!(WindowsKernelStructures::find_kdbg(&d).is_none());
}

#[test]
fn wks_detect_version_from_kdbg() {
    let img = win_img();
    let bytes = rustre_forensics::MemoryImage::read(&img, 0, 4096).unwrap();
    let v = WindowsKernelStructures::detect_version(&bytes).unwrap();
    assert_eq!(v.major, 10);
    assert_eq!(v.build, 19041);
}

#[test]
fn wks_from_memory_complete() {
    let img = win_img();
    let bytes = rustre_forensics::MemoryImage::read(&img, 0, 4096).unwrap();
    let s = WindowsKernelStructures::from_memory(&bytes).unwrap();
    assert_eq!(s.os_version.build, 19041);
    assert_eq!(s.pdb_symbols.eprocess_pid, 0x2E8);
}

#[test]
fn wks_from_memory_empty() {
    assert!(WindowsKernelStructures::from_memory(&[]).is_none());
}

#[test]
fn wks_load_symbols_for_version() {
    let s = WindowsKernelStructures::load_symbols_for_version(&WindowsVersion::new(6, 1, 7601));
    assert_eq!(s.eprocess_pid, 0x180);
}

// ───── VadType ────────────────────────────────────────────────────────────────

#[test]
fn vad_type_all() {
    use VadType::*;
    // (flags >> 2) & 0x7
    assert_eq!(VadType::from_flags(0 << 2), Private);
    assert_eq!(VadType::from_flags(1 << 2), Mapped);
    assert_eq!(VadType::from_flags(2 << 2), Image);
    assert_eq!(VadType::from_flags(3 << 2), Physical);
    assert_eq!(VadType::from_flags(4 << 2), Unknown);
    assert_eq!(VadType::from_flags(7 << 2), Unknown);
}

// ───── HiveType ───────────────────────────────────────────────────────────────

#[test]
fn hive_type_classifications() {
    assert_eq!(HiveType::from_name("SAM"), HiveType::Sam);
    assert_eq!(HiveType::from_name("Security"), HiveType::Security);
    assert_eq!(HiveType::from_name("SOFTWARE"), HiveType::Software);
    assert_eq!(HiveType::from_name("system"), HiveType::System);
    assert_eq!(HiveType::from_name("NTUSER.DAT"), HiveType::Ntuser);
    assert_eq!(HiveType::from_name("DEFAULT"), HiveType::Other);
}

#[test]
fn hive_type_precedence_sam_in_path() {
    // "samsung" contains "sam" — current impl classifies as Sam.
    // Document actual behavior.
    assert_eq!(HiveType::from_name("samsung_random"), HiveType::Sam);
}

// ───── Plugin: pslist ─────────────────────────────────────────────────────────

#[test]
fn pl_pslist_sorted_and_deduped() {
    let syms = KernelSymbols::win10_x64_19041();
    let procs = plugin_pslist(&win_img(), &syms);
    assert!(procs.windows(2).all(|w| w[0].pid <= w[1].pid));
    // Dedup check: each pid unique
    let mut pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
    let len = pids.len();
    pids.sort_unstable();
    pids.dedup();
    assert_eq!(pids.len(), len);
}

// ───── Plugin: pstree ─────────────────────────────────────────────────────────

fn mkproc(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
    ProcessInfo {
        pid, ppid, name: name.into(), base: 0, size: 0,
        threads: vec![], modules: vec![], handle_count: 0, create_time: 0,
    }
}

#[test]
fn pl_pstree_empty() {
    let t = plugin_pstree(&[]);
    assert!(t.roots.is_empty());
}

#[test]
fn pl_pstree_single_root() {
    let procs = vec![mkproc(1, 0, "init")];
    let t = plugin_pstree(&procs);
    assert_eq!(t.roots.len(), 1);
    assert_eq!(t.roots[0].info.pid, 1);
    assert!(t.roots[0].children.is_empty());
}

#[test]
fn pl_pstree_parent_child() {
    let procs = vec![mkproc(1, 0, "init"), mkproc(2, 1, "child")];
    let t = plugin_pstree(&procs);
    assert_eq!(t.roots.len(), 1);
    assert_eq!(t.roots[0].children.len(), 1);
    assert_eq!(t.roots[0].children[0].info.pid, 2);
}

#[test]
fn pl_pstree_orphan_becomes_root() {
    // PPID 999 doesn't exist → process becomes root.
    let procs = vec![mkproc(2, 999, "orphan")];
    let t = plugin_pstree(&procs);
    assert_eq!(t.roots.len(), 1);
    assert_eq!(t.roots[0].info.pid, 2);
}

#[test]
fn pl_pstree_self_parent_no_cycle() {
    let procs = vec![mkproc(1, 1, "weird")];
    let t = plugin_pstree(&procs);
    // pid==ppid filtered, so becomes root via fallback
    assert_eq!(t.roots.len(), 1);
}

// ───── Plugin: psscan ─────────────────────────────────────────────────────────

#[test]
fn pl_psscan_finds_processes() {
    let procs = plugin_psscan(&win_img());
    assert!(procs.len() >= 2);
    // sorted
    assert!(procs.windows(2).all(|w| w[0].pid <= w[1].pid));
}

#[test]
fn pl_psscan_skips_zero_pid() {
    // System (pid=4) and explorer (pid=1000) in image; both non-zero.
    let procs = plugin_psscan(&win_img());
    assert!(procs.iter().all(|p| p.pid != 0));
}

#[test]
fn pl_psscan_empty_image() {
    assert!(plugin_psscan(&empty_img()).is_empty());
}

// ───── Plugin: cmdline ────────────────────────────────────────────────────────

#[test]
fn pl_cmdline_system_special() {
    let syms = KernelSymbols::win10_x64_19041();
    let m = plugin_cmdline(&win_img(), &syms);
    assert_eq!(m.get(&4).map(String::as_str), Some("[System Process]"));
}

#[test]
fn pl_cmdline_has_process_entry() {
    let syms = KernelSymbols::win10_x64_19041();
    let m = plugin_cmdline(&win_img(), &syms);
    let c = m.get(&1000).expect("explorer command line");
    assert!(c.contains("explorer"));
    assert!(c.contains("--pid 1000"));
}

// ───── Plugin: dlllist ────────────────────────────────────────────────────────

#[test]
fn pl_dlllist_returns_entries() {
    let syms = KernelSymbols::win10_x64_19041();
    let dlls = plugin_dlllist(&win_img(), &syms, 1000);
    assert!(!dlls.is_empty());
    let d = &dlls[0];
    assert!(d.in_load_order && d.in_init_order && d.in_mem_order);
}

// ───── Plugin: handles ────────────────────────────────────────────────────────

#[test]
fn pl_handles_synthesizes_when_empty() {
    let syms = KernelSymbols::win10_x64_19041();
    let h = plugin_handles(&win_img(), &syms, 1000);
    // No HDLR tags in mock → 5 synthesized handles
    assert_eq!(h.len(), 5);
}

// ───── Plugin: netscan ────────────────────────────────────────────────────────

#[test]
fn pl_netscan_includes_ncon() {
    let conns = plugin_netscan(&win_img());
    assert!(conns.iter().any(|c| c.local_port == 443 && c.remote_port == 80));
}

// ───── Plugin: filescan ───────────────────────────────────────────────────────

#[test]
fn pl_filescan_empty_mock() {
    // No FOBJ / eliF tags in build_mock_image
    let f = plugin_filescan(&win_img());
    assert!(f.is_empty(), "unexpected files: {f:?}");
}

// ───── Plugin: vadinfo & malfind ──────────────────────────────────────────────

#[test]
fn pl_vadinfo_synthesizes_for_known_pid() {
    let syms = KernelSymbols::win10_x64_19041();
    let v = plugin_vadinfo(&win_img(), &syms, 1000);
    // No VADN tags → synth 3 entries (image, stack, heap)
    assert_eq!(v.len(), 3);
    assert!(v.iter().any(|e| e.vad_type == VadType::Image));
    assert!(v.iter().any(|e| e.vad_type == VadType::Private));
}

#[test]
fn pl_vadinfo_unknown_pid_empty() {
    let syms = KernelSymbols::win10_x64_19041();
    let v = plugin_vadinfo(&win_img(), &syms, 0xDEAD_BEEF);
    assert!(v.is_empty());
}

#[test]
fn pl_malfind_runs() {
    let syms = KernelSymbols::win10_x64_19041();
    // Should not panic; mock has no RWX/PE-private regions so likely empty.
    let _ = plugin_malfind(&win_img(), &syms);
}

// ───── Send/Sync ─────────────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WindowsVersion>();
    assert_send_sync::<ThreadState>();
    assert_send_sync::<NetProtocol>();
    assert_send_sync::<ConnectionState>();
    assert_send_sync::<ProcessInfo>();
    assert_send_sync::<ModuleInfo>();
    assert_send_sync::<NetworkConnection>();
    assert_send_sync::<RegistryHive>();
    assert_send_sync::<HeapAllocation>();
    assert_send_sync::<KernelSymbols>();
    assert_send_sync::<WindowsKernelStructures>();
    assert_send_sync::<VadType>();
    assert_send_sync::<HiveType>();
}
