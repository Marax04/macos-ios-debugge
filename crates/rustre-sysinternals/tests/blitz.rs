//! Blitz unit tests for `rustre-sysinternals` public API.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustre_sysinternals::{
    AutorunCategory, AutorunEntry, AutorunScanner, CertInfo, DriverFlags, DriverInfo,
    FileSignatureChecker, HandleInfo, InMemorySystemMonitor, MemoryInfo, MemoryStats, ModuleInfo,
    NetworkConnection, NetworkEndpoint, NetworkMonitor, NetworkProtocol, ProcessInfo,
    ProcessScanner, ProcessStatus, ProcessTree, RegistryDataType, RegistryValue, ResourceUsage,
    SignatureInfo, SysinternalsError, SystemMonitor, SystemSnapshot, TcpState, ThreadInfo,
    ThreadState,
};

fn sample_proc(pid: u32, parent_pid: u32, name: &str) -> ProcessInfo {
    ProcessInfo::new(pid, parent_pid, name)
}

#[test]
fn error_display_messages() {
    assert_eq!(SysinternalsError::AccessDenied.to_string(), "Access denied");
    assert_eq!(SysinternalsError::Unsupported.to_string(), "Not supported");
    assert_eq!(SysinternalsError::Timeout.to_string(), "Timeout");
    assert_eq!(
        SysinternalsError::ProcessNotFound(42).to_string(),
        "Process not found: 42"
    );
    assert!(SysinternalsError::Io("x".into()).to_string().contains('x'));
    assert!(SysinternalsError::InvalidData("y".into()).to_string().contains('y'));
    assert!(SysinternalsError::NotFound("z".into()).to_string().contains('z'));
}

#[test]
fn driver_flags_bitops_and_display() {
    let f = DriverFlags::LOADED | DriverFlags::KERNEL_MODE;
    assert!(f.contains(DriverFlags::LOADED));
    assert!(f.contains(DriverFlags::KERNEL_MODE));
    assert!(!f.contains(DriverFlags::FS_FILTER));
    assert_eq!(DriverFlags::NONE.bits(), 0);
    assert!(!format!("{f}").is_empty());
}

#[test]
fn thread_state_display() {
    assert_eq!(ThreadState::Running.to_string(), "Running");
    assert_eq!(ThreadState::Waiting.to_string(), "Waiting");
    assert_eq!(ThreadState::Ready.to_string(), "Ready");
    assert_eq!(ThreadState::Terminated.to_string(), "Terminated");
    assert_eq!(ThreadState::Unknown.to_string(), "Unknown");
}

#[test]
fn process_status_display() {
    assert_eq!(ProcessStatus::Running.to_string(), "Running");
    assert_eq!(ProcessStatus::Sleeping.to_string(), "Sleeping");
    assert_eq!(ProcessStatus::Stopped.to_string(), "Stopped");
    assert_eq!(ProcessStatus::Zombie.to_string(), "Zombie");
    assert_eq!(ProcessStatus::Unknown.to_string(), "Unknown");
}

#[test]
fn network_protocol_display() {
    assert_eq!(NetworkProtocol::Tcp.to_string(), "TCP");
    assert_eq!(NetworkProtocol::Udp.to_string(), "UDP");
    assert_eq!(NetworkProtocol::Tcp6.to_string(), "TCP6");
    assert_eq!(NetworkProtocol::Udp6.to_string(), "UDP6");
    assert_eq!(NetworkProtocol::Raw.to_string(), "RAW");
}

#[test]
fn tcp_state_display_all_variants() {
    for (s, expect) in [
        (TcpState::Listen, "LISTEN"),
        (TcpState::Established, "ESTABLISHED"),
        (TcpState::TimeWait, "TIME_WAIT"),
        (TcpState::CloseWait, "CLOSE_WAIT"),
        (TcpState::Closed, "CLOSED"),
        (TcpState::SynSent, "SYN_SENT"),
        (TcpState::SynReceived, "SYN_RECEIVED"),
        (TcpState::FinWait1, "FIN_WAIT_1"),
        (TcpState::FinWait2, "FIN_WAIT_2"),
        (TcpState::LastAck, "LAST_ACK"),
        (TcpState::Closing, "CLOSING"),
        (TcpState::Unknown, "UNKNOWN"),
    ] {
        assert_eq!(s.to_string(), expect);
    }
}

#[test]
fn registry_data_type_display() {
    assert_eq!(RegistryDataType::RegSz.to_string(), "REG_SZ");
    assert_eq!(RegistryDataType::RegBinary.to_string(), "REG_BINARY");
    assert_eq!(RegistryDataType::RegDword.to_string(), "REG_DWORD");
    assert_eq!(RegistryDataType::RegQword.to_string(), "REG_QWORD");
    assert_eq!(RegistryDataType::RegMultiSz.to_string(), "REG_MULTI_SZ");
    assert_eq!(RegistryDataType::RegExpandSz.to_string(), "REG_EXPAND_SZ");
}

#[test]
fn memory_info_ratio_zero_vss() {
    let m = MemoryInfo::new(0, 100, 100, 0, 0, 0);
    assert!(m.rss_vss_ratio().abs() < f64::EPSILON);
}

#[test]
fn memory_info_ratio_normal() {
    // rss=512 MiB, vss=1024 MiB ratio ~= 0.5
    let m = MemoryInfo::new(1024 * 1024 * 1024, 512 * 1024 * 1024, 0, 0, 0, 0);
    let r = m.rss_vss_ratio();
    assert!((r - 0.5).abs() < 0.01);
}

#[test]
fn memory_info_ratio_sub_mib_vss() {
    // vss != 0 but < 1 MiB => vss_mib==0 branch -> returns 1.0
    let m = MemoryInfo::new(1024, 1024, 0, 0, 0, 0);
    assert!((m.rss_vss_ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn memory_info_default_is_zero() {
    let m = MemoryInfo::default();
    assert_eq!(m.vss, 0);
    assert_eq!(m.rss, 0);
}

#[test]
fn memory_stats_default() {
    let m = MemoryStats::default();
    assert_eq!(m.working_set, 0);
}

#[test]
fn module_info_contains_addr() {
    let m = ModuleInfo::new(0x1000, 0x100, "foo.dll", "C:\\foo.dll");
    assert!(m.contains_addr(0x1000));
    assert!(m.contains_addr(0x10FF));
    assert!(!m.contains_addr(0x0FFF));
    assert!(!m.contains_addr(0x1100));
    assert!(m.is_64bit);
    assert!(m.signed.is_none());
}

#[test]
fn module_info_zero_size() {
    let m = ModuleInfo::new(0x1000, 0, "x", "x");
    assert!(!m.contains_addr(0x1000));
}

#[test]
fn module_info_saturating() {
    let m = ModuleInfo::new(u64::MAX - 1, u64::MAX, "x", "x");
    // base+size saturates, so just inside is true
    assert!(m.contains_addr(u64::MAX - 1));
}

#[test]
fn thread_info_new_defaults() {
    let t = ThreadInfo::new(1, 2, 0xdead, 5, ThreadState::Running);
    assert_eq!(t.tid, 1);
    assert_eq!(t.pid, 2);
    assert_eq!(t.start_address, 0xdead);
    assert_eq!(t.priority, 5);
    assert_eq!(t.state, ThreadState::Running);
    assert!(t.wait_reason.is_empty());
}

#[test]
fn process_info_env_helpers() {
    let mut p = sample_proc(10, 1, "test.exe");
    p.env_vars.push(("PATH".into(), "/bin".into()));
    p.env_vars.push(("HOME".into(), "/home/x".into()));
    assert_eq!(p.get_env("PATH"), Some("/bin"));
    assert_eq!(p.get_env("HOME"), Some("/home/x"));
    assert_eq!(p.get_env("nope"), None);
}

#[test]
fn process_info_temp_and_system32() {
    let mut p = sample_proc(1, 0, "x");
    p.exe_path = "C:\\Windows\\Temp\\bad.exe".into();
    assert!(p.in_temp_dir());
    assert!(!p.is_system32());

    p.exe_path = "C:\\Windows\\System32\\svchost.exe".into();
    assert!(!p.in_temp_dir());
    assert!(p.is_system32());

    p.exe_path = "/usr/bin/foo".into();
    assert!(!p.in_temp_dir());
    assert!(!p.is_system32());

    p.exe_path = "/tmp/x".into();
    assert!(p.in_temp_dir());
}

#[test]
fn process_info_csv_and_json() {
    let p = sample_proc(33, 1, "init");
    let csv = p.to_csv_row();
    assert!(csv.starts_with("33,1,init,"));
    let json = p.to_json().expect("json");
    assert!(json.contains("\"pid\":33"));
    assert!(json.contains("\"name\":\"init\""));
}

#[test]
fn driver_info_new() {
    let d = DriverInfo::new(0x1000, 0x200, "/d", "drv", DriverFlags::LOADED);
    assert_eq!(d.base, 0x1000);
    assert_eq!(d.size, 0x200);
    assert_eq!(d.name, "drv");
    assert!(d.flags.contains(DriverFlags::LOADED));
}

#[test]
fn handle_info_new() {
    let h = HandleInfo::new(0xabc, 4, "File", 0x1000, 0x001f_01ff);
    assert_eq!(h.handle, 0xabc);
    assert_eq!(h.type_name, "File");
}

#[test]
fn registry_value_new() {
    let v = RegistryValue::new(
        "HKLM",
        "Software\\Test",
        "Value",
        RegistryDataType::RegSz,
        b"hi".to_vec(),
    );
    assert_eq!(v.hive, "HKLM");
    assert_eq!(v.data, b"hi");
    assert_eq!(v.data_type, RegistryDataType::RegSz);
}

#[test]
fn network_endpoint_new() {
    let e = NetworkEndpoint::new(
        9,
        NetworkProtocol::Tcp,
        "127.0.0.1",
        80,
        "10.0.0.1",
        443,
        TcpState::Established,
    );
    assert_eq!(e.local_port, 80);
    assert_eq!(e.remote_port, 443);
    assert_eq!(e.protocol, NetworkProtocol::Tcp);
}

#[test]
fn network_connection_tcp_helpers() {
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let c = NetworkConnection::new_tcp(7, "p", local, 8080, remote, 443, TcpState::Established);
    assert!(c.is_established());
    assert!(!c.is_listening());
    let listening =
        NetworkConnection::new_tcp(8, "p", local, 22, remote, 0, TcpState::Listen);
    assert!(listening.is_listening());
    assert!(!listening.is_established());

    let csv = c.to_csv_row();
    assert!(csv.contains("7,p,TCP,127.0.0.1,8080,10.0.0.1,ESTABLISHED"));
}

#[test]
fn system_snapshot_empty_const() {
    let s = SystemSnapshot::empty();
    assert!(s.processes.is_empty());
    assert!(s.drivers.is_empty());
    assert!(s.network.is_empty());
    assert!(s.handles.is_empty());
}

#[test]
fn in_memory_system_monitor_all_methods() {
    let mut m = InMemorySystemMonitor::new();
    m.add_process(sample_proc(1, 0, "init"));
    m.add_process(sample_proc(2, 1, "child"));
    m.add_driver(DriverInfo::new(0, 0, "", "d", DriverFlags::NONE));
    m.add_handle(HandleInfo::new(1, 1, "K", 0, 0));
    m.add_handle(HandleInfo::new(2, 2, "K", 0, 0));
    m.add_endpoint(NetworkEndpoint::new(
        1,
        NetworkProtocol::Udp,
        "0",
        0,
        "0",
        0,
        TcpState::Closed,
    ));

    assert_eq!(m.list_processes().unwrap().len(), 2);
    assert_eq!(m.list_drivers().unwrap().len(), 1);
    assert_eq!(m.list_handles(None).unwrap().len(), 2);
    assert_eq!(m.list_handles(Some(1)).unwrap().len(), 1);
    assert_eq!(m.list_handles(Some(99)).unwrap().len(), 0);
    assert_eq!(m.network_connections().unwrap().len(), 1);
    let snap = m.snapshot().unwrap();
    assert_eq!(snap.processes.len(), 2);
    assert_eq!(snap.drivers.len(), 1);
    assert_eq!(snap.network.len(), 1);
    assert_eq!(snap.handles.len(), 2);
}

#[test]
fn system_monitor_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemorySystemMonitor>();
}

#[test]
fn process_scanner_stubs() {
    assert!(ProcessScanner::scan().unwrap().is_empty());
    let err = ProcessScanner::get_process(123).unwrap_err();
    assert!(matches!(err, SysinternalsError::ProcessNotFound(_)));
    assert!(ProcessScanner::find_by_name("x").unwrap().is_empty());
    let tree = ProcessScanner::process_tree().unwrap();
    assert!(tree.roots.is_empty());
}

#[test]
fn process_scanner_cache_lifecycle() {
    let mut s = ProcessScanner::new(Duration::from_millis(50));
    assert!(s.needs_refresh());
    s.update_cache(vec![sample_proc(10, 0, "a"), sample_proc(11, 0, "b")]);
    assert!(!s.needs_refresh());
    assert_eq!(s.cached(10).map(|p| p.name), Some("a".to_string()));
    assert_eq!(s.cached(11).map(|p| p.name), Some("b".to_string()));
    assert!(s.cached(99).is_none());
}

#[test]
fn process_tree_from_list_basic() {
    let procs = vec![
        sample_proc(1, 0, "init"),
        sample_proc(2, 1, "shell"),
        sample_proc(3, 2, "child"),
        sample_proc(4, 1, "sibling"),
    ];
    let tree = ProcessTree::from_list(&procs).unwrap();
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.count(), 4);
    assert_eq!(tree.max_depth(), 3);
    let found = tree.find(3).unwrap();
    assert_eq!(found.info.name, "child");
    assert!(tree.find(999).is_none());
    let txt = tree.to_text(2);
    assert!(txt.contains("init"));
    assert!(txt.contains("shell"));
}

#[test]
fn process_tree_empty() {
    let tree = ProcessTree::from_list(&[]).unwrap();
    assert_eq!(tree.count(), 0);
    assert_eq!(tree.max_depth(), 0);
    assert!(tree.find(1).is_none());
    assert!(tree.to_text(2).is_empty());
}

#[test]
fn process_tree_orphan_parents_become_roots() {
    // ppid 999 doesn't exist -> treated as root
    let procs = vec![sample_proc(5, 999, "orphan")];
    let tree = ProcessTree::from_list(&procs).unwrap();
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].info.pid, 5);
}

#[test]
fn process_scanner_orphaned_processes_none() {
    let procs = vec![sample_proc(1, 0, "init"), sample_proc(2, 1, "child")];
    let tree = ProcessTree::from_list(&procs).unwrap();
    let orphans = ProcessScanner::orphaned_processes(&tree);
    // ppid=0 ignored; child ppid=1 exists, so no orphans
    assert!(orphans.is_empty());
}

#[test]
fn autorun_category_display() {
    assert_eq!(AutorunCategory::LogonRegistry.to_string(), "Logon Registry");
    assert_eq!(AutorunCategory::RunOnce.to_string(), "Run Once");
    assert_eq!(AutorunCategory::Services.to_string(), "Services");
    assert_eq!(AutorunCategory::AppCertDlls.to_string(), "AppCert DLLs");
    assert_eq!(AutorunCategory::Winlogon.to_string(), "Winlogon");
}

#[test]
fn autorun_entry_suspicious_path() {
    let mut e = AutorunEntry::new(
        AutorunCategory::Services,
        "loc",
        "n",
        "C:\\Users\\x\\AppData\\bad.exe",
        "C:\\Users\\x\\AppData\\bad.exe",
    );
    assert!(e.is_suspicious_path());
    e.image_path = "C:\\Windows\\System32\\good.exe".into();
    assert!(!e.is_suspicious_path());
    e.image_path = "/tmp/x".into();
    assert!(e.is_suspicious_path());
}

#[test]
fn autorun_entry_unsigned_and_csv() {
    let mut e = AutorunEntry::new(
        AutorunCategory::RunOnce,
        "loc",
        "n",
        "C:\\good.exe",
        "C:\\good.exe",
    );
    assert!(!e.is_unsigned());
    e.signed = Some(false);
    assert!(e.is_unsigned());
    e.enabled = false;
    assert!(!e.is_unsigned());
    e.enabled = true;
    e.signed = Some(true);
    let csv = e.to_csv_row();
    assert!(csv.contains("Run Once"));
    assert!(csv.contains("signed"));
}

#[test]
fn autorun_scanner_stubs_and_filters() {
    assert!(AutorunScanner::scan_all().unwrap().is_empty());
    assert!(AutorunScanner::scan_category(AutorunCategory::Services)
        .unwrap()
        .is_empty());

    let mut e1 = AutorunEntry::new(AutorunCategory::Services, "L", "n1", "C:\\ok", "C:\\ok");
    e1.signed = Some(true);
    let mut e2 = AutorunEntry::new(AutorunCategory::Services, "L", "n2", "C:\\Temp\\x", "x");
    e2.signed = Some(true);
    let mut e3 = AutorunEntry::new(AutorunCategory::Services, "L", "n3", "C:\\good", "g");
    e3.signed = Some(false);

    let entries = vec![e1, e2, e3];
    let susp = AutorunScanner::filter_suspicious(&entries);
    assert_eq!(susp.len(), 2);
    let uns = AutorunScanner::filter_unsigned(&entries);
    assert_eq!(uns.len(), 1);
}

#[test]
fn autorun_scanner_diff() {
    let a = AutorunEntry::new(AutorunCategory::Services, "L1", "a", "p1", "p1");
    let b_old = AutorunEntry::new(AutorunCategory::Services, "L1", "b", "p2", "p2");
    let mut b_new = b_old.clone();
    b_new.launch_string = "p2-changed".into();
    let c = AutorunEntry::new(AutorunCategory::Services, "L1", "c", "p3", "p3");

    let baseline = vec![a.clone(), b_old];
    let current = vec![a, b_new, c];

    let diff = AutorunScanner::diff(&baseline, &current);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].name, "c");
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert!(!diff.is_clean());
    assert_eq!(diff.total_changes(), 2);

    let empty_diff = AutorunScanner::diff(&[], &[]);
    assert!(empty_diff.is_clean());
    assert_eq!(empty_diff.total_changes(), 0);
}

#[test]
fn cert_info_valid_at() {
    let c = CertInfo::new("s", "i", "00", 100, 200, false);
    assert!(!c.valid_at(50));
    assert!(c.valid_at(100));
    assert!(c.valid_at(150));
    assert!(c.valid_at(200));
    assert!(!c.valid_at(201));
}

#[test]
fn signature_info_unsigned_and_has_root() {
    let mut s = SignatureInfo::unsigned("/x/y");
    assert!(!s.is_signed);
    assert!(!s.is_valid);
    assert_eq!(s.path, "/x/y");
    assert!(!s.has_root_cert());
    s.cert_chain
        .push(CertInfo::new("s", "i", "0", 0, 1, true));
    assert!(s.has_root_cert());
}

#[test]
fn file_signature_checker_has_pe_signature_negatives() {
    assert!(!FileSignatureChecker::has_pe_signature(&[]));
    assert!(!FileSignatureChecker::has_pe_signature(b"not a pe"));
    let mut small = vec![0u8; 0x40];
    small[0] = b'M';
    small[1] = b'Z';
    // PE offset points past end -> false
    assert!(!FileSignatureChecker::has_pe_signature(&small));
}

#[test]
fn file_signature_checker_hash_io_error() {
    let p = std::path::Path::new("does-not-exist-XYZ-12345.bin");
    let err = FileSignatureChecker::hash_sha256(p).unwrap_err();
    assert!(matches!(err, SysinternalsError::Io(_)));
    let err = FileSignatureChecker::hash_md5(p).unwrap_err();
    assert!(matches!(err, SysinternalsError::Io(_)));
    let err = FileSignatureChecker::check(p).unwrap_err();
    assert!(matches!(err, SysinternalsError::Io(_)));
}

#[test]
fn file_signature_checker_hash_known_vectors() {
    let dir = std::env::temp_dir();
    let path = dir.join("rustre_sysinternals_blitz_empty.bin");
    std::fs::write(&path, b"").unwrap();
    let s = FileSignatureChecker::hash_sha256(&path).unwrap();
    // SHA-256 of empty input
    assert_eq!(
        s,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let m = FileSignatureChecker::hash_md5(&path).unwrap();
    // MD5 of empty input
    assert_eq!(m, "d41d8cd98f00b204e9800998ecf8427e");

    let path2 = dir.join("rustre_sysinternals_blitz_abc.bin");
    std::fs::write(&path2, b"abc").unwrap();
    let s2 = FileSignatureChecker::hash_sha256(&path2).unwrap();
    assert_eq!(
        s2,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let m2 = FileSignatureChecker::hash_md5(&path2).unwrap();
    assert_eq!(m2, "900150983cd24fb0d6963f7d28e17f72");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn file_signature_checker_check_unsigned_file() {
    let dir = std::env::temp_dir();
    let p = dir.join("rustre_sysinternals_blitz_unsigned.bin");
    std::fs::write(&p, b"not a PE file at all").unwrap();
    let info = FileSignatureChecker::check(&p).unwrap();
    assert!(!info.is_signed);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn network_monitor_stubs_and_helpers() {
    assert!(NetworkMonitor::snapshot().unwrap().is_empty());
    assert!(NetworkMonitor::connections_for_pid(1).unwrap().is_empty());
    assert!(NetworkMonitor::listening_ports().unwrap().is_empty());
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(NetworkMonitor::connections_to_addr(addr).unwrap().is_empty());

    let c1 = NetworkConnection::new_tcp(1, "a", addr, 22, addr, 0, TcpState::Listen);
    let c2 = NetworkConnection::new_tcp(2, "b", addr, 80, addr, 1234, TcpState::Established);
    let c3 = NetworkConnection::new_tcp(1, "a", addr, 443, addr, 5678, TcpState::Established);
    let conns = vec![c1, c2, c3];

    assert_eq!(NetworkMonitor::filter_listening(&conns).len(), 1);
    assert_eq!(NetworkMonitor::filter_established(&conns).len(), 2);
    let grouped = NetworkMonitor::group_by_pid(&conns);
    assert_eq!(grouped.get(&1).map(Vec::len), Some(2));
    assert_eq!(grouped.get(&2).map(Vec::len), Some(1));

    let csv = NetworkMonitor::to_csv(&conns);
    assert!(csv.starts_with("PID,Process"));
    assert_eq!(csv.lines().count(), 4); // header + 3
}

#[test]
fn resource_usage_new_defaults() {
    let r = ResourceUsage::new(77);
    assert_eq!(r.pid, 77);
    assert!(r.cpu_percent.abs() < f64::EPSILON);
    assert_eq!(r.memory_bytes, 0);
    assert_eq!(r.disk_read_bytes, 0);
    assert_eq!(r.thread_count, 0);
}

#[test]
fn enum_equality_and_hash() {
    use std::collections::HashSet;
    let mut set: HashSet<TcpState> = HashSet::new();
    set.insert(TcpState::Listen);
    set.insert(TcpState::Listen);
    set.insert(TcpState::Established);
    assert_eq!(set.len(), 2);
}

#[test]
fn serde_roundtrip_process_info() {
    let p = sample_proc(11, 0, "rt");
    let s = serde_json::to_string(&p).unwrap();
    let back: ProcessInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.pid, 11);
    assert_eq!(back.name, "rt");
}

#[test]
fn serde_roundtrip_driver_flags() {
    let f = DriverFlags::LOADED | DriverFlags::FS_FILTER;
    let s = serde_json::to_string(&f).unwrap();
    let back: DriverFlags = serde_json::from_str(&s).unwrap();
    assert_eq!(back, f);
}
