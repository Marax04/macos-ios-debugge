//! Blitz2 coverage tests for rustre-sysinternals.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustre_sysinternals::*;

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}
const fn lcg_next(s: &mut u64) -> u64 {
    *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
    *s
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ─── Constructors ─────────────────────────────────────────────────────────

#[test]
fn memory_info_new_zero() {
    let m = MemoryInfo::new(0, 0, 0, 0, 0, 0);
    assert_eq!(m.vss, 0);
    assert!(m.rss_vss_ratio().abs() < f64::EPSILON);
}

#[test]
fn memory_info_ratio_one() {
    let m = MemoryInfo::new(100, 100, 100, 0, 0, 0);
    assert!((m.rss_vss_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn memory_info_ratio_half() {
    let m = MemoryInfo::new(200, 100, 100, 0, 0, 0);
    assert!((m.rss_vss_ratio() - 0.5).abs() < 1e-9);
}

#[test]
fn memory_info_ratio_max() {
    let m = MemoryInfo::new(u64::MAX, u64::MAX, 0, 0, 0, 0);
    assert!((m.rss_vss_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn module_info_contains_basic() {
    let m = ModuleInfo::new(0x1000, 0x100, "x", "/x");
    assert!(m.contains_addr(0x1000));
    assert!(m.contains_addr(0x10FF));
    assert!(!m.contains_addr(0x1100));
    assert!(!m.contains_addr(0xFFF));
}

#[test]
fn module_info_contains_zero_size() {
    let m = ModuleInfo::new(0x1000, 0, "x", "/x");
    assert!(!m.contains_addr(0x1000));
}

#[test]
fn module_info_contains_saturating() {
    let m = ModuleInfo::new(u64::MAX - 5, 100, "x", "/x");
    // saturating_add caps end at u64::MAX; range is [base, u64::MAX) → MAX excluded.
    assert!(!m.contains_addr(u64::MAX));
    assert!(m.contains_addr(u64::MAX - 5));
    assert!(m.contains_addr(u64::MAX - 1));
}

#[test]
fn thread_info_new_defaults() {
    let t = ThreadInfo::new(1, 2, 0x1000, 5, ThreadState::Running);
    assert_eq!(t.tid, 1);
    assert_eq!(t.pid, 2);
    assert_eq!(t.state, ThreadState::Running);
    assert!(t.wait_reason.is_empty());
}

#[test]
fn process_info_new_defaults() {
    let p = ProcessInfo::new(42, 1, "init");
    assert_eq!(p.pid, 42);
    assert_eq!(p.ppid, 1);
    assert_eq!(p.name, "init");
    assert_eq!(p.status, ProcessStatus::Unknown);
}

#[test]
fn process_info_env_get() {
    let mut p = ProcessInfo::new(1, 0, "x");
    p.env_vars.push(("PATH".into(), "/bin".into()));
    p.env_vars.push(("HOME".into(), "/root".into()));
    assert_eq!(p.get_env("PATH"), Some("/bin"));
    assert_eq!(p.get_env("HOME"), Some("/root"));
    assert_eq!(p.get_env("MISSING"), None);
}

#[test]
fn process_info_temp_dir_detection() {
    let mut p = ProcessInfo::new(1, 0, "x");
    p.exe_path = "C:\\Users\\x\\Temp\\foo.exe".into();
    assert!(p.in_temp_dir());
    p.exe_path = "/tmp/foo".into();
    assert!(p.in_temp_dir());
    p.exe_path = "/usr/bin/foo".into();
    assert!(!p.in_temp_dir());
}

#[test]
fn process_info_system32_detection() {
    let mut p = ProcessInfo::new(1, 0, "x");
    p.exe_path = "C:\\Windows\\System32\\foo.exe".into();
    assert!(p.is_system32());
    p.exe_path = "C:\\Windows\\SysWOW64\\foo.exe".into();
    assert!(p.is_system32());
    p.exe_path = "/usr/bin/foo".into();
    assert!(!p.is_system32());
}

#[test]
fn process_info_csv_row() {
    let p = ProcessInfo::new(42, 1, "init");
    let csv = p.to_csv_row();
    assert!(csv.starts_with("42,1,init,"));
}

#[test]
fn process_info_json_roundtrip() {
    let p = ProcessInfo::new(7, 1, "abc");
    let j = p.to_json().unwrap();
    assert!(j.contains("\"pid\":7"));
}

#[test]
fn driver_info_new() {
    let d = DriverInfo::new(0x1000, 0x200, "/d", "drv", DriverFlags::LOADED);
    assert_eq!(d.base, 0x1000);
    assert_eq!(d.size, 0x200);
    assert!(d.flags.contains(DriverFlags::LOADED));
}

#[test]
fn handle_info_new() {
    let h = HandleInfo::new(0xABCD, 1, "File", 0xDEAD, 0xF003F);
    assert_eq!(h.handle, 0xABCD);
    assert_eq!(h.type_name, "File");
}

#[test]
fn registry_value_new() {
    let r = RegistryValue::new("HKLM", "Software\\X", "Val", RegistryDataType::RegDword, vec![1,0,0,0]);
    assert_eq!(r.hive, "HKLM");
    assert_eq!(r.data_type, RegistryDataType::RegDword);
    assert_eq!(r.data.len(), 4);
}

#[test]
fn network_endpoint_new() {
    let e = NetworkEndpoint::new(1, NetworkProtocol::Tcp, "0.0.0.0", 80, "1.2.3.4", 443, TcpState::Established);
    assert_eq!(e.local_port, 80);
    assert_eq!(e.state, TcpState::Established);
}

#[test]
fn network_connection_new_tcp() {
    let c = NetworkConnection::new_tcp(
        1, "p",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80,
        IpAddr::V4(Ipv4Addr::new(1,2,3,4)), 443,
        TcpState::Established,
    );
    assert!(c.is_established());
    assert!(!c.is_listening());
    assert_eq!(c.protocol, NetworkProtocol::Tcp);
}

#[test]
fn network_connection_listening() {
    let c = NetworkConnection::new_tcp(
        1, "p",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0,
        TcpState::Listen,
    );
    assert!(c.is_listening());
    assert!(!c.is_established());
}

#[test]
fn network_connection_csv() {
    let c = NetworkConnection::new_tcp(
        7, "proc",
        IpAddr::V4(Ipv4Addr::LOCALHOST), 80,
        IpAddr::V4(Ipv4Addr::new(1,2,3,4)), 443,
        TcpState::Established,
    );
    let row = c.to_csv_row();
    assert!(row.starts_with("7,proc,TCP,"));
}

#[test]
fn system_snapshot_empty() {
    let s = SystemSnapshot::empty();
    assert!(s.processes.is_empty());
    assert!(s.drivers.is_empty());
    assert!(s.handles.is_empty());
    assert!(s.network.is_empty());
}

// ─── In-Memory Monitor ────────────────────────────────────────────────────

#[test]
fn in_memory_monitor_add_and_list() {
    let mut m = InMemorySystemMonitor::new();
    m.add_process(ProcessInfo::new(1, 0, "init"));
    m.add_process(ProcessInfo::new(2, 1, "child"));
    m.add_driver(DriverInfo::new(0, 0, "/d", "d", DriverFlags::NONE));
    m.add_handle(HandleInfo::new(1, 1, "File", 0, 0));
    m.add_handle(HandleInfo::new(2, 2, "File", 0, 0));
    m.add_endpoint(NetworkEndpoint::new(1, NetworkProtocol::Tcp, "0.0.0.0", 80, "", 0, TcpState::Listen));
    assert_eq!(m.list_processes().unwrap().len(), 2);
    assert_eq!(m.list_drivers().unwrap().len(), 1);
    assert_eq!(m.list_handles(None).unwrap().len(), 2);
    assert_eq!(m.list_handles(Some(1)).unwrap().len(), 1);
    assert_eq!(m.list_handles(Some(99)).unwrap().len(), 0);
    assert_eq!(m.network_connections().unwrap().len(), 1);
    let snap = m.snapshot().unwrap();
    assert_eq!(snap.processes.len(), 2);
}

// ─── ProcessTree ──────────────────────────────────────────────────────────

#[allow(clippy::similar_names)]
fn make_proc(pid: u32, ppid: u32) -> ProcessInfo {
    ProcessInfo::new(pid, ppid, format!("p{pid}"))
}

#[test]
fn process_tree_empty() {
    let t = ProcessTree::from_list(&[]).unwrap();
    assert_eq!(t.count(), 0);
    assert_eq!(t.max_depth(), 0);
}

#[test]
fn process_tree_single_root() {
    let t = ProcessTree::from_list(&[make_proc(1, 0)]).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.max_depth(), 1);
    assert!(t.find(1).is_some());
    assert!(t.find(99).is_none());
}

#[test]
fn process_tree_simple_hierarchy() {
    let procs = vec![make_proc(1,0), make_proc(2,1), make_proc(3,1), make_proc(4,2)];
    let t = ProcessTree::from_list(&procs).unwrap();
    assert_eq!(t.count(), 4);
    assert_eq!(t.max_depth(), 3);
}

#[test]
fn process_tree_orphan_promoted_to_root() {
    // ppid 99 does not exist → orphan should be a root
    let procs = vec![make_proc(1,0), make_proc(5,99)];
    let t = ProcessTree::from_list(&procs).unwrap();
    assert_eq!(t.roots.len(), 2);
}

#[test]
fn process_tree_self_parent_is_root() {
    let procs = vec![make_proc(7,7)];
    let t = ProcessTree::from_list(&procs).unwrap();
    assert_eq!(t.roots.len(), 1);
}

#[test]
fn process_tree_cycle_is_safe() {
    // 100 → 200 → 100. PIDs exist; both have non-zero ppids referencing existing pids → no root.
    let procs = vec![make_proc(100, 200), make_proc(200, 100)];
    let t = ProcessTree::from_list(&procs).unwrap();
    // No infinite recursion. Either zero roots (no root since each refs the other) or finite tree.
    assert!(t.count() <= 4);
}

#[test]
fn process_tree_text_render() {
    let procs = vec![make_proc(1,0), make_proc(2,1)];
    let t = ProcessTree::from_list(&procs).unwrap();
    let s = t.to_text(2);
    assert!(s.contains("[1]"));
    assert!(s.contains("[2]"));
}

#[test]
fn process_tree_orphaned_processes() {
    let procs = vec![make_proc(1,0), make_proc(2,1)];
    let t = ProcessTree::from_list(&procs).unwrap();
    let orph = ProcessScanner::orphaned_processes(&t);
    assert!(orph.is_empty());
}

#[test]
fn process_scanner_stubs() {
    assert!(ProcessScanner::scan().unwrap().is_empty());
    assert!(ProcessScanner::get_process(1).is_err());
    assert!(ProcessScanner::find_by_name("x").unwrap().is_empty());
    let t = ProcessScanner::process_tree().unwrap();
    assert_eq!(t.count(), 0);
}

#[test]
fn process_scanner_cache_lifecycle() {
    let mut s = ProcessScanner::new(Duration::from_millis(1));
    assert!(s.needs_refresh());
    s.update_cache(vec![make_proc(1,0), make_proc(2,1)]);
    assert!(!s.needs_refresh());
    assert!(s.cached(1).is_some());
    assert!(s.cached(99).is_none());
    thread::sleep(Duration::from_millis(5));
    assert!(s.needs_refresh());
}

// ─── Autoruns ─────────────────────────────────────────────────────────────

#[test]
fn autorun_entry_suspicious_path() {
    let mut e = AutorunEntry::new(AutorunCategory::RunOnce, "loc", "n", "C:\\Users\\x\\AppData\\foo.exe", "");
    assert!(e.is_suspicious_path());
    e.image_path = "C:\\Windows\\System32\\svchost.exe".into();
    assert!(!e.is_suspicious_path());
}

#[test]
fn autorun_entry_unsigned_detection() {
    let mut e = AutorunEntry::new(AutorunCategory::Services, "loc", "n", "p", "p");
    e.signed = Some(false);
    e.enabled = true;
    assert!(e.is_unsigned());
    e.enabled = false;
    assert!(!e.is_unsigned());
    e.enabled = true;
    e.signed = Some(true);
    assert!(!e.is_unsigned());
    e.signed = None;
    assert!(!e.is_unsigned());
}

#[test]
fn autorun_entry_csv() {
    let mut e = AutorunEntry::new(AutorunCategory::Services, "L", "N", "/p", "/p");
    e.signed = Some(true);
    let row = e.to_csv_row();
    assert!(row.contains("signed"));
    e.signed = Some(false);
    assert!(e.to_csv_row().contains("unsigned"));
    e.signed = None;
    assert!(e.to_csv_row().contains("unknown"));
}

#[test]
fn autorun_scanner_stubs() {
    assert!(AutorunScanner::scan_all().unwrap().is_empty());
    assert!(AutorunScanner::scan_category(AutorunCategory::Services).unwrap().is_empty());
}

#[test]
fn autorun_scanner_filter_suspicious() {
    let mut e1 = AutorunEntry::new(AutorunCategory::RunOnce, "L", "A", "C:\\temp\\x.exe", "");
    e1.signed = Some(true);
    let mut e2 = AutorunEntry::new(AutorunCategory::RunOnce, "L", "B", "C:\\Windows\\x.exe", "");
    e2.signed = Some(true);
    let entries = vec![e1, e2];
    let sus = AutorunScanner::filter_suspicious(&entries);
    assert_eq!(sus.len(), 1);
    assert_eq!(sus[0].name, "A");
}

#[test]
fn autorun_scanner_filter_unsigned() {
    let mut e1 = AutorunEntry::new(AutorunCategory::RunOnce, "L", "A", "p", "p");
    e1.signed = Some(false);
    let mut e2 = AutorunEntry::new(AutorunCategory::RunOnce, "L", "B", "p", "p");
    e2.signed = Some(true);
    let entries = vec![e1, e2];
    let u = AutorunScanner::filter_unsigned(&entries);
    assert_eq!(u.len(), 1);
}

#[test]
fn autorun_diff_clean() {
    let e = AutorunEntry::new(AutorunCategory::RunOnce, "L", "A", "p", "p");
    let e2 = e.clone();
    let d = AutorunScanner::diff(std::slice::from_ref(&e), &[e2]);
    assert!(d.is_clean());
    assert_eq!(d.total_changes(), 0);
}

#[test]
fn autorun_diff_added_removed_changed() {
    let a = AutorunEntry::new(AutorunCategory::RunOnce, "L", "A", "p", "p1");
    let b = AutorunEntry::new(AutorunCategory::RunOnce, "L", "B", "p", "p");
    let mut a2 = a.clone();
    a2.launch_string = "p2".into();
    let d = AutorunScanner::diff(&[a, b], &[a2, AutorunEntry::new(AutorunCategory::RunOnce, "L", "C", "p", "p")]);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.removed.len(), 1);
    assert_eq!(d.changed.len(), 1);
    assert!(!d.is_clean());
    assert_eq!(d.total_changes(), 3);
}

// ─── CertInfo / SignatureInfo / PE ────────────────────────────────────────

#[test]
fn cert_info_valid_at_boundaries() {
    let c = CertInfo::new("s", "i", "00", 100, 200, false);
    assert!(!c.valid_at(99));
    assert!(c.valid_at(100));
    assert!(c.valid_at(150));
    assert!(c.valid_at(200));
    assert!(!c.valid_at(201));
}

#[test]
fn signature_info_unsigned_helper() {
    let s = SignatureInfo::unsigned("/p");
    assert!(!s.is_signed);
    assert!(!s.is_valid);
    assert!(!s.has_root_cert());
}

#[test]
fn signature_info_has_root_cert() {
    let mut s = SignatureInfo::unsigned("/p");
    s.cert_chain.push(CertInfo::new("s","i","00",0,0,false));
    assert!(!s.has_root_cert());
    s.cert_chain.push(CertInfo::new("s","i","00",0,0,true));
    assert!(s.has_root_cert());
}

#[test]
fn pe_signature_rejects_short() {
    assert!(!FileSignatureChecker::has_pe_signature(&[]));
    assert!(!FileSignatureChecker::has_pe_signature(&[0u8; 10]));
    assert!(!FileSignatureChecker::has_pe_signature(&[0u8; 0x3F]));
}

#[test]
fn pe_signature_rejects_non_mz() {
    let mut buf = vec![0u8; 0x100];
    buf[0] = b'X';
    assert!(!FileSignatureChecker::has_pe_signature(&buf));
}

// ─── NetworkMonitor helpers ───────────────────────────────────────────────

#[test]
fn network_monitor_filters_and_grouping() {
    let c1 = NetworkConnection::new_tcp(1, "a",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, TcpState::Listen);
    let c2 = NetworkConnection::new_tcp(1, "a",
        IpAddr::V4(Ipv4Addr::LOCALHOST), 1000,
        IpAddr::V4(Ipv4Addr::new(1,2,3,4)), 443, TcpState::Established);
    let c3 = NetworkConnection::new_tcp(2, "b",
        IpAddr::V4(Ipv4Addr::LOCALHOST), 1001,
        IpAddr::V4(Ipv4Addr::new(1,2,3,4)), 443, TcpState::Established);
    let conns = vec![c1, c2, c3];
    assert_eq!(NetworkMonitor::filter_listening(&conns).len(), 1);
    assert_eq!(NetworkMonitor::filter_established(&conns).len(), 2);
    let g = NetworkMonitor::group_by_pid(&conns);
    assert_eq!(g.get(&1).unwrap().len(), 2);
    assert_eq!(g.get(&2).unwrap().len(), 1);
    let csv = NetworkMonitor::to_csv(&conns);
    assert!(csv.starts_with("PID,Process,"));
    assert_eq!(csv.lines().count(), 4);
}

#[test]
fn network_monitor_stubs() {
    assert!(NetworkMonitor::snapshot().unwrap().is_empty());
    assert!(NetworkMonitor::connections_for_pid(1).unwrap().is_empty());
    assert!(NetworkMonitor::listening_ports().unwrap().is_empty());
    assert!(NetworkMonitor::connections_to_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap().is_empty());
}

// ─── Display / Debug / Eq / Hash consistency ─────────────────────────────

#[test]
fn enum_display_strings() {
    assert_eq!(ThreadState::Running.to_string(), "Running");
    assert_eq!(ProcessStatus::Sleeping.to_string(), "Sleeping");
    assert_eq!(NetworkProtocol::Tcp.to_string(), "TCP");
    assert_eq!(NetworkProtocol::Udp6.to_string(), "UDP6");
    assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
    assert_eq!(TcpState::TimeWait.to_string(), "TIME_WAIT");
    assert_eq!(RegistryDataType::RegSz.to_string(), "REG_SZ");
    assert_eq!(AutorunCategory::Services.to_string(), "Services");
}

#[test]
fn enum_eq_hash_consistency_30_pairs() {
    let variants = [
        ThreadState::Running, ThreadState::Waiting, ThreadState::Ready,
        ThreadState::Terminated, ThreadState::Unknown,
    ];
    // Build 30 cross-pairs to compare.
    let mut s = lcg_seed();
    for _ in 0..30 {
        let a = variants[usize::try_from(lcg_next(&mut s) % variants.len() as u64).unwrap()];
        let b = variants[usize::try_from(lcg_next(&mut s) % variants.len() as u64).unwrap()];
        if a == b {
            assert_eq!(hash_of(&a), hash_of(&b));
        } else {
            // Different variants may or may not collide in hash, but Eq must be false.
            assert_ne!(a, b);
        }
    }
}

#[test]
fn tcp_state_hash_set() {
    let mut set = HashSet::new();
    set.insert(TcpState::Listen);
    set.insert(TcpState::Listen);
    set.insert(TcpState::Established);
    assert_eq!(set.len(), 2);
}

#[test]
fn driver_flags_bitops() {
    let f = DriverFlags::LOADED | DriverFlags::KERNEL_MODE;
    assert!(f.contains(DriverFlags::LOADED));
    assert!(f.contains(DriverFlags::KERNEL_MODE));
    assert!(!f.contains(DriverFlags::FS_FILTER));
    assert_eq!(hash_of(&f), hash_of(&(DriverFlags::LOADED | DriverFlags::KERNEL_MODE)));
}

#[test]
fn error_display() {
    let errors = [
        SysinternalsError::AccessDenied,
        SysinternalsError::Unsupported,
        SysinternalsError::Io("x".into()),
        SysinternalsError::ProcessNotFound(7),
        SysinternalsError::InvalidData("y".into()),
        SysinternalsError::Timeout,
        SysinternalsError::NotFound("z".into()),
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
        assert!(!format!("{e:?}").is_empty());
    }
}

#[test]
fn error_specific_variants() {
    match SysinternalsError::ProcessNotFound(42) {
        SysinternalsError::ProcessNotFound(p) => assert_eq!(p, 42),
        _ => panic!(),
    }
    match SysinternalsError::Io("err".into()) {
        SysinternalsError::Io(s) => assert_eq!(s, "err"),
        _ => panic!(),
    }
    match ProcessScanner::get_process(0) {
        Err(SysinternalsError::ProcessNotFound(_)) => {}
        _ => panic!(),
    }
}

// ─── Round-trip on 50 LCG-seeded inputs ───────────────────────────────────

#[test]
#[allow(clippy::similar_names)]
fn process_info_json_roundtrip_50() {
    let mut s = lcg_seed();
    for _ in 0..50 {
        let pid = u32::try_from(lcg_next(&mut s) % 100_000).unwrap();
        let ppid = u32::try_from(lcg_next(&mut s) % 100_000).unwrap();
        let p = ProcessInfo::new(pid, ppid, format!("proc_{pid}"));
        let j = p.to_json().unwrap();
        let p2: ProcessInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(p2.pid, pid);
        assert_eq!(p2.ppid, ppid);
    }
}

#[test]
fn memory_info_serde_roundtrip_50() {
    let mut s = lcg_seed();
    for _ in 0..50 {
        let m = MemoryInfo::new(
            lcg_next(&mut s), lcg_next(&mut s), lcg_next(&mut s),
            lcg_next(&mut s), lcg_next(&mut s), lcg_next(&mut s),
        );
        let j = serde_json::to_string(&m).unwrap();
        let m2: MemoryInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(m.vss, m2.vss);
        assert_eq!(m.rss, m2.rss);
    }
}

#[test]
fn module_info_contains_50() {
    let mut s = lcg_seed();
    for _ in 0..50 {
        let base = lcg_next(&mut s) & 0x0000_FFFF_FFFF_FFFF;
        let size = (lcg_next(&mut s) & 0xFFFF) + 1;
        let m = ModuleInfo::new(base, size, "x", "/x");
        assert!(m.contains_addr(base));
        assert!(!m.contains_addr(base.saturating_add(size)));
    }
}

// ─── Send/Sync threaded ───────────────────────────────────────────────────

#[test]
fn in_memory_monitor_send_sync_threads() {
    let mut m = InMemorySystemMonitor::new();
    for i in 0..50 {
        m.add_process(make_proc(i, 0));
    }
    let arc: Arc<dyn SystemMonitor> = Arc::new(m);
    let mut handles = vec![];
    for _ in 0..4 {
        let a = arc.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let v = a.list_processes().unwrap();
                assert_eq!(v.len(), 50);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn process_tree_traversal_threaded() {
    let procs: Vec<ProcessInfo> = (1u32..20).map(|i| make_proc(i, if i == 1 { 0 } else { i / 2 })).collect();
    let tree = Arc::new(ProcessTree::from_list(&procs).unwrap());
    let mut handles = vec![];
    for _ in 0..4 {
        let t = tree.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(t.count() >= 19);
                assert!(t.find(1).is_some());
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn shared_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ProcessInfo>();
    assert_send_sync::<ModuleInfo>();
    assert_send_sync::<ThreadInfo>();
    assert_send_sync::<DriverInfo>();
    assert_send_sync::<HandleInfo>();
    assert_send_sync::<NetworkConnection>();
    assert_send_sync::<NetworkEndpoint>();
    assert_send_sync::<RegistryValue>();
    assert_send_sync::<AutorunEntry>();
    assert_send_sync::<SignatureInfo>();
    assert_send_sync::<CertInfo>();
    assert_send_sync::<ProcessTree>();
    assert_send_sync::<SystemSnapshot>();
    assert_send_sync::<SysinternalsError>();
}
