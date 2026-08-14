//! Blitz tests for rustre-sandbox public API in lib.rs.

use rustre_sandbox::{
    ArtifactCollector, BehaviorFlag, BehaviorRecord, FileOp, FileTrace, FilesystemSnapshot,
    MockSandbox, NetworkProto, NetworkTrace, ProcessNode, ProcessTree, RegistryOp, RegistryTrace,
    ResourceLimits, Sandbox, SandboxArch, SandboxConfig, SandboxError, SandboxOs, SandboxPermissions,
    SandboxPolicy, SandboxResult, SandboxSession, SandboxStatus, SyscallTrace,
};

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn resource_limits_generous_vs_tight() {
    let g = ResourceLimits::generous();
    let t = ResourceLimits::tight();
    assert!(g.max_memory_mb > t.max_memory_mb);
    assert!(g.max_open_files > t.max_open_files);
    assert!(g.cpu_percent >= t.cpu_percent);
}

#[test]
fn resource_limits_default_is_generous() {
    let d = ResourceLimits::default();
    let g = ResourceLimits::generous();
    assert_eq!(d.max_memory_mb, g.max_memory_mb);
}

#[test]
fn resource_limits_memory_and_disk_exceeded() {
    let l = ResourceLimits::tight();
    assert!(l.memory_exceeded(l.max_memory_mb + 1));
    assert!(!l.memory_exceeded(l.max_memory_mb));
    assert!(l.disk_exceeded(l.max_disk_write_mb + 1));
    assert!(!l.disk_exceeded(0));
}

#[test]
fn sandbox_policy_permissive_allows_all() {
    let p = SandboxPolicy::permissive();
    assert!(p.perms.contains(SandboxPermissions::ALLOW_NETWORK));
    assert!(p.perms.contains(SandboxPermissions::ALLOW_FS));
    assert!(p.is_network_allowed("anything.example"));
    assert!(p.is_write_allowed("/anywhere"));
}

#[test]
fn sandbox_policy_restrictive_denies_all() {
    let p = SandboxPolicy::restrictive();
    assert!(!p.perms.contains(SandboxPermissions::ALLOW_NETWORK));
    assert!(!p.is_network_allowed("anything"));
    assert!(!p.is_write_allowed("/tmp/x"));
}

#[test]
fn sandbox_policy_balanced_writes_only_to_temp() {
    let p = SandboxPolicy::balanced();
    assert!(p.is_write_allowed("/tmp/file"));
    assert!(p.is_write_allowed("C:\\Windows\\Temp\\foo.exe"));
    assert!(!p.is_write_allowed("/etc/passwd"));
}

#[test]
fn sandbox_policy_network_allowlist() {
    let mut p = SandboxPolicy::permissive();
    p.network_allowlist = vec!["example.com".into()];
    assert!(p.is_network_allowed("api.example.com")); // note: contains-check, not subdomain
    assert!(!p.is_network_allowed("evil.org"));
}

#[test]
fn sandbox_policy_validate_ok() {
    assert!(SandboxPolicy::permissive().validate().is_ok());
    assert!(SandboxPolicy::restrictive().validate().is_ok());
    assert!(SandboxPolicy::balanced().validate().is_ok());
}

#[test]
fn sandbox_policy_validate_zero_timeout() {
    let mut p = SandboxPolicy::permissive();
    p.timeout_secs = 0;
    assert!(matches!(p.validate(), Err(SandboxError::InvalidConfig(_))));
}

#[test]
fn sandbox_policy_validate_zero_memory() {
    let mut p = SandboxPolicy::permissive();
    p.max_memory_mb = 0;
    assert!(matches!(p.validate(), Err(SandboxError::InvalidConfig(_))));
}

#[test]
fn sandbox_policy_validate_bad_cpu() {
    let mut p = SandboxPolicy::permissive();
    p.limits.cpu_percent = 0;
    assert!(p.validate().is_err());
    p.limits.cpu_percent = 101;
    assert!(p.validate().is_err());
}

#[test]
fn behavior_flag_describe_and_score() {
    let f = BehaviorFlag::INJECTION | BehaviorFlag::NETWORK;
    let names = f.describe();
    assert!(names.contains(&"injection"));
    assert!(names.contains(&"network"));
    assert_eq!(f.threat_score(), 25 + 5);
}

#[test]
fn behavior_flag_threat_score_capped_at_100() {
    let f = BehaviorFlag::all();
    assert_eq!(f.threat_score(), 100);
}

#[test]
fn behavior_flag_empty_score_is_zero() {
    assert_eq!(BehaviorFlag::empty().threat_score(), 0);
    assert!(BehaviorFlag::empty().describe().is_empty());
}

#[test]
fn sandbox_status_display() {
    assert_eq!(SandboxStatus::NotStarted.to_string(), "not_started");
    assert_eq!(SandboxStatus::Running.to_string(), "running");
    assert_eq!(SandboxStatus::Finished.to_string(), "finished");
    assert_eq!(SandboxStatus::Timeout.to_string(), "timeout");
    assert!(SandboxStatus::Crashed("x".into()).to_string().contains("crashed"));
}

#[test]
fn syscall_trace_builders() {
    let t = SyscallTrace::new(1, "Foo", 100, 50)
        .with_arg("a")
        .with_arg("b")
        .with_ret(42)
        .flagged();
    assert_eq!(t.number, 1);
    assert_eq!(t.name, "Foo");
    assert_eq!(t.args.len(), 2);
    assert_eq!(t.ret, Some(42));
    assert!(t.flagged);
}

#[test]
fn network_proto_display() {
    assert_eq!(NetworkProto::Tcp.to_string(), "tcp");
    assert_eq!(NetworkProto::Udp.to_string(), "udp");
    assert_eq!(NetworkProto::Other("foo".into()).to_string(), "foo");
}

#[test]
fn network_trace_is_external() {
    let mk = |ip: &str| NetworkTrace {
        proto: NetworkProto::Tcp,
        local_addr: "0".into(),
        remote_addr: ip.into(),
        remote_port: 80,
        bytes_sent: 0,
        bytes_recv: 0,
        ts_ms: 0,
        pid: 0,
        dns_query: None,
    };
    assert!(!mk("127.0.0.1").is_external());
    assert!(!mk("192.168.1.1").is_external());
    assert!(!mk("10.0.0.1").is_external());
    assert!(!mk("172.16.0.1").is_external());
    assert!(mk("172.32.0.1").is_external());
    assert!(mk("8.8.8.8").is_external());
}

#[test]
fn network_trace_c2_port() {
    let mk = |port: u16| NetworkTrace {
        proto: NetworkProto::Tcp,
        local_addr: "0".into(),
        remote_addr: "1.1.1.1".into(),
        remote_port: port,
        bytes_sent: 0,
        bytes_recv: 0,
        ts_ms: 0,
        pid: 0,
        dns_query: None,
    };
    assert!(mk(443).is_c2_port());
    assert!(mk(4444).is_c2_port());
    assert!(mk(31337).is_c2_port());
    assert!(!mk(22).is_c2_port());
}

#[test]
fn file_op_display() {
    assert_eq!(FileOp::Create.to_string(), "create");
    assert_eq!(FileOp::SetAttributes.to_string(), "set_attributes");
}

#[test]
fn file_trace_dropper_op() {
    let mk = |op, p: &str| FileTrace {
        op,
        path: p.into(),
        bytes: 0,
        ts_ms: 0,
        pid: 0,
        success: true,
    };
    assert!(mk(FileOp::Create, "x.exe").is_dropper_op());
    assert!(mk(FileOp::Write, "y.DLL").is_dropper_op());
    assert!(mk(FileOp::Write, "y.ps1").is_dropper_op());
    assert!(!mk(FileOp::Read, "x.exe").is_dropper_op());
    assert!(!mk(FileOp::Create, "x.txt").is_dropper_op());
}

#[test]
fn registry_op_display() {
    assert_eq!(RegistryOp::CreateKey.to_string(), "create_key");
    assert_eq!(RegistryOp::DeleteValue.to_string(), "delete_value");
}

#[test]
fn registry_trace_persistence_op() {
    let mk = |op, k: &str| RegistryTrace {
        op,
        key: k.into(),
        value_name: "v".into(),
        data: None,
        ts_ms: 0,
        pid: 0,
    };
    assert!(mk(RegistryOp::SetValue, r"HKCU\Software\Run\foo").is_persistence_op());
    assert!(mk(RegistryOp::CreateKey, r"HKLM\Services\bar").is_persistence_op());
    assert!(!mk(RegistryOp::SetValue, r"HKCU\Software\Other").is_persistence_op());
    assert!(!mk(RegistryOp::QueryValue, r"HKCU\Run\x").is_persistence_op());
}

#[test]
fn process_node_running() {
    let mut n = ProcessNode::new(1, 0, "a.exe", "a.exe", 0);
    assert!(n.is_running());
    n.exit_code = Some(0);
    assert!(!n.is_running());
}

#[test]
fn process_tree_insert_and_find() {
    let mut t = ProcessTree::new(1);
    t.insert(ProcessNode::new(1, 0, "root.exe", "", 0));
    t.insert(ProcessNode::new(2, 1, "child.exe", "", 1));
    t.insert(ProcessNode::new(3, 1, "child2.exe", "", 2));
    assert_eq!(t.process_count(), 3);
    assert!(t.find(2).is_some());
    assert!(t.find(99).is_none());
    let root = t.find(1).unwrap();
    assert_eq!(root.children.len(), 2);
}

#[test]
fn process_tree_leaves_and_depth() {
    let mut t = ProcessTree::new(1);
    t.insert(ProcessNode::new(1, 0, "r", "", 0));
    t.insert(ProcessNode::new(2, 1, "c", "", 0));
    t.insert(ProcessNode::new(3, 2, "gc", "", 0));
    assert_eq!(t.max_depth(), 2);
    let leaves = t.leaves();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].pid, 3);
}

#[test]
fn process_tree_empty_depth() {
    let t = ProcessTree::new(99);
    assert_eq!(t.max_depth(), 0);
    assert_eq!(t.process_count(), 0);
}

#[test]
fn behavior_record_records_and_flags() {
    let mut r = BehaviorRecord::new(1);
    r.record_syscall(SyscallTrace::new(1, "VirtualAllocEx", 1, 0));
    assert!(r.flags.contains(BehaviorFlag::INJECTION));
    r.record_syscall(SyscallTrace::new(2, "CryptEncrypt", 1, 0));
    assert!(r.flags.contains(BehaviorFlag::CRYPTO));
    r.record_syscall(SyscallTrace::new(3, "IsDebuggerPresent", 1, 0));
    assert!(r.flags.contains(BehaviorFlag::ANTIANALYSIS));
}

#[test]
fn behavior_record_network_c2() {
    let mut r = BehaviorRecord::new(1);
    r.record_network(NetworkTrace {
        proto: NetworkProto::Https,
        local_addr: "0".into(),
        remote_addr: "8.8.8.8".into(),
        remote_port: 443,
        bytes_sent: 0,
        bytes_recv: 0,
        ts_ms: 0,
        pid: 0,
        dns_query: None,
    });
    assert!(r.flags.contains(BehaviorFlag::NETWORK));
    assert!(r.flags.contains(BehaviorFlag::C2));
    assert_eq!(r.external_conn_count(), 1);
}

#[test]
fn behavior_record_file_and_registry() {
    let mut r = BehaviorRecord::new(1);
    r.record_file(FileTrace {
        op: FileOp::Create,
        path: "p.exe".into(),
        bytes: 0,
        ts_ms: 0,
        pid: 0,
        success: true,
    });
    assert!(r.flags.contains(BehaviorFlag::FILESYSTEM));
    assert!(r.flags.contains(BehaviorFlag::DROPPER));
    assert_eq!(r.dropped_exe_count(), 1);

    r.record_registry(RegistryTrace {
        op: RegistryOp::SetValue,
        key: r"HKCU\Software\Run\x".into(),
        value_name: "v".into(),
        data: None,
        ts_ms: 0,
        pid: 0,
    });
    assert!(r.flags.contains(BehaviorFlag::REGISTRY));
    assert!(r.flags.contains(BehaviorFlag::PERSISTENCE));
    assert_eq!(r.persistence_op_count(), 1);
}

#[test]
fn behavior_record_flagged_syscall_count_and_log() {
    let mut r = BehaviorRecord::new(1);
    r.record_syscall(SyscallTrace::new(1, "X", 1, 0).flagged());
    r.record_syscall(SyscallTrace::new(2, "Y", 1, 0));
    assert_eq!(r.flagged_syscall_count(), 1);
    r.log("hello");
    assert!(r.log.iter().any(|l| l == "hello"));
}

#[test]
fn behavior_record_mock_has_data() {
    let r = BehaviorRecord::mock();
    assert!(!r.syscalls.is_empty());
    assert!(!r.network.is_empty());
    assert!(!r.files.is_empty());
    assert!(!r.registry.is_empty());
    assert!(r.flags.contains(BehaviorFlag::INJECTION));
}

#[test]
fn sandbox_arch_and_os_display() {
    assert_eq!(SandboxArch::X64.to_string(), "x64");
    assert_eq!(SandboxArch::Arm64.to_string(), "arm64");
    assert_eq!(SandboxOs::Windows10.to_string(), "windows10");
    assert_eq!(SandboxOs::AndroidApi33.to_string(), "android_api33");
}

#[test]
fn sandbox_config_windows_default_valid() {
    let c = SandboxConfig::windows_default("test");
    assert_eq!(c.name, "test");
    assert_eq!(c.arch, SandboxArch::X64);
    assert_eq!(c.os, SandboxOs::Windows10);
    assert!(c.validate().is_ok());
}

#[test]
fn artifact_collector_add_and_find() {
    let mut a = ArtifactCollector::new();
    assert_eq!(a.total_bytes(), 0);
    assert_eq!(a.binary_count(), 0);
    a.add_binary("a.exe", vec![1, 2, 3]);
    a.add_binary("b.exe", vec![4, 5]);
    a.add_memory_dump("dump", vec![0; 10]);
    a.set_pcap(vec![0; 4]);
    a.add_screenshot(vec![0; 2]);
    a.log("msg");
    assert_eq!(a.binary_count(), 2);
    assert_eq!(a.total_bytes(), 3 + 2 + 10 + 4 + 2);
    assert_eq!(a.find_binary("a.exe"), Some(&[1u8, 2, 3][..]));
    assert_eq!(a.find_binary("missing"), None);
    assert_eq!(a.logs.len(), 1);
}

#[test]
fn artifact_collector_default() {
    let a = ArtifactCollector::default();
    assert_eq!(a.total_bytes(), 0);
}

#[test]
fn filesystem_snapshot_diff() {
    let mut pre = FilesystemSnapshot::new("pre", 0);
    pre.add("a", "h1");
    pre.add("b", "h2");
    pre.add("c", "h3");
    let mut post = FilesystemSnapshot::new("post", 1);
    post.add("a", "h1"); // unchanged
    post.add("b", "h2-modified"); // modified
    post.add("d", "h4"); // added
    // c removed
    let (added, removed, modified) = pre.diff(&post);
    assert_eq!(added, vec!["d".to_string()]);
    assert_eq!(removed, vec!["c".to_string()]);
    assert_eq!(modified, vec!["b".to_string()]);
    assert_eq!(post.file_count(), 3);
}

#[test]
fn sandbox_result_clean() {
    let r = SandboxResult::clean();
    assert_eq!(r.status, SandboxStatus::Finished);
    assert_eq!(r.threat_score, 0);
    assert!(!r.is_malicious());
    assert!(!r.timed_out());
    assert!(r.fs_diff().is_none());
}

#[test]
fn sandbox_result_is_malicious() {
    let mut r = SandboxResult::clean();
    r.behaviors = BehaviorFlag::INJECTION;
    assert!(r.is_malicious());
    r.behaviors = BehaviorFlag::NETWORK | BehaviorFlag::PERSISTENCE;
    assert!(r.is_malicious());
    r.behaviors = BehaviorFlag::NETWORK;
    assert!(!r.is_malicious());
}

#[test]
fn sandbox_result_timed_out_and_log() {
    let mut r = SandboxResult::clean();
    r.status = SandboxStatus::Timeout;
    assert!(r.timed_out());
    r.add_log("entry");
    assert_eq!(r.log.len(), 1);
}

#[test]
fn sandbox_result_compute_threat_score() {
    let mut r = SandboxResult::clean();
    r.behaviors = BehaviorFlag::INJECTION;
    r.compute_threat_score();
    assert_eq!(r.threat_score, 25);
}

#[test]
fn sandbox_result_to_json_round_trips() {
    let r = SandboxResult::clean();
    let s = r.to_json().expect("json ok");
    assert!(s.contains("\"status\""));
    let _back: SandboxResult = serde_json::from_str(&s).expect("deserialize");
}

#[test]
fn sandbox_result_mock_has_high_score() {
    let r = SandboxResult::mock();
    assert!(r.is_malicious());
    assert!(r.threat_score > 0);
    assert!(r.fs_diff().is_some());
    let (added, _removed, _modified) = r.fs_diff().unwrap();
    assert!(!added.is_empty());
}

#[test]
fn sandbox_session_lifecycle() {
    let c = SandboxConfig::windows_default("s");
    let s = SandboxSession::new("id-1", c);
    assert_eq!(s.id, "id-1");
    assert_eq!(s.current_status(), SandboxStatus::NotStarted);
    s.start();
    assert_eq!(s.current_status(), SandboxStatus::Running);
    s.finish(Some(0));
    assert_eq!(s.current_status(), SandboxStatus::Finished);
    s.timeout();
    assert_eq!(s.current_status(), SandboxStatus::Timeout);
}

#[test]
fn sandbox_session_tick_and_timeout() {
    let mut c = SandboxConfig::windows_default("s");
    c.policy.timeout_secs = 1;
    let s = SandboxSession::new("id", c);
    assert_eq!(s.elapsed_ms(), 0);
    assert!(!s.is_timed_out());
    s.tick_ms(500);
    assert!(!s.is_timed_out());
    s.tick_ms(600);
    assert_eq!(s.elapsed_ms(), 1100);
    assert!(s.is_timed_out());
}

#[test]
fn sandbox_session_collect_result() {
    let c = SandboxConfig::windows_default("s");
    let s = SandboxSession::new("id", c);
    s.start();
    s.finish(Some(0));
    let r = s.collect_result();
    assert_eq!(r.status, SandboxStatus::Finished);
}

#[test]
fn mock_sandbox_clean_and_malicious() {
    let clean = MockSandbox::clean("c");
    assert_eq!(<MockSandbox as Sandbox>::name(&clean), "c");
    let policy = SandboxPolicy::permissive();
    let r = <MockSandbox as Sandbox>::run(&clean, "x", &policy).unwrap();
    assert!(!r.is_malicious());

    let mal = MockSandbox::malicious("m");
    let r2 = <MockSandbox as Sandbox>::run(&mal, "x", &policy).unwrap();
    assert!(r2.is_malicious());
}

#[test]
fn mock_sandbox_supports_arch() {
    let s = MockSandbox::clean("c");
    assert!(<MockSandbox as Sandbox>::supports_arch(&s, "x64"));
    assert!(<MockSandbox as Sandbox>::supports_arch(&s, "arm64"));
    assert!(!<MockSandbox as Sandbox>::supports_arch(&s, "sparc"));
}

#[test]
fn sandbox_error_display() {
    let e = SandboxError::Timeout(30);
    assert!(e.to_string().contains("30"));
    let e2 = SandboxError::SpawnFailed("nope".into());
    assert!(e2.to_string().contains("nope"));
}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<SandboxResult>();
    assert_send_sync::<SandboxConfig>();
    assert_send_sync::<SandboxPolicy>();
    assert_send_sync::<BehaviorRecord>();
    assert_send_sync::<ArtifactCollector>();
    assert_send_sync::<SandboxSession>();
    assert_send_sync::<MockSandbox>();
}
