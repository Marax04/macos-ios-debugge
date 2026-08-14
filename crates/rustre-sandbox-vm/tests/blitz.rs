//! Blitz tests for the public lib API of rustre-sandbox-vm.

use rustre_sandbox_vm::*;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn vm_error_display() {
    assert_eq!(VmError::NotFound("x".into()).to_string(), "not found: x");
    assert_eq!(VmError::AlreadyRunning.to_string(), "already running");
    assert_eq!(VmError::NotRunning.to_string(), "not running");
    assert_eq!(VmError::Timeout.to_string(), "timeout");
    assert_eq!(VmError::SnapshotFailed("s".into()).to_string(), "snapshot failed: s");
    assert_eq!(VmError::InvalidState("i".into()).to_string(), "invalid state: i");
    assert_eq!(VmError::CommError("c".into()).to_string(), "communication error: c");
    assert_eq!(VmError::Io("io".into()).to_string(), "io error: io");
    assert_eq!(VmError::Resource("r".into()).to_string(), "resource error: r");
    assert_eq!(VmError::QmpError("q".into()).to_string(), "qmp error: q");
    assert_eq!(VmError::SpawnError("sp".into()).to_string(), "spawn error: sp");
}

#[test]
fn vm_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::Other, "boom");
    let e: VmError = io.into();
    assert!(matches!(e, VmError::Io(_)));
}

#[test]
fn vm_error_from_serde_json() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let e: VmError = bad.unwrap_err().into();
    assert!(matches!(e, VmError::QmpError(_)));
}

#[test]
fn vm_arch_display() {
    assert_eq!(VmArch::X86.to_string(), "x86");
    assert_eq!(VmArch::X64.to_string(), "x64");
    assert_eq!(VmArch::Arm.to_string(), "arm");
    assert_eq!(VmArch::Arm64.to_string(), "arm64");
    assert_eq!(VmArch::Mips.to_string(), "mips");
    assert_eq!(VmArch::Riscv64.to_string(), "riscv64");
}

#[test]
fn vm_arch_eq_and_serde() {
    assert_eq!(VmArch::X64, VmArch::X64);
    assert_ne!(VmArch::X64, VmArch::X86);
    let j = serde_json::to_string(&VmArch::Arm64).unwrap();
    let back: VmArch = serde_json::from_str(&j).unwrap();
    assert_eq!(back, VmArch::Arm64);
}

#[test]
fn vm_os_display() {
    assert_eq!(VmOs::Windows10.to_string(), "windows10");
    assert_eq!(VmOs::Windows11.to_string(), "windows11");
    assert_eq!(VmOs::Windows7.to_string(), "windows7");
    assert_eq!(VmOs::Ubuntu22.to_string(), "ubuntu22");
    assert_eq!(VmOs::Debian12.to_string(), "debian12");
    assert_eq!(VmOs::Kali.to_string(), "kali");
    assert_eq!(VmOs::AndroidApi33.to_string(), "android_api33");
    assert_eq!(VmOs::MacOs13.to_string(), "macos13");
}

#[test]
fn vm_accelerator_display() {
    assert_eq!(VmAccelerator::Kvm.to_string(), "kvm");
    assert_eq!(VmAccelerator::Whpx.to_string(), "whpx");
    assert_eq!(VmAccelerator::Hvf.to_string(), "hvf");
    assert_eq!(VmAccelerator::Tcg.to_string(), "tcg");
}

#[test]
fn disk_format_display() {
    assert_eq!(DiskFormat::Qcow2.to_string(), "qcow2");
    assert_eq!(DiskFormat::Raw.to_string(), "raw");
    assert_eq!(DiskFormat::Vmdk.to_string(), "vmdk");
    assert_eq!(DiskFormat::Vhd.to_string(), "vhd");
    assert_eq!(DiskFormat::Vhdx.to_string(), "vhdx");
}

#[test]
fn disk_image_builder() {
    let d = DiskImage::new("/x.qcow2", DiskFormat::Qcow2, 40);
    assert_eq!(d.path, "/x.qcow2");
    assert_eq!(d.size_gb, 40);
    assert!(!d.is_overlay);
    assert!(d.base_hash.is_none());

    let d2 = d.clone().as_overlay().with_base_hash("abc");
    assert!(d2.is_overlay);
    assert_eq!(d2.base_hash.as_deref(), Some("abc"));
}

#[test]
fn vm_net_type_display() {
    assert_eq!(VmNetType::None.to_string(), "none");
    assert_eq!(VmNetType::Nat.to_string(), "nat");
    assert_eq!(VmNetType::HostOnly.to_string(), "host_only");
    assert_eq!(VmNetType::Bridged.to_string(), "bridged");
}

#[test]
fn vm_config_defaults_and_builders() {
    let c = VmConfig::new("vm1", VmArch::X64, VmOs::Windows10);
    assert_eq!(c.name, "vm1");
    assert_eq!(c.memory_mb, 2048);
    assert_eq!(c.disk_gb, 40);
    assert_eq!(c.vcpus, 2);
    assert!(c.isolated);
    assert_eq!(c.accelerator, VmAccelerator::Tcg);
    assert_eq!(c.net_type, VmNetType::None);
    assert!(c.extra_args.is_empty());
    assert_eq!(c.boot_timeout_secs, 120);

    let c2 = c
        .with_memory(4096)
        .with_disk_size(80)
        .with_vcpus(8)
        .with_isolation(false)
        .with_accelerator(VmAccelerator::Kvm)
        .with_net(VmNetType::Nat)
        .with_extra_arg("-foo")
        .with_disk_image(DiskImage::new("/d.qcow2", DiskFormat::Qcow2, 80));
    assert_eq!(c2.memory_mb, 4096);
    assert_eq!(c2.disk_gb, 80);
    assert_eq!(c2.vcpus, 8);
    assert!(!c2.isolated);
    assert_eq!(c2.accelerator, VmAccelerator::Kvm);
    assert_eq!(c2.net_type, VmNetType::Nat);
    assert_eq!(c2.extra_args, vec!["-foo".to_string()]);
    assert!(c2.disk.is_some());
}

#[test]
fn vm_config_build_qemu_args() {
    let c = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22)
        .with_accelerator(VmAccelerator::Kvm)
        .with_net(VmNetType::Nat)
        .with_disk_image(DiskImage::new("/d.qcow2", DiskFormat::Qcow2, 10))
        .with_extra_arg("-extra");
    let args = c.build_qemu_args();
    assert!(args.iter().any(|a| a.contains("accel=kvm")));
    assert!(args.iter().any(|a| a.contains("-m 2048")));
    assert!(args.iter().any(|a| a.contains("file=/d.qcow2")));
    assert!(args.iter().any(|a| a.contains("nic user")));
    assert!(args.contains(&"-extra".to_string()));

    let none_net = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22).build_qemu_args();
    assert!(none_net.iter().any(|a| a == "-nic none"));

    let host = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22)
        .with_net(VmNetType::HostOnly)
        .build_qemu_args();
    assert!(host.iter().any(|a| a.contains("nic tap")));

    let bridged = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22)
        .with_net(VmNetType::Bridged)
        .build_qemu_args();
    assert!(bridged.iter().any(|a| a.contains("nic bridge")));
}

#[test]
fn vm_state_display() {
    assert_eq!(VmState::Stopped.to_string(), "stopped");
    assert_eq!(VmState::Starting.to_string(), "starting");
    assert_eq!(VmState::Running.to_string(), "running");
    assert_eq!(VmState::Suspended.to_string(), "suspended");
    assert_eq!(VmState::Reverting.to_string(), "reverting");
    assert_eq!(VmState::Saving.to_string(), "saving");
    assert_eq!(VmState::Error("boom".into()).to_string(), "error: boom");
}

#[test]
fn snapshot_info_builder() {
    let s = SnapshotInfo::new("id1", "name", 100, 200)
        .with_parent("p")
        .with_description("desc");
    assert_eq!(s.id, "id1");
    assert_eq!(s.name, "name");
    assert_eq!(s.created_at, 100);
    assert_eq!(s.size_bytes, 200);
    assert_eq!(s.parent.as_deref(), Some("p"));
    assert_eq!(s.description, "desc");
}

#[test]
fn memory_region_methods() {
    let r = MemoryRegion {
        start: 0x1000,
        end: 0x2000,
        label: "x".into(),
        readable: true,
        writable: true,
        executable: true,
        mapped_file: None,
    };
    assert_eq!(r.size(), 0x1000);
    assert!(r.is_rwx());
    assert!(r.contains(0x1000));
    assert!(r.contains(0x1fff));
    assert!(!r.contains(0x2000));
    assert!(!r.contains(0x0fff));

    let r2 = MemoryRegion {
        start: 0x10,
        end: 0x5,
        ..r
    };
    assert_eq!(r2.size(), 0); // saturating sub
}

#[test]
fn memory_map_basic() {
    let mut m = MemoryMap::new(42);
    assert_eq!(m.pid, 42);
    assert!(m.regions.is_empty());
    assert_eq!(m.total_size(), 0);
    assert!(m.find_region(0).is_none());
    assert!(m.executable_regions().is_empty());

    m.add(MemoryRegion {
        start: 0,
        end: 100,
        label: "a".into(),
        readable: true,
        writable: true,
        executable: true,
        mapped_file: None,
    });
    assert_eq!(m.regions.len(), 1);
    assert_eq!(m.total_size(), 100);
    assert!(m.find_region(50).is_some());
}

#[test]
fn memory_map_mock_filters() {
    let m = MemoryMap::mock(123);
    assert_eq!(m.pid, 123);
    assert_eq!(m.regions.len(), 4);
    assert_eq!(m.executable_regions().len(), 3);
    assert_eq!(m.rwx_regions().len(), 1);
    assert_eq!(m.rwx_regions()[0].label, "[injected]");
    assert_eq!(m.anonymous_writable().len(), 2);
    assert!(m.total_size() > 0);
}

#[test]
fn guest_command_builder() {
    let c = GuestCommand::new("calc.exe")
        .with_arg("/a")
        .with_arg("/b")
        .with_env("K", "V")
        .with_cwd("C:\\")
        .with_timeout(60);
    assert_eq!(c.executable, "calc.exe");
    assert_eq!(c.args, vec!["/a", "/b"]);
    assert_eq!(c.env.get("K").unwrap(), "V");
    assert_eq!(c.cwd, "C:\\");
    assert_eq!(c.timeout_secs, 60);
}

#[test]
fn guest_command_result_is_ok() {
    let r = GuestCommandResult {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        duration_ms: 0,
        timed_out: false,
    };
    assert!(r.is_ok());
    let r2 = GuestCommandResult { exit_code: 1, ..r.clone() };
    assert!(!r2.is_ok());
    let r3 = GuestCommandResult { timed_out: true, ..r };
    assert!(!r3.is_ok());
}

#[test]
fn guest_agent_lifecycle_and_exec() {
    let mut a = GuestAgent::new("vm-1");
    assert_eq!(a.vm_id, "vm-1");
    assert!(!a.connected);
    assert_eq!(a.commands_sent(), 0);

    let cmd = GuestCommand::new("ls").with_arg("-l");
    assert!(matches!(a.exec(&cmd), Err(VmError::CommError(_))));
    assert!(matches!(a.upload("a", "b"), Err(VmError::CommError(_))));
    assert!(matches!(a.download("r", "l"), Err(VmError::CommError(_))));
    assert!(matches!(a.read_memory_map(1), Err(VmError::CommError(_))));

    a.connect();
    assert!(a.connected);
    assert_eq!(a.agent_pid, Some(1000));

    let r = a.exec(&cmd).unwrap();
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("ls"));
    assert_eq!(a.commands_sent(), 1);

    a.upload("x", "y").unwrap();
    let bytes = a.download("file.txt", "_").unwrap();
    assert_eq!(bytes, b"contents of file.txt");

    let mm = a.read_memory_map(7).unwrap();
    assert_eq!(mm.pid, 7);

    a.disconnect();
    assert!(!a.connected);
    assert!(a.agent_pid.is_none());
}

#[test]
fn network_mode_nic_arg() {
    assert_eq!(NetworkMode::None.nic_arg(), "none");
    assert_eq!(NetworkMode::User.nic_arg(), "user,model=virtio-net-pci");
    assert_eq!(
        NetworkMode::Tap { iface: "tap0".into() }.nic_arg(),
        "tap,ifname=tap0,model=virtio-net-pci"
    );
    assert_eq!(
        NetworkMode::Bridge { br: "br0".into() }.nic_arg(),
        "bridge,br=br0,model=virtio-net-pci"
    );
}

#[test]
fn network_mode_eq() {
    assert_eq!(NetworkMode::None, NetworkMode::None);
    assert_ne!(NetworkMode::None, NetworkMode::User);
}

#[test]
fn qemu_process_builder_defaults_and_args() {
    let b = QemuProcessBuilder::new("/img.qcow2");
    assert_eq!(b.memory_mb, 2048);
    assert_eq!(b.cpus, 2);
    assert_eq!(b.accelerator, "tcg");
    assert_eq!(b.display, "none");
    assert!(b.snapshot.is_none());
    assert_eq!(b.net_mode, NetworkMode::None);

    let args = b.build_args();
    assert!(args.contains(&"-m".to_string()));
    assert!(args.contains(&"2048".to_string()));
    assert!(args.contains(&"-smp".to_string()));
    assert!(args.contains(&"2".to_string()));
    assert!(args.iter().any(|a| a.contains("file=/img.qcow2")));
    assert!(args.iter().any(|a| a.contains("q35,accel=tcg")));
    assert!(args.contains(&"-display".to_string()));
}

#[test]
fn qemu_process_builder_full_chain() {
    let b = QemuProcessBuilder::new("/i.qcow2")
        .memory_mb(8192)
        .cpus(8)
        .snapshot("snap1")
        .net_mode(NetworkMode::User)
        .accelerator("kvm")
        .display("sdl")
        .extra_arg("-foo");
    assert_eq!(b.memory_mb, 8192);
    assert_eq!(b.cpus, 8);
    assert_eq!(b.snapshot.as_deref(), Some("snap1"));
    assert_eq!(b.accelerator, "kvm");
    assert_eq!(b.display, "sdl");

    let args = b.build_args();
    assert!(args.contains(&"8192".to_string()));
    assert!(args.contains(&"8".to_string()));
    assert!(args.iter().any(|a| a == "-loadvm"));
    assert!(args.iter().any(|a| a == "snap1"));
    assert!(args.iter().any(|a| a.contains("accel=kvm")));
    assert!(args.iter().any(|a| a == "sdl"));
    assert!(args.contains(&"-foo".to_string()));
}

#[test]
fn qemu_process_builder_qmp_socket_override() {
    let b = QemuProcessBuilder::new("/i.qcow2")
        .qmp_socket_path(std::path::PathBuf::from("/tmp/qmp.sock"));
    let args = b.build_args();
    // Linux/Mac branch will emit unix:; Windows might too if path doesn't start tcp:.
    let qmp = args
        .iter()
        .find(|a| a.contains("/tmp/qmp.sock") || a.contains("qmp.sock"))
        .expect("qmp arg present");
    assert!(qmp.contains("server,nowait"));
}

#[test]
fn vm_instance_lifecycle_and_snapshots() {
    let cfg = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22);
    let mut vm = VmInstance::new("id1", cfg);
    assert_eq!(vm.id, "id1");
    assert!(vm.is_stopped());
    assert!(!vm.is_running());
    assert_eq!(vm.snapshot_count(), 0);
    assert!(vm.latest_snapshot().is_none());
    assert!(vm.find_snapshot("x").is_none());

    vm.add_tag("malware");
    assert_eq!(vm.tags, vec!["malware".to_string()]);

    let s1 = vm.take_snapshot("first").unwrap();
    let s2 = vm.take_snapshot("second").unwrap();
    assert_eq!(s1, "snap-0000");
    assert_eq!(s2, "snap-0001");
    assert_eq!(vm.snapshot_count(), 2);
    assert!(vm.find_snapshot(&s1).is_some());
    // s2's parent should be s1
    assert_eq!(vm.find_snapshot(&s2).unwrap().parent.as_deref(), Some(s1.as_str()));

    // qemu_args delegates to config
    assert_eq!(vm.qemu_args(), vm.config.build_qemu_args());
}

#[test]
fn vm_instance_revert_and_delete() {
    let cfg = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22);
    let mut vm = VmInstance::new("id", cfg);
    let s1 = vm.take_snapshot("a").unwrap();
    let _s2 = vm.take_snapshot("b").unwrap();
    let _s3 = vm.take_snapshot("c").unwrap();
    assert_eq!(vm.snapshot_count(), 3);

    vm.revert(&s1).unwrap();
    assert_eq!(vm.snapshot_count(), 1);
    assert_eq!(vm.state, VmState::Stopped);

    assert!(matches!(vm.revert("nope"), Err(VmError::NotFound(_))));

    let _s4 = vm.take_snapshot("d").unwrap();
    assert_eq!(vm.snapshot_count(), 2);
    vm.delete_snapshot(&s1).unwrap();
    assert_eq!(vm.snapshot_count(), 1);

    assert!(matches!(vm.delete_snapshot("nope"), Err(VmError::NotFound(_))));
}

#[test]
fn vm_instance_snapshot_in_error_state_fails() {
    let cfg = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22);
    let mut vm = VmInstance::new("id", cfg);
    vm.state = VmState::Error("dead".into());
    assert!(matches!(vm.take_snapshot("x"), Err(VmError::SnapshotFailed(_))));
}

#[test]
fn vm_instance_latest_snapshot() {
    let cfg = VmConfig::new("v", VmArch::X64, VmOs::Ubuntu22);
    let mut vm = VmInstance::new("id", cfg);
    vm.snapshots.push(SnapshotInfo::new("a", "a", 10, 0));
    vm.snapshots.push(SnapshotInfo::new("b", "b", 50, 0));
    vm.snapshots.push(SnapshotInfo::new("c", "c", 30, 0));
    assert_eq!(vm.latest_snapshot().unwrap().id, "b");
}

#[test]
fn vm_pool_basic_operations() {
    let pool = VmPool::new();
    assert!(pool.find("x").is_none());
    assert!(pool.available().is_empty());
    assert!(pool.running().is_empty());

    let vm1 = VmInstance::new("a", VmConfig::new("a", VmArch::X64, VmOs::Ubuntu22));
    let vm2 = VmInstance::new("b", VmConfig::new("b", VmArch::X64, VmOs::Ubuntu22));
    pool.add(vm1);
    pool.add(vm2);

    assert!(pool.find("a").is_some());
    assert!(pool.find("b").is_some());
    assert!(pool.find("c").is_none());
    assert_eq!(pool.available().len(), 2);
    assert_eq!(pool.running().len(), 0);

    pool.update_state("a", VmState::Running).unwrap();
    assert_eq!(pool.available().len(), 1);
    assert_eq!(pool.running().len(), 1);

    assert!(matches!(
        pool.update_state("missing", VmState::Running),
        Err(VmError::NotFound(_))
    ));

    let removed = pool.remove("a").unwrap();
    assert_eq!(removed.id, "a");
    assert!(pool.find("a").is_none());

    assert!(matches!(pool.remove("nope"), Err(VmError::NotFound(_))));
}

#[test]
fn vm_pool_send_sync() {
    assert_send_sync::<VmPool>();
    assert_send_sync::<VmInstance>();
    assert_send_sync::<VmConfig>();
    assert_send_sync::<VmError>();
    assert_send_sync::<MemoryMap>();
    assert_send_sync::<GuestAgent>();
    assert_send_sync::<NetworkMode>();
}

#[test]
fn vm_config_serde_roundtrip() {
    let c = VmConfig::new("rt", VmArch::Arm64, VmOs::Kali)
        .with_memory(512)
        .with_net(VmNetType::Bridged);
    let j = serde_json::to_string(&c).unwrap();
    let back: VmConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, c.name);
    assert_eq!(back.memory_mb, 512);
    assert_eq!(back.net_type, VmNetType::Bridged);
    assert_eq!(back.arch, VmArch::Arm64);
}

#[test]
fn snapshot_info_serde_roundtrip() {
    let s = SnapshotInfo::new("id", "n", 1, 2).with_parent("p").with_description("d");
    let j = serde_json::to_string(&s).unwrap();
    let back: SnapshotInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id, "id");
    assert_eq!(back.parent.as_deref(), Some("p"));
    assert_eq!(back.description, "d");
}
