// Exhaustive black-box tests for rustre-syscalls-windows.
// Goal: surface bugs in pure-logic public APIs.

use rustre_syscalls_windows::*;
use std::collections::HashMap;

// ─── WinArch / WinVersion / ParamDirection Display ───────────────────────────

#[test]
fn arch_display_all() {
    assert_eq!(WinArch::X86.to_string(), "x86");
    assert_eq!(WinArch::X64.to_string(), "x64");
    assert_eq!(WinArch::Arm64.to_string(), "arm64");
}

#[test]
fn version_display_all() {
    assert_eq!(WinVersion::WindowsXP.to_string(), "Windows XP");
    assert_eq!(WinVersion::WindowsVista.to_string(), "Windows Vista");
    assert_eq!(WinVersion::Windows7.to_string(), "Windows 7");
    assert_eq!(WinVersion::Windows8.to_string(), "Windows 8");
    assert_eq!(WinVersion::Windows81.to_string(), "Windows 8.1");
    assert_eq!(WinVersion::Windows10.to_string(), "Windows 10");
    assert_eq!(WinVersion::Windows11.to_string(), "Windows 11");
}

#[test]
fn param_direction_display() {
    assert_eq!(ParamDirection::In.to_string(), "In");
    assert_eq!(ParamDirection::Out.to_string(), "Out");
    assert_eq!(ParamDirection::InOut.to_string(), "InOut");
    assert_eq!(ParamDirection::OptIn.to_string(), "In_opt");
    assert_eq!(ParamDirection::OptOut.to_string(), "Out_opt");
}

// ─── WinSyscallParam ─────────────────────────────────────────────────────────

#[test]
fn param_to_c_in() {
    let p = WinSyscallParam::new("Handle", "HANDLE", ParamDirection::In);
    // formatted via {:?} on direction
    assert_eq!(p.to_c(), "_In_ HANDLE Handle");
}

#[test]
fn param_to_c_optin() {
    let p = WinSyscallParam::new("buf", "PVOID", ParamDirection::OptIn);
    assert_eq!(p.to_c(), "_OptIn_ PVOID buf");
}

// ─── WinNtSyscall ────────────────────────────────────────────────────────────

#[test]
fn syscall_new_zw_alias_from_nt() {
    let s = WinNtSyscall::new(0, "NtClose", vec![], "ntdll.dll");
    assert_eq!(s.zw_name, "ZwClose");
}

#[test]
fn syscall_new_no_nt_prefix_keeps_name() {
    let s = WinNtSyscall::new(0, "RtlAllocateHeap", vec![], "ntdll.dll");
    assert_eq!(s.zw_name, "RtlAllocateHeap");
}

#[test]
fn syscall_arity_matches_params_len() {
    let params = vec![
        WinSyscallParam::new("a", "DWORD", ParamDirection::In),
        WinSyscallParam::new("b", "PVOID", ParamDirection::Out),
    ];
    let s = WinNtSyscall::new(0x10, "NtFoo", params, "ntdll.dll");
    assert_eq!(s.arity(), 2);
}

#[test]
fn syscall_has_output_params_true_for_out() {
    let p = vec![WinSyscallParam::new("o", "PVOID", ParamDirection::Out)];
    assert!(WinNtSyscall::new(0, "NtX", p, "n").has_output_params());
}

#[test]
fn syscall_has_output_params_true_for_inout() {
    let p = vec![WinSyscallParam::new("o", "PVOID", ParamDirection::InOut)];
    assert!(WinNtSyscall::new(0, "NtX", p, "n").has_output_params());
}

#[test]
fn syscall_has_output_params_true_for_optout() {
    let p = vec![WinSyscallParam::new("o", "PVOID", ParamDirection::OptOut)];
    assert!(WinNtSyscall::new(0, "NtX", p, "n").has_output_params());
}

#[test]
fn syscall_has_output_params_false_when_only_in() {
    let p = vec![
        WinSyscallParam::new("a", "DWORD", ParamDirection::In),
        WinSyscallParam::new("b", "DWORD", ParamDirection::OptIn),
    ];
    assert!(!WinNtSyscall::new(0, "NtX", p, "n").has_output_params());
}

#[test]
fn syscall_prototype_format() {
    let p = vec![WinSyscallParam::new("h", "HANDLE", ParamDirection::In)];
    let s = WinNtSyscall::new(0, "NtClose", p, "ntdll.dll");
    assert_eq!(s.prototype(), "NTSTATUS NtClose(_In_ HANDLE h);");
}

// ─── NtdllExport ─────────────────────────────────────────────────────────────

#[test]
fn ntdll_export_with_ordinal() {
    let e = NtdllExport::new("NtClose", 0x1000, Some(0xF)).with_ordinal(42);
    assert_eq!(e.name, "NtClose");
    assert_eq!(e.rva, 0x1000);
    assert_eq!(e.ssn, Some(0xF));
    assert_eq!(e.ordinal, Some(42));
}

// ─── ObjectAttributes ────────────────────────────────────────────────────────

#[test]
fn object_attributes_defaults() {
    let oa = ObjectAttributes::new("\\??\\C:\\file");
    assert_eq!(oa.length, 48);
    assert_eq!(oa.object_name, "\\??\\C:\\file");
    assert!(!oa.is_inherit());
    assert!(!oa.is_open_if());
    assert!(!oa.is_kernel_handle());
}

#[test]
fn object_attributes_flags() {
    let mut oa = ObjectAttributes::new("x");
    oa.attributes = 0x2 | 0x80 | 0x200;
    assert!(oa.is_inherit());
    assert!(oa.is_open_if());
    assert!(oa.is_kernel_handle());
}

// ─── UnicodeString ───────────────────────────────────────────────────────────

#[test]
fn unicode_string_ascii_lengths() {
    let u = UnicodeString::from_string("AB");
    assert_eq!(u.length, 4);
    assert_eq!(u.maximum_length, 6);
}

#[test]
fn unicode_string_empty() {
    let u = UnicodeString::from_string("");
    assert_eq!(u.length, 0);
    assert_eq!(u.maximum_length, 2);
}

#[test]
fn unicode_string_supplementary_plane() {
    // U+1F600 → 2 UTF-16 code units = 4 bytes
    let u = UnicodeString::from_string("😀");
    assert_eq!(u.length, 4);
}

// ─── MemoryBasicInformation ──────────────────────────────────────────────────

#[test]
fn mbi_state_predicates() {
    let mut m = MemoryBasicInformation {
        base_address: 0,
        allocation_base: 0,
        allocation_protect: 0,
        region_size: 0,
        state: 0x1000,
        protect: 0x40,
        mem_type: 0x2_0000,
    };
    assert!(m.is_committed());
    assert!(!m.is_free());
    assert!(!m.is_reserved());
    assert!(m.is_rwx());
    assert_eq!(m.type_name(), "MEM_PRIVATE");
    m.state = 0x1_0000;
    assert!(m.is_free());
    m.state = 0x2000;
    assert!(m.is_reserved());
    m.mem_type = 0x100_0000;
    assert_eq!(m.type_name(), "MEM_IMAGE");
    m.mem_type = 0x4_0000;
    assert_eq!(m.type_name(), "MEM_MAPPED");
    m.mem_type = 0xdead_beef;
    assert_eq!(m.type_name(), "MEM_UNKNOWN");
}

// ─── Peb ─────────────────────────────────────────────────────────────────────

#[test]
fn peb_debug_flags() {
    let p = Peb {
        image_base: 0,
        ldr: 0,
        process_parameters: 0,
        being_debugged: true,
        nt_global_flags: 0x40,
        heap_count: 0,
    };
    assert!(p.is_debugged());
    assert!(p.has_heap_debug_flags());
}

#[test]
fn peb_no_heap_debug() {
    let p = Peb {
        image_base: 0,
        ldr: 0,
        process_parameters: 0,
        being_debugged: false,
        nt_global_flags: 0x80, // not in 0x70 mask
        heap_count: 0,
    };
    assert!(!p.is_debugged());
    assert!(!p.has_heap_debug_flags());
}

// ─── PageProtect ─────────────────────────────────────────────────────────────

#[test]
fn page_protect_names() {
    assert_eq!(PageProtect::name(0x01), "PAGE_NOACCESS");
    assert_eq!(PageProtect::name(0x02), "PAGE_READONLY");
    assert_eq!(PageProtect::name(0x04), "PAGE_READWRITE");
    assert_eq!(PageProtect::name(0x08), "PAGE_WRITECOPY");
    assert_eq!(PageProtect::name(0x10), "PAGE_EXECUTE");
    assert_eq!(PageProtect::name(0x20), "PAGE_EXECUTE_READ");
    assert_eq!(PageProtect::name(0x40), "PAGE_EXECUTE_READWRITE");
    assert_eq!(PageProtect::name(0x80), "PAGE_EXECUTE_WRITECOPY");
    assert_eq!(PageProtect::name(0x00), "PAGE_UNKNOWN");
}

#[test]
fn page_protect_is_executable_zero() {
    assert!(!PageProtect::is_executable(0));
    assert!(!PageProtect::is_executable(0x01));
}

#[test]
fn page_protect_is_rwx_exact() {
    assert!(PageProtect::is_rwx(0x40));
    assert!(!PageProtect::is_rwx(0x60));
}

// ─── analyse_stub / HookKind ─────────────────────────────────────────────────

#[test]
fn analyse_stub_x64_clean() {
    let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let h = analyse_stub("NtX", 6, WinArch::X64, &stub);
    assert_eq!(h.kind, HookKind::Clean);
}

#[test]
fn analyse_stub_x64_ssn_mismatch() {
    let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x0F, 0x05];
    match analyse_stub("NtX", 6, WinArch::X64, &stub).kind {
        HookKind::SsnMismatch { expected: 6, found: 7 } => {}
        other => panic!("got {other:?}"),
    }
}

#[test]
fn analyse_stub_x64_trampoline() {
    let stub = [0xE9, 0x00, 0x00, 0x00, 0x00, 0, 0, 0];
    match analyse_stub("NtX", 0, WinArch::X64, &stub).kind {
        HookKind::Trampoline { target: 5 } => {}
        other => panic!("got {other:?}"),
    }
}

#[test]
fn analyse_stub_x64_inline_hook_unknown() {
    let stub = [0xCC, 0xCC, 0xCC, 0xCC, 0, 0, 0, 0];
    assert_eq!(
        analyse_stub("NtX", 0, WinArch::X64, &stub).kind,
        HookKind::InlineHook
    );
}

#[test]
fn analyse_stub_x64_too_short() {
    let stub = [0x4C, 0x8B];
    assert_eq!(analyse_stub("NtX", 0, WinArch::X64, &stub).kind, HookKind::Clean);
}

#[test]
fn analyse_stub_x86_clean() {
    let stub = [0xB8, 0x42, 0x00, 0x00, 0x00, 0xBA, 0, 0];
    assert_eq!(
        analyse_stub("NtX", 0x42, WinArch::X86, &stub).kind,
        HookKind::Clean
    );
}

#[test]
fn analyse_stub_x86_mismatch() {
    let stub = [0xB8, 0x99, 0x00, 0x00, 0x00, 0xBA, 0, 0];
    match analyse_stub("NtX", 0x42, WinArch::X86, &stub).kind {
        HookKind::SsnMismatch { expected: 0x42, found: 0x99 } => {}
        other => panic!("got {other:?}"),
    }
}

#[test]
fn analyse_stub_arm64_always_clean() {
    let stub = [0xCC; 16];
    assert_eq!(
        analyse_stub("NtX", 0, WinArch::Arm64, &stub).kind,
        HookKind::Clean
    );
}

#[test]
fn hook_analysis_is_hooked() {
    let stub = [0xE9, 0, 0, 0, 0, 0, 0, 0];
    let h = analyse_stub("NtX", 0, WinArch::X64, &stub);
    assert!(h.is_hooked());
}

#[test]
fn hook_kind_display() {
    assert_eq!(HookKind::Clean.to_string(), "Clean");
    assert_eq!(HookKind::InlineHook.to_string(), "InlineHook");
    assert_eq!(HookKind::IatHook.to_string(), "IatHook");
    let s = HookKind::SsnMismatch { expected: 1, found: 2 }.to_string();
    assert!(s.contains("expected=1"));
    assert!(s.contains("found=2"));
    let t = HookKind::Trampoline { target: 0xdead_beef }.to_string();
    assert!(t.contains("Trampoline"));
}

// ─── VersionSsn / build_version_ssn_table ────────────────────────────────────

#[test]
fn version_ssn_lookup() {
    let mut map = HashMap::new();
    map.insert(WinVersion::Windows10, 6);
    let v = VersionSsn::new("NtReadFile", map);
    assert_eq!(v.ssn_for(WinVersion::Windows10), Some(6));
    assert_eq!(v.ssn_for(WinVersion::WindowsXP), None);
}

#[test]
fn build_version_ssn_table_nonempty_and_known() {
    let tbl = build_version_ssn_table();
    assert!(!tbl.is_empty());
    let ntclose = tbl.iter().find(|e| e.name == "NtClose").expect("NtClose row");
    assert_eq!(ntclose.ssn_for(WinVersion::Windows10), Some(0x000F));
    assert_eq!(ntclose.ssn_for(WinVersion::WindowsXP), Some(0x0019));
}

// ─── WinSyscallDb / WinSyscallResolver ───────────────────────────────────────

#[test]
fn db_default_equiv_new() {
    let a = WinSyscallDb::default();
    let b = WinSyscallDb::new();
    assert_eq!(a.arch_count(WinArch::X64), b.arch_count(WinArch::X64));
}

#[test]
fn db_arch_counts_positive() {
    let db = WinSyscallDb::new();
    assert!(db.arch_count(WinArch::X64) > 0);
    assert!(db.arch_count(WinArch::X86) > 0);
    assert_eq!(db.arch_count(WinArch::Arm64), 0);
}

#[test]
fn db_zw_count_matches_arch_count() {
    let db = WinSyscallDb::new();
    assert_eq!(db.zw_count(WinArch::X64), db.arch_count(WinArch::X64));
}

#[test]
fn db_all_for_arch_unknown_is_none() {
    let db = WinSyscallDb::new();
    assert!(db.all_for_arch(WinArch::Arm64).is_none());
}

#[test]
fn db_lookup_by_name_finds_ntclose() {
    let db = WinSyscallDb::new();
    let s = db.lookup_by_name(WinArch::X64, "NtClose").expect("NtClose");
    assert_eq!(s.name, "NtClose");
}

#[test]
fn db_lookup_by_zw_finds_zwclose() {
    let db = WinSyscallDb::new();
    let s = db.lookup_by_zw_name(WinArch::X64, "ZwClose").expect("ZwClose");
    assert_eq!(s.zw_name, "ZwClose");
}

#[test]
fn db_lookup_unknown_returns_none() {
    let db = WinSyscallDb::new();
    assert!(db.lookup_by_name(WinArch::X64, "NtThisDoesNotExist").is_none());
    assert!(db.lookup(WinArch::X64, 0xFFFF_FFFF).is_none());
}

#[test]
fn db_categories_dedup_and_nonempty() {
    let db = WinSyscallDb::new();
    let cats = db.categories(WinArch::X64);
    assert!(!cats.is_empty());
    let mut sorted = cats.clone();
    sorted.dedup();
    assert_eq!(sorted.len(), cats.len(), "categories must be deduplicated");
}

#[test]
fn resolver_lookup_by_name_consistent_with_ssn_lookup() {
    let r = WinSyscallResolver::new();
    if let Some(s) = r.lookup_by_name(WinArch::X64, "NtClose") {
        let by_ssn = r.lookup(WinArch::X64, s.ssn).expect("ssn lookup");
        assert_eq!(by_ssn.name, s.name);
    }
}

#[test]
fn resolver_all_for_arm64_empty_slice() {
    let r = WinSyscallResolver::new();
    assert!(r.all_for_arch(WinArch::Arm64).is_empty());
}

#[test]
fn resolver_ssn_for_version() {
    let r = WinSyscallResolver::new();
    assert_eq!(r.ssn_for_version("NtClose", WinVersion::Windows11), Some(0x000F));
    assert_eq!(r.ssn_for_version("NotARealSyscall", WinVersion::Windows10), None);
}

#[test]
fn resolver_analyse_hook_uses_db_ssn() {
    let r = WinSyscallResolver::new();
    let target_ssn = r
        .lookup_by_name(WinArch::X64, "NtClose")
        .map_or(0, |s| s.ssn);
    let stub = [
        0x4C, 0x8B, 0xD1, 0xB8,
        (target_ssn & 0xFF) as u8,
        ((target_ssn >> 8) & 0xFF) as u8,
        ((target_ssn >> 16) & 0xFF) as u8,
        ((target_ssn >> 24) & 0xFF) as u8,
        0x0F, 0x05,
    ];
    let h = r.analyse_hook("NtClose", WinArch::X64, &stub);
    assert_eq!(h.kind, HookKind::Clean);
}

// ─── SyscallCapture / SyscallFilter / SyscallMonitor ─────────────────────────

#[test]
fn capture_succeeded_status_success() {
    let mut c = SyscallCapture::new(0, 1, 1, 0, "NtX");
    c.ret = 0;
    assert!(c.succeeded());
}

#[test]
fn capture_succeeded_failed_status() {
    let mut c = SyscallCapture::new(0, 1, 1, 0, "NtX");
    c.ret = 0xC000_0005; // ACCESS_VIOLATION
    assert!(!c.succeeded());
}

#[test]
fn capture_ret_status_name_known() {
    let mut c = SyscallCapture::new(0, 1, 1, 0, "NtX");
    c.ret = 0xC000_0005;
    assert_eq!(c.ret_status_name(), "STATUS_ACCESS_VIOLATION");
}

#[test]
fn filter_pid_inclusion() {
    let f = SyscallFilter::new().with_pids([100u32, 200]);
    let mut c = SyscallCapture::new(0, 100, 1, 0x000F, "NtClose");
    assert!(f.matches(&c));
    c.pid = 999;
    assert!(!f.matches(&c));
}

#[test]
fn filter_exclude_nr() {
    let f = SyscallFilter::new().exclude([0x000Fu32]);
    let c = SyscallCapture::new(0, 0, 0, 0x000F, "NtClose");
    assert!(!f.matches(&c));
}

#[test]
fn filter_category_unknown_nr_rejected() {
    let f = SyscallFilter::new().with_categories([SyscallCategory::FileIo]);
    let c = SyscallCapture::new(0, 0, 0, 0xFFFF_FFFE, "NtUnknown");
    assert!(!f.matches(&c));
}

#[test]
fn filter_empty_matches_everything() {
    let f = SyscallFilter::new();
    let c = SyscallCapture::new(0, 0, 0, 12345, "x");
    assert!(f.matches(&c));
}

#[test]
fn monitor_record_and_snapshot_count() {
    let m = SyscallMonitor::new();
    assert_eq!(m.count(), 0);
    m.record(SyscallCapture::new(0, 1, 1, 0, "a"));
    m.record(SyscallCapture::new(1, 2, 2, 1, "b"));
    assert_eq!(m.count(), 2);
    assert_eq!(m.snapshot().len(), 2);
}

#[test]
fn monitor_for_pid_and_nr() {
    let m = SyscallMonitor::new();
    m.record(SyscallCapture::new(0, 1, 1, 10, "a"));
    m.record(SyscallCapture::new(0, 2, 1, 10, "a"));
    m.record(SyscallCapture::new(0, 1, 1, 20, "b"));
    assert_eq!(m.for_pid(1).len(), 2);
    assert_eq!(m.for_nr(10).len(), 2);
    m.reset();
    assert_eq!(m.count(), 0);
}

#[test]
fn monitor_filter_drops_excluded() {
    let m = SyscallMonitor::new();
    m.add_filter(SyscallFilter::new().exclude([42u32]));
    m.record(SyscallCapture::new(0, 1, 1, 42, "drop"));
    m.record(SyscallCapture::new(0, 1, 1, 7, "keep"));
    assert_eq!(m.count(), 1);
    m.clear_filters();
    m.record(SyscallCapture::new(0, 1, 1, 42, "now-kept"));
    assert_eq!(m.count(), 2);
}

// ─── NtTraceCollector ────────────────────────────────────────────────────────

#[test]
fn raw_bytes_empty_yields_empty() {
    let v = NtTraceCollector::from_raw_bytes(&[]).unwrap();
    assert!(v.is_empty());
}

#[test]
fn raw_bytes_truncated_errors() {
    let r = NtTraceCollector::from_raw_bytes(&[0u8; 3]);
    assert!(r.is_err());
}

#[test]
fn raw_bytes_roundtrip_one_record() {
    // Build one record manually.
    let mut buf = Vec::new();
    buf.extend_from_slice(&123u64.to_le_bytes()); // ts
    buf.extend_from_slice(&42u32.to_le_bytes()); // pid
    buf.extend_from_slice(&7u32.to_le_bytes()); // tid
    buf.extend_from_slice(&0x000Fu32.to_le_bytes()); // nr
    let name = b"NtClose";
    buf.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_le_bytes());
    buf.extend_from_slice(name);
    for _ in 0..12 {
        buf.extend_from_slice(&0u64.to_le_bytes());
    }
    buf.extend_from_slice(&0u64.to_le_bytes()); // ret
    buf.extend_from_slice(&999u64.to_le_bytes()); // duration

    let v = NtTraceCollector::from_raw_bytes(&buf).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].timestamp, 123);
    assert_eq!(v[0].pid, 42);
    assert_eq!(v[0].tid, 7);
    assert_eq!(v[0].nr, 0x000F);
    assert_eq!(v[0].name, "NtClose");
    assert_eq!(v[0].duration_ns, 999);
}

#[test]
fn raw_bytes_name_overrun_errors() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&9999u32.to_le_bytes()); // huge name_len
    let r = NtTraceCollector::from_raw_bytes(&buf);
    assert!(r.is_err());
}

// ─── decode_ntstatus / ntstatus_name / format_ntstatus ───────────────────────

#[test]
fn decode_ntstatus_success() {
    assert_eq!(decode_ntstatus(0), "STATUS_SUCCESS");
    assert_eq!(decode_ntstatus(0x0000_0103), "STATUS_PENDING");
}

#[test]
fn decode_ntstatus_error_known() {
    assert_eq!(decode_ntstatus(0xC000_0005), "STATUS_ACCESS_VIOLATION");
    assert_eq!(decode_ntstatus(0xC000_0022), "STATUS_ACCESS_DENIED");
}

#[test]
fn decode_ntstatus_unknown_falls_through() {
    assert_eq!(decode_ntstatus(0xDEAD_BEEF), "STATUS_UNKNOWN");
}

#[test]
fn ntstatus_name_unknown_is_none() {
    assert_eq!(ntstatus_name(0xDEAD_BEEF), None);
}

#[test]
fn format_ntstatus_known() {
    let s = format_ntstatus(0xC000_0005);
    assert!(s.contains("0xc0000005"));
    assert!(s.contains("STATUS_ACCESS_VIOLATION"));
}

#[test]
fn format_ntstatus_unknown_is_hex_only() {
    let s = format_ntstatus(0xDEAD_BEEF);
    assert_eq!(s, "0xdeadbeef");
}

// ─── InlineHookDescriptor ────────────────────────────────────────────────────

#[test]
fn inline_hook_jmp_patch_bytes_layout() {
    let d = InlineHookDescriptor::new(
        "NtX", "ntdll.dll",
        /* target */ 0x1000,
        /* detour */ 0x1010,
        /* tramp */ 0,
        vec![],
    );
    let p = d.jmp_patch_bytes();
    assert_eq!(p[0], 0xE9);
    // rel = 0x1010 - (0x1000 + 5) = 11
    assert_eq!(i32::from_le_bytes([p[1], p[2], p[3], p[4]]), 11);
}

#[test]
fn inline_hook_jmp_patch_backward() {
    let d = InlineHookDescriptor::new(
        "NtX", "ntdll.dll",
        0x2000,
        0x1000, // backward
        0,
        vec![],
    );
    let p = d.jmp_patch_bytes();
    let rel = i32::from_le_bytes([p[1], p[2], p[3], p[4]]);
    assert_eq!(rel, -0x1005);
}

#[test]
fn inline_hook_jmp64_patch() {
    let d = InlineHookDescriptor::new(
        "NtX", "ntdll.dll",
        0,
        0x1122_3344_5566_7788,
        0,
        vec![],
    );
    let p = d.jmp64_patch_bytes();
    assert_eq!(&p[0..6], &[0xFF, 0x25, 0, 0, 0, 0]);
    assert_eq!(
        u64::from_le_bytes(p[6..14].try_into().unwrap()),
        0x1122_3344_5566_7788
    );
}

// ─── HookRegistry ────────────────────────────────────────────────────────────

#[test]
fn hook_registry_lifecycle() {
    let mut r = HookRegistry::new();
    assert!(r.is_empty());
    let h = InlineHookDescriptor::new("NtX", "ntdll.dll", 0, 0, 0, vec![]);
    r.register(h);
    assert_eq!(r.len(), 1);
    assert!(r.find("NtX").is_some());
    assert_eq!(r.active_hooks().len(), 0);
    r.activate("NtX");
    assert_eq!(r.active_hooks().len(), 1);
    r.deactivate("NtX");
    assert_eq!(r.active_hooks().len(), 0);
    r.remove("NtX");
    assert!(r.is_empty());
}

#[test]
fn hook_registry_missing_name_is_noop() {
    let mut r = HookRegistry::new();
    r.activate("does-not-exist");
    r.deactivate("does-not-exist");
    r.remove("does-not-exist");
    assert!(r.is_empty());
}

// ─── nt_to_win32_path / is_system_path ───────────────────────────────────────

#[test]
fn nt_to_win32_harddisk_volume_3_is_c() {
    let p = nt_to_win32_path("\\Device\\HarddiskVolume3\\Windows\\System32\\foo.dll");
    // volume 1 -> A, 2 -> B, 3 -> C
    assert_eq!(p, "C:\\Windows\\System32\\foo.dll");
}

#[test]
fn nt_to_win32_harddisk_volume_1_is_a() {
    let p = nt_to_win32_path("\\Device\\HarddiskVolume1\\x");
    assert_eq!(p, "A:\\x");
}

#[test]
fn nt_to_win32_dosdevice_prefix() {
    let p = nt_to_win32_path("\\??\\C:\\path");
    assert_eq!(p, "C:\\path");
}

#[test]
fn nt_to_win32_long_path_prefix() {
    let p = nt_to_win32_path("\\\\?\\C:\\very\\long");
    assert_eq!(p, "C:\\very\\long");
}

#[test]
fn nt_to_win32_unknown_passthrough() {
    let p = nt_to_win32_path("foo");
    assert_eq!(p, "foo");
}

#[test]
fn is_system_path_true_cases() {
    assert!(is_system_path("C:\\Windows\\System32\\kernel32.dll"));
    assert!(is_system_path("c:\\windows\\syswow64\\x.dll"));
    assert!(is_system_path("D:\\app\\Windows\\x"));
}

#[test]
fn is_system_path_false() {
    assert!(!is_system_path("C:\\Users\\me\\file.txt"));
}

// ─── decode_file_access / decode_alloc_type ──────────────────────────────────

#[test]
fn decode_file_access_zero_is_hex() {
    assert_eq!(decode_file_access(0), "0x0");
}

#[test]
fn decode_file_access_combined() {
    let s = decode_file_access(0x8000_0000 | 0x4000_0000 | 0x0010_0000);
    assert!(s.contains("GENERIC_READ"));
    assert!(s.contains("GENERIC_WRITE"));
    assert!(s.contains("SYNCHRONIZE"));
}

#[test]
fn decode_alloc_type_combined() {
    let s = decode_alloc_type(0x1000 | 0x2000);
    assert!(s.contains("MEM_COMMIT"));
    assert!(s.contains("MEM_RESERVE"));
}

#[test]
fn decode_alloc_type_zero() {
    assert_eq!(decode_alloc_type(0), "0x0");
}

// ─── nt_to_win32_reg_path / is_persistence_registry_key ──────────────────────

#[test]
fn reg_path_machine_to_hklm() {
    assert_eq!(
        nt_to_win32_reg_path("\\REGISTRY\\MACHINE\\SOFTWARE\\X"),
        "HKLM\\SOFTWARE\\X"
    );
}

#[test]
fn reg_path_user_to_hku() {
    assert_eq!(
        nt_to_win32_reg_path("\\REGISTRY\\USER\\S-1-5-21"),
        "HKU\\S-1-5-21"
    );
}

#[test]
fn reg_path_other_registry() {
    assert_eq!(nt_to_win32_reg_path("\\REGISTRY\\A\\B"), "A\\B");
}

#[test]
fn reg_path_passthrough() {
    assert_eq!(nt_to_win32_reg_path("HKLM\\already"), "HKLM\\already");
}

#[test]
fn is_persistence_run_key() {
    assert!(is_persistence_registry_key(
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X"
    ));
    assert!(is_persistence_registry_key("HKLM\\System\\CurrentControlSet\\Services\\foo"));
    assert!(!is_persistence_registry_key("HKLM\\Software\\Vendor\\App"));
}

// ─── is_dangerous_privilege / WINDOWS_PRIVILEGES ─────────────────────────────

#[test]
fn dangerous_privilege_known() {
    assert!(is_dangerous_privilege("SeDebugPrivilege"));
    assert!(is_dangerous_privilege("SeImpersonatePrivilege"));
    assert!(!is_dangerous_privilege("SeChangeNotifyPrivilege"));
    assert!(!is_dangerous_privilege(""));
}

#[test]
fn privileges_list_contains_known() {
    assert!(WINDOWS_PRIVILEGES.contains(&"SeDebugPrivilege"));
}

// ─── winsock_error_name ──────────────────────────────────────────────────────

#[test]
fn winsock_known_codes() {
    assert_eq!(winsock_error_name(10_054), Some("WSAECONNRESET"));
    assert_eq!(winsock_error_name(11_001), Some("WSAHOST_NOT_FOUND"));
    assert_eq!(winsock_error_name(0), None);
    assert_eq!(winsock_error_name(-1), None);
}

// ─── PeHeaders::parse ────────────────────────────────────────────────────────

fn build_pe_pe32plus() -> Vec<u8> {
    // DOS header up to e_lfanew at offset 60, PE header at offset 0x80.
    let e_lfanew: u32 = 0x80;
    let mut data = vec![0u8; 0x80 + 100];
    data[0] = b'M';
    data[1] = b'Z';
    data[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
    let off = e_lfanew as usize;
    // PE\0\0
    data[off..off + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
    data[off + 4..off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine = AMD64
    data[off + 6..off + 8].copy_from_slice(&3u16.to_le_bytes()); // sections
    data[off + 8..off + 12].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // ts
    let opt = off + 24;
    data[opt..opt + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
    data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
    data[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // base
    data[opt + 56..opt + 60].copy_from_slice(&0xA000u32.to_le_bytes()); // size_of_image
    data[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
    data[opt + 70..opt + 72].copy_from_slice(&(0x0040u16 | 0x0100 | 0x2000).to_le_bytes()); // dllchars
    data
}

#[test]
fn pe_headers_parse_pe32plus() {
    let data = build_pe_pe32plus();
    let h = PeHeaders::parse(&data).expect("parse");
    assert!(h.is_64bit);
    assert_eq!(h.machine, 0x8664);
    assert_eq!(h.number_of_sections, 3);
    assert_eq!(h.timestamp, 0x1234_5678);
    assert_eq!(h.entry_point_rva, 0x1000);
    assert_eq!(h.image_base, 0x0000_0001_4000_0000);
    assert_eq!(h.size_of_image, 0xA000);
    assert_eq!(h.subsystem, 3);
    assert!(h.has_aslr());
    assert!(h.has_dep());
    assert!(h.is_dll());
}

#[test]
fn pe_headers_bad_dos_magic() {
    let data = vec![0u8; 256];
    assert!(PeHeaders::parse(&data).is_none());
}

#[test]
fn pe_headers_too_short() {
    assert!(PeHeaders::parse(&[0u8; 32]).is_none());
}

#[test]
fn pe_headers_bad_pe_sig() {
    let mut data = vec![0u8; 256];
    data[0] = b'M';
    data[1] = b'Z';
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    // Leave PE bytes as zero.
    assert!(PeHeaders::parse(&data).is_none());
}

// ─── stub-detection helpers ──────────────────────────────────────────────────

#[test]
fn is_clean_x64_stub_short_returns_false() {
    assert!(!is_clean_x64_stub(&[0x4C, 0x8B], 0));
}

#[test]
fn is_clean_x86_stub_short_returns_false() {
    assert!(!is_clean_x86_stub(&[0xB8, 0], 0));
}

#[test]
fn detect_hook_type_empty_clean() {
    assert_eq!(detect_hook_type(&[]), HookKind::Clean);
}

#[test]
fn detect_hook_type_ff25_inline() {
    let stub = [0xFF, 0x25, 0, 0, 0, 0, 0, 0];
    assert_eq!(detect_hook_type(&stub), HookKind::InlineHook);
}

#[test]
fn detect_hook_type_push_ret_inline() {
    let stub = [0x68, 0x11, 0x22, 0x33, 0x44, 0xC3];
    assert_eq!(detect_hook_type(&stub), HookKind::InlineHook);
}

// ─── categorize_nt indirectly via WinNtSyscall ───────────────────────────────

#[test]
fn category_filesystem() {
    let s = WinNtSyscall::new(0, "NtCreateFile", vec![], "ntdll.dll");
    assert_eq!(s.category, NtSyscallCategory::FileSystem);
}

#[test]
fn category_memory() {
    let s = WinNtSyscall::new(0, "NtAllocateVirtualMemory", vec![], "ntdll.dll");
    assert_eq!(s.category, NtSyscallCategory::Memory);
}

#[test]
fn category_registry() {
    let s = WinNtSyscall::new(0, "NtOpenKey", vec![], "ntdll.dll");
    assert_eq!(s.category, NtSyscallCategory::Registry);
}

#[test]
fn category_security_token() {
    let s = WinNtSyscall::new(0, "NtAccessCheck", vec![], "ntdll.dll");
    assert_eq!(s.category, NtSyscallCategory::Security);
}

#[test]
fn category_display() {
    assert_eq!(NtSyscallCategory::FileSystem.to_string(), "filesystem");
    assert_eq!(NtSyscallCategory::Memory.to_string(), "memory");
    assert_eq!(NtSyscallCategory::Unknown.to_string(), "unknown");
}

// ─── ArgType / SyscallCategory display ───────────────────────────────────────

#[test]
fn argtype_display_names() {
    assert_eq!(ArgType::Handle.to_string(), "HANDLE");
    assert_eq!(ArgType::SizeT.to_string(), "SIZE_T");
    assert_eq!(ArgType::UlongPtr.to_string(), "ULONG_PTR");
}

#[test]
fn syscallcategory_display_filio() {
    assert_eq!(SyscallCategory::FileIo.to_string(), "FileIO");
    assert_eq!(SyscallCategory::ObjectMgmt.to_string(), "ObjectMgmt");
}

// ─── Send/Sync sanity for SyscallMonitor ─────────────────────────────────────

#[test]
fn monitor_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SyscallMonitor>();
    assert_send_sync::<WinSyscallResolver>();
    assert_send_sync::<WinSyscallDb>();
}

// ─── WinEventLevel ───────────────────────────────────────────────────────────

#[test]
fn win_event_level_values_and_display() {
    assert_eq!(WinEventLevel::Critical as u8, 1);
    assert_eq!(WinEventLevel::Verbose as u8, 5);
    assert_eq!(WinEventLevel::Warning.to_string(), "Warning");
}
