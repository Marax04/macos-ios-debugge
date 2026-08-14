
// ─── Windows event log record ─────────────────────────────────────────────────

/// A simplified Windows event log record for malware analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinEventRecord {
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub level: WinEventLevel,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub message: String,
    pub keywords: u64,
}

/// Windows event log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WinEventLevel {
    Critical = 1,
    Error    = 2,
    Warning  = 3,
    Info     = 4,
    Verbose  = 5,
}

impl std::fmt::Display for WinEventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::Error    => write!(f, "Error"),
            Self::Warning  => write!(f, "Warning"),
            Self::Info     => write!(f, "Info"),
            Self::Verbose  => write!(f, "Verbose"),
        }
    }
}

impl WinEventRecord {
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"event_id\":{},\"provider\":{:?},\"channel\":{:?},\"level\":{:?},\"pid\":{},\"tid\":{},\"message\":{:?}}}",
            self.event_id, self.provider, self.channel, self.level.to_string(), self.pid, self.tid, self.message
        )
    }
}

// ─── Windows stub detection helpers ──────────────────────────────────────────

/// Known clean stub patterns for ntdll x64.
pub static CLEAN_X64_STUB_PREFIX: &[u8] = &[0x4C, 0x8B, 0xD1, 0xB8];

/// Check whether stub bytes look clean (unhooked) for x64.
#[must_use]
pub fn is_clean_x64_stub(stub: &[u8], expected_ssn: u32) -> bool {
    if stub.len() < 8 { return false; }
    if &stub[..4] != CLEAN_X64_STUB_PREFIX { return false; }
    let found_ssn = u16::from_le_bytes([stub[4], stub[5]]) as u32;
    found_ssn == expected_ssn
}

/// Check whether stub bytes look clean (unhooked) for x86.
#[must_use]
pub fn is_clean_x86_stub(stub: &[u8], expected_ssn: u32) -> bool {
    if stub.len() < 5 || stub[0] != 0xB8 { return false; }
    let found = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
    found == expected_ssn
}

/// Detect the kind of inline hook at the beginning of a function stub.
#[must_use]
pub fn detect_hook_type(stub: &[u8]) -> HookKind {
    if stub.is_empty() { return HookKind::Clean; }
    if stub[0] == 0xE9 && stub.len() >= 5 {
        let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        let target = (5i64 + rel as i64) as u64;
        return HookKind::Trampoline { target };
    }
    if stub[0] == 0xFF && stub.len() >= 6 && stub[1] == 0x25 {
        // JMP [RIP+offset] — absolute jump through memory
        return HookKind::InlineHook;
    }
    if stub[0] == 0x68 && stub.len() >= 5 {
        // PUSH addr; RET — old-style hook
        return HookKind::InlineHook;
    }
    HookKind::Clean
}

// ─── Windows PE header parsing helpers ───────────────────────────────────────

/// DOS header magic: "MZ"
pub const MZ_MAGIC: u16 = 0x5A4D;
/// PE header magic: "PE\0\0"
pub const PE_MAGIC: u32 = 0x00004550;
/// PE32 optional header magic.
pub const PE32_MAGIC: u16 = 0x010B;
/// PE32+ optional header magic.
pub const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Minimal parsed PE header information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeHeaders {
    pub is_64bit: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub number_of_sections: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

impl PeHeaders {
    /// Parse minimal PE headers from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 { return None; }
        let dos_magic = u16::from_le_bytes([data[0], data[1]]);
        if dos_magic != MZ_MAGIC { return None; }
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if e_lfanew + 24 > data.len() { return None; }
        let pe_magic = u32::from_le_bytes([data[e_lfanew], data[e_lfanew+1], data[e_lfanew+2], data[e_lfanew+3]]);
        if pe_magic != PE_MAGIC { return None; }
        let machine = u16::from_le_bytes([data[e_lfanew+4], data[e_lfanew+5]]);
        let number_of_sections = u16::from_le_bytes([data[e_lfanew+6], data[e_lfanew+7]]);
        let timestamp = u32::from_le_bytes([data[e_lfanew+8], data[e_lfanew+9], data[e_lfanew+10], data[e_lfanew+11]]);
        let opt_off = e_lfanew + 24;
        if opt_off + 4 > data.len() { return None; }
        let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off+1]]);
        let is_64bit = opt_magic == PE32_PLUS_MAGIC;
        if opt_off + 60 > data.len() { return None; }
        let entry_point_rva = u32::from_le_bytes([data[opt_off+16], data[opt_off+17], data[opt_off+18], data[opt_off+19]]);
        let (image_base, subsystem_off, size_of_image_off) = if is_64bit {
            let base = u64::from_le_bytes([
                data[opt_off+24], data[opt_off+25], data[opt_off+26], data[opt_off+27],
                data[opt_off+28], data[opt_off+29], data[opt_off+30], data[opt_off+31],
            ]);
            (base, opt_off + 68, opt_off + 56)
        } else {
            let base = u32::from_le_bytes([data[opt_off+28], data[opt_off+29], data[opt_off+30], data[opt_off+31]]) as u64;
            (base, opt_off + 68, opt_off + 56)
        };
        let size_of_image = if size_of_image_off + 4 <= data.len() {
            u32::from_le_bytes([data[size_of_image_off], data[size_of_image_off+1], data[size_of_image_off+2], data[size_of_image_off+3]])
        } else { 0 };
        let subsystem = if subsystem_off + 2 <= data.len() {
            u16::from_le_bytes([data[subsystem_off], data[subsystem_off+1]])
        } else { 0 };
        let dll_char_off = subsystem_off + 2;
        let dll_characteristics = if dll_char_off + 2 <= data.len() {
            u16::from_le_bytes([data[dll_char_off], data[dll_char_off+1]])
        } else { 0 };
        Some(Self { is_64bit, machine, timestamp, number_of_sections, entry_point_rva, image_base, size_of_image, subsystem, dll_characteristics })
    }

    /// Returns `true` if ASLR is enabled (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).
    #[must_use]
    pub fn has_aslr(&self) -> bool { self.dll_characteristics & 0x0040 != 0 }
    /// Returns `true` if DEP is enabled.
    #[must_use]
    pub fn has_dep(&self) -> bool { self.dll_characteristics & 0x0100 != 0 }
    /// Returns `true` if the file is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool { self.dll_characteristics & 0x2000 != 0 }
}

// ─── Additional tests (part 4) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext4_tests {
    use super::*;

    #[test]
    fn test_win_event_level_display() {
        assert_eq!(WinEventLevel::Critical.to_string(), "Critical");
        assert_eq!(WinEventLevel::Warning.to_string(),  "Warning");
        assert_eq!(WinEventLevel::Info.to_string(),     "Info");
    }

    #[test]
    fn test_win_event_record_to_json() {
        let rec = WinEventRecord {
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            channel: "Security".to_string(),
            level: WinEventLevel::Info,
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            message: "A new process has been created.".to_string(),
            keywords: 0x8020000000000000,
        };
        let j = rec.to_json();
        assert!(j.contains("4688"));
        assert!(j.contains("process has been created"));
    }

    #[test]
    fn test_is_clean_x64_stub_true() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06u8, 0x00, 0x00, 0x00, 0x0F, 0x05];
        assert!(is_clean_x64_stub(&stub, 6));
    }

    #[test]
    fn test_is_clean_x64_stub_wrong_ssn() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06u8, 0x00, 0x00, 0x00, 0x0F, 0x05];
        assert!(!is_clean_x64_stub(&stub, 7));
    }

    #[test]
    fn test_is_clean_x64_stub_hooked() {
        let stub = [0xE9, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00];
        assert!(!is_clean_x64_stub(&stub, 0));
    }

    #[test]
    fn test_is_clean_x86_stub_true() {
        let ssn: u32 = 0x42;
        let bytes = ssn.to_le_bytes();
        let stub = [0xB8, bytes[0], bytes[1], bytes[2], bytes[3], 0xBA, 0x00, 0x00];
        assert!(is_clean_x86_stub(&stub, 0x42));
    }

    #[test]
    fn test_detect_hook_type_jmp_rel32() {
        let stub = [0xE9, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        match detect_hook_type(&stub) {
            HookKind::Trampoline { target } => assert_eq!(target, 21),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_detect_hook_type_clean() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06, 0x00, 0x00, 0x00];
        assert_eq!(detect_hook_type(&stub), HookKind::Clean);
    }

    #[test]
    fn test_detect_hook_type_push_ret() {
        let stub = [0x68, 0x00, 0x10, 0x00, 0x00, 0xC3, 0x90, 0x90];
        assert_eq!(detect_hook_type(&stub), HookKind::InlineHook);
    }

    #[test]
    fn test_pe_headers_parse_invalid_magic() {
        let data = vec![0u8; 64];
        assert!(PeHeaders::parse(&data).is_none());
    }

    #[test]
    fn test_pe_headers_too_short() {
        assert!(PeHeaders::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_analyse_stub_clean_x64() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let h = analyse_stub("NtClose", 3, WinArch::X64, &stub);
        assert_eq!(h.kind, HookKind::Clean);
        assert!(!h.is_hooked());
    }

    #[test]
    fn test_analyse_stub_wrong_ssn() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let h = analyse_stub("NtClose", 3, WinArch::X64, &stub);
        match h.kind {
            HookKind::SsnMismatch { expected, found } => {
                assert_eq!(expected, 3);
                assert_eq!(found, 5);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_hook_kind_display() {
        assert_eq!(HookKind::Clean.to_string(), "Clean");
        assert_eq!(HookKind::InlineHook.to_string(), "InlineHook");
        assert!(HookKind::SsnMismatch { expected: 1, found: 2 }.to_string().contains("SsnMismatch"));
    }

    #[test]
    fn test_page_protect_is_executable() {
        assert!(PageProtect::is_executable(0x40));  // PAGE_EXECUTE_READWRITE
        assert!(PageProtect::is_executable(0x20));  // PAGE_EXECUTE_READ
        assert!(!PageProtect::is_executable(0x04)); // PAGE_READWRITE
    }

    #[test]
    fn test_page_protect_name_rwx() {
        assert_eq!(PageProtect::name(0x40), "PAGE_EXECUTE_READWRITE");
    }

    #[test]
    fn test_page_protect_is_writable() {
        assert!(PageProtect::is_writable(0x04));
        assert!(PageProtect::is_writable(0x40));
        assert!(!PageProtect::is_writable(0x02));
    }

    #[test]
    fn test_win_syscall_db_x64_count() {
        let db = WinSyscallDb::new();
        assert!(db.arch_count(WinArch::X64) > 50);
    }

    #[test]
    fn test_win_syscall_resolver_lookup_ntclose() {
        let r = WinSyscallResolver::new();
        let s = r.lookup_by_name(WinArch::X64, "NtClose");
        assert!(s.is_some());
    }

    #[test]
    fn test_win_event_level_values() {
        assert_eq!(WinEventLevel::Critical as u8, 1);
        assert_eq!(WinEventLevel::Error    as u8, 2);
        assert_eq!(WinEventLevel::Warning  as u8, 3);
        assert_eq!(WinEventLevel::Info     as u8, 4);
        assert_eq!(WinEventLevel::Verbose  as u8, 5);
    }
}
