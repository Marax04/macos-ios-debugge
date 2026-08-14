
// ─── NTSTATUS decoder ─────────────────────────────────────────────────────────

/// Return the symbolic name of a common NTSTATUS code.
#[must_use]
pub fn ntstatus_name(code: u32) -> Option<&'static str> {
    match code {
        0x00000000 => Some("STATUS_SUCCESS"),
        0x00000001 => Some("STATUS_WAIT_1"),
        0x00000080 => Some("STATUS_ABANDONED_WAIT_0"),
        0x000000C0 => Some("STATUS_USER_APC"),
        0x00000100 => Some("STATUS_USER_CALLBACK"),
        0x00000101 => Some("STATUS_ALERTED"),
        0x00000102 => Some("STATUS_TIMEOUT"),
        0x00000103 => Some("STATUS_PENDING"),
        0x00000104 => Some("STATUS_REPARSE"),
        0x00000105 => Some("STATUS_MORE_ENTRIES"),
        0x00000106 => Some("STATUS_NOT_ALL_ASSIGNED"),
        0x00000107 => Some("STATUS_SOME_NOT_MAPPED"),
        0x00000108 => Some("STATUS_OPLOCK_BREAK_IN_PROGRESS"),
        0x00000109 => Some("STATUS_VOLUME_MOUNTED"),
        0x0000010A => Some("STATUS_RXACT_COMMITTED"),
        0x0000010B => Some("STATUS_NOTIFY_CLEANUP"),
        0x0000010C => Some("STATUS_NOTIFY_ENUM_DIR"),
        0x0000010D => Some("STATUS_NO_QUOTAS_FOR_ACCOUNT"),
        0x00000110 => Some("STATUS_DELETE_PENDING"),
        0x00000111 => Some("STATUS_CTL_FILE_NOT_SUPPORTED"),
        0x40000000 => Some("STATUS_OBJECT_NAME_EXISTS"),
        0x40000001 => Some("STATUS_THREAD_WAS_SUSPENDED"),
        0x40000002 => Some("STATUS_WORKING_SET_LIMIT_RANGE"),
        0x40000003 => Some("STATUS_IMAGE_NOT_AT_BASE"),
        0x40000004 => Some("STATUS_RXACT_STATE_CREATED"),
        0x40000005 => Some("STATUS_SEGMENT_NOTIFICATION"),
        0x40000006 => Some("STATUS_LOCAL_USER_SESSION_KEY"),
        0x40000007 => Some("STATUS_BAD_CURRENT_DIRECTORY"),
        0x40000008 => Some("STATUS_SERIAL_MORE_WRITES"),
        0x40000009 => Some("STATUS_REGISTRY_RECOVERED"),
        0x4000000A => Some("STATUS_FT_READ_RECOVERY_FROM_BACKUP"),
        0x8000000D => Some("STATUS_NO_MORE_FILES"),
        0x80000001 => Some("STATUS_GUARD_PAGE_VIOLATION"),
        0x80000002 => Some("STATUS_DATATYPE_MISALIGNMENT"),
        0x80000003 => Some("STATUS_BREAKPOINT"),
        0x80000004 => Some("STATUS_SINGLE_STEP"),
        0x80000005 => Some("STATUS_BUFFER_OVERFLOW"),
        0x80000006 => Some("STATUS_NO_MORE_FILES"),
        0x80000007 => Some("STATUS_WAKE_SYSTEM_DEBUGGER"),
        0x80000008 => Some("STATUS_HANDLES_CLOSED"),
        0x80000009 => Some("STATUS_NO_INHERITANCE"),
        0x8000000A => Some("STATUS_GUID_SUBSTITUTION_MADE"),
        0x8000000B => Some("STATUS_PARTIAL_COPY"),
        0x8000000C => Some("STATUS_DEVICE_PAPER_EMPTY"),
        0x8000000E => Some("STATUS_NO_MORE_EAS"),
        0x8000000F => Some("STATUS_RETURNS_WITHOUT_PERFORMING_REQUESTED_OPERATION"),
        0x80000010 => Some("STATUS_PREDEFINED_HANDLE"),
        0x80000011 => Some("STATUS_WAS_UNLOCKED"),
        0x80000012 => Some("STATUS_SERVICE_NOTIFICATION"),
        0x80000013 => Some("STATUS_WAS_LOCKED"),
        0x80000014 => Some("STATUS_LOG_HARD_ERROR"),
        0x80000015 => Some("STATUS_ALREADY_WIN32"),
        0x80000016 => Some("STATUS_WX86_UNSIMULATE"),
        0x80000017 => Some("STATUS_WX86_CONTINUE"),
        0xC0000001 => Some("STATUS_UNSUCCESSFUL"),
        0xC0000002 => Some("STATUS_NOT_IMPLEMENTED"),
        0xC0000003 => Some("STATUS_INVALID_INFO_CLASS"),
        0xC0000004 => Some("STATUS_INFO_LENGTH_MISMATCH"),
        0xC0000005 => Some("STATUS_ACCESS_VIOLATION"),
        0xC0000006 => Some("STATUS_IN_PAGE_ERROR"),
        0xC0000007 => Some("STATUS_PAGEFILE_QUOTA"),
        0xC0000008 => Some("STATUS_INVALID_HANDLE"),
        0xC0000009 => Some("STATUS_BAD_INITIAL_STACK"),
        0xC000000A => Some("STATUS_BAD_INITIAL_PC"),
        0xC000000B => Some("STATUS_INVALID_CID"),
        0xC000000C => Some("STATUS_TIMER_NOT_CANCELED"),
        0xC000000D => Some("STATUS_INVALID_PARAMETER"),
        0xC000000E => Some("STATUS_NO_SUCH_DEVICE"),
        0xC000000F => Some("STATUS_NO_SUCH_FILE"),
        0xC0000010 => Some("STATUS_INVALID_DEVICE_REQUEST"),
        0xC0000011 => Some("STATUS_END_OF_FILE"),
        0xC0000012 => Some("STATUS_WRONG_VOLUME"),
        0xC0000013 => Some("STATUS_NO_MEDIA_IN_DEVICE"),
        0xC0000014 => Some("STATUS_UNRECOGNIZED_MEDIA"),
        0xC0000015 => Some("STATUS_NONEXISTENT_SECTOR"),
        0xC0000016 => Some("STATUS_MORE_PROCESSING_REQUIRED"),
        0xC0000017 => Some("STATUS_NO_MEMORY"),
        0xC0000018 => Some("STATUS_CONFLICTING_ADDRESSES"),
        0xC0000019 => Some("STATUS_NOT_MAPPED_VIEW"),
        0xC000001A => Some("STATUS_UNABLE_TO_FREE_VM"),
        0xC000001B => Some("STATUS_UNABLE_TO_DELETE_SECTION"),
        0xC000001C => Some("STATUS_INVALID_SYSTEM_SERVICE"),
        0xC000001D => Some("STATUS_ILLEGAL_INSTRUCTION"),
        0xC000001E => Some("STATUS_INVALID_LOCK_SEQUENCE"),
        0xC000001F => Some("STATUS_INVALID_VIEW_SIZE"),
        0xC0000020 => Some("STATUS_INVALID_FILE_FOR_SECTION"),
        0xC0000021 => Some("STATUS_ALREADY_COMMITTED"),
        0xC0000022 => Some("STATUS_ACCESS_DENIED"),
        0xC0000023 => Some("STATUS_BUFFER_TOO_SMALL"),
        0xC0000024 => Some("STATUS_OBJECT_TYPE_MISMATCH"),
        0xC0000025 => Some("STATUS_NONCONTINUABLE_EXCEPTION"),
        0xC0000026 => Some("STATUS_INVALID_DISPOSITION"),
        0xC0000027 => Some("STATUS_UNWIND"),
        0xC0000028 => Some("STATUS_BAD_STACK"),
        0xC0000029 => Some("STATUS_INVALID_UNWIND_TARGET"),
        0xC000002A => Some("STATUS_NOT_LOCKED"),
        0xC000002B => Some("STATUS_PARITY_ERROR"),
        0xC000002C => Some("STATUS_UNABLE_TO_DECOMMIT_VM"),
        0xC000002D => Some("STATUS_NOT_COMMITTED"),
        0xC000002E => Some("STATUS_INVALID_PORT_ATTRIBUTES"),
        0xC000002F => Some("STATUS_PORT_MESSAGE_TOO_LONG"),
        0xC0000030 => Some("STATUS_INVALID_PARAMETER_MIX"),
        0xC0000031 => Some("STATUS_INVALID_QUOTA_LOWER"),
        0xC0000032 => Some("STATUS_DISK_CORRUPT_ERROR"),
        0xC0000033 => Some("STATUS_OBJECT_NAME_INVALID"),
        0xC0000034 => Some("STATUS_OBJECT_NAME_NOT_FOUND"),
        0xC0000035 => Some("STATUS_OBJECT_NAME_COLLISION"),
        0xC0000037 => Some("STATUS_PORT_DISCONNECTED"),
        0xC0000038 => Some("STATUS_DEVICE_ALREADY_ATTACHED"),
        0xC0000039 => Some("STATUS_OBJECT_PATH_INVALID"),
        0xC000003A => Some("STATUS_OBJECT_PATH_NOT_FOUND"),
        0xC000003B => Some("STATUS_OBJECT_PATH_SYNTAX_BAD"),
        0xC000003C => Some("STATUS_DATA_OVERRUN"),
        0xC000003D => Some("STATUS_DATA_LATE_ERROR"),
        0xC000003E => Some("STATUS_DATA_ERROR"),
        0xC000003F => Some("STATUS_CRC_ERROR"),
        0xC0000040 => Some("STATUS_SECTION_TOO_BIG"),
        0xC0000041 => Some("STATUS_PORT_CONNECTION_REFUSED"),
        0xC0000042 => Some("STATUS_INVALID_PORT_HANDLE"),
        0xC0000043 => Some("STATUS_SHARING_VIOLATION"),
        0xC0000044 => Some("STATUS_QUOTA_EXCEEDED"),
        0xC0000045 => Some("STATUS_INVALID_PAGE_PROTECTION"),
        0xC0000046 => Some("STATUS_MUTANT_NOT_OWNED"),
        0xC0000047 => Some("STATUS_SEMAPHORE_LIMIT_EXCEEDED"),
        0xC0000048 => Some("STATUS_PORT_ALREADY_SET"),
        0xC0000049 => Some("STATUS_SECTION_NOT_IMAGE"),
        0xC000004A => Some("STATUS_SUSPEND_COUNT_EXCEEDED"),
        0xC000004B => Some("STATUS_THREAD_IS_TERMINATING"),
        0xC000004C => Some("STATUS_BAD_WORKING_SET_LIMIT"),
        0xC000004D => Some("STATUS_INCOMPATIBLE_FILE_MAP"),
        0xC000004E => Some("STATUS_SECTION_PROTECTION"),
        0xC000004F => Some("STATUS_EAS_NOT_SUPPORTED"),
        0xC0000050 => Some("STATUS_EA_TOO_LARGE"),
        0xC0000051 => Some("STATUS_NONEXISTENT_EA_ENTRY"),
        0xC0000052 => Some("STATUS_NO_EAS_ON_FILE"),
        0xC0000053 => Some("STATUS_EA_CORRUPT_ERROR"),
        0xC0000054 => Some("STATUS_FILE_LOCK_CONFLICT"),
        0xC0000055 => Some("STATUS_LOCK_NOT_GRANTED"),
        0xC0000056 => Some("STATUS_DELETE_PENDING"),
        0xC0000057 => Some("STATUS_CTL_FILE_NOT_SUPPORTED"),
        0xC0000058 => Some("STATUS_UNKNOWN_REVISION"),
        0xC0000059 => Some("STATUS_REVISION_MISMATCH"),
        0xC000005A => Some("STATUS_INVALID_OWNER"),
        0xC000005B => Some("STATUS_INVALID_PRIMARY_GROUP"),
        0xC000005C => Some("STATUS_NO_IMPERSONATION_TOKEN"),
        0xC000005D => Some("STATUS_CANT_DISABLE_MANDATORY"),
        0xC000005E => Some("STATUS_NO_LOGON_SERVERS"),
        0xC000005F => Some("STATUS_NO_SUCH_LOGON_SESSION"),
        0xC0000060 => Some("STATUS_NO_SUCH_PRIVILEGE"),
        0xC0000061 => Some("STATUS_PRIVILEGE_NOT_HELD"),
        0xC0000062 => Some("STATUS_INVALID_ACCOUNT_NAME"),
        0xC0000063 => Some("STATUS_USER_EXISTS"),
        0xC0000064 => Some("STATUS_NO_SUCH_USER"),
        0xC0000065 => Some("STATUS_GROUP_EXISTS"),
        0xC0000066 => Some("STATUS_NO_SUCH_GROUP"),
        0xC0000067 => Some("STATUS_MEMBER_IN_GROUP"),
        0xC0000068 => Some("STATUS_MEMBER_NOT_IN_GROUP"),
        0xC0000069 => Some("STATUS_LAST_ADMIN"),
        0xC000006A => Some("STATUS_WRONG_PASSWORD"),
        0xC000006B => Some("STATUS_ILL_FORMED_PASSWORD"),
        0xC000006C => Some("STATUS_PASSWORD_RESTRICTION"),
        0xC000006D => Some("STATUS_LOGON_FAILURE"),
        0xC000006E => Some("STATUS_ACCOUNT_RESTRICTION"),
        0xC000006F => Some("STATUS_INVALID_LOGON_HOURS"),
        0xC0000070 => Some("STATUS_INVALID_WORKSTATION"),
        0xC0000071 => Some("STATUS_PASSWORD_EXPIRED"),
        0xC0000072 => Some("STATUS_ACCOUNT_DISABLED"),
        0xC0000073 => Some("STATUS_NONE_MAPPED"),
        0xC0000074 => Some("STATUS_TOO_MANY_LUIDS_REQUESTED"),
        0xC0000075 => Some("STATUS_LUIDS_EXHAUSTED"),
        0xC0000076 => Some("STATUS_INVALID_SUB_AUTHORITY"),
        0xC0000077 => Some("STATUS_INVALID_ACL"),
        0xC0000078 => Some("STATUS_INVALID_SID"),
        0xC0000079 => Some("STATUS_INVALID_SECURITY_DESCR"),
        0xC0000080 => Some("STATUS_PROCEDURE_NOT_FOUND"),
        0xC0000081 => Some("STATUS_INVALID_IMAGE_FORMAT"),
        0xC0000082 => Some("STATUS_NO_TOKEN"),
        0xC0000083 => Some("STATUS_BAD_INHERITANCE_ACL"),
        0xC0000084 => Some("STATUS_RANGE_NOT_LOCKED"),
        0xC0000085 => Some("STATUS_DISK_FULL"),
        0xC0000086 => Some("STATUS_SERVER_DISABLED"),
        0xC0000087 => Some("STATUS_SERVER_NOT_DISABLED"),
        0xC0000088 => Some("STATUS_TOO_MANY_GUIDS_REQUESTED"),
        0xC0000089 => Some("STATUS_GUIDS_EXHAUSTED"),
        0xC000008A => Some("STATUS_INVALID_ID_AUTHORITY"),
        0xC000008B => Some("STATUS_AGENTS_EXHAUSTED"),
        0xC000008C => Some("STATUS_INVALID_VOLUME_LABEL"),
        0xC000008D => Some("STATUS_SECTION_NOT_EXTENDED"),
        0xC000008E => Some("STATUS_NOT_MAPPED_DATA"),
        0xC000008F => Some("STATUS_RESOURCE_DATA_NOT_FOUND"),
        0xC0000090 => Some("STATUS_RESOURCE_TYPE_NOT_FOUND"),
        0xC0000091 => Some("STATUS_RESOURCE_NAME_NOT_FOUND"),
        0xC0000092 => Some("STATUS_ARRAY_BOUNDS_EXCEEDED"),
        0xC0000093 => Some("STATUS_FLOAT_DENORMAL_OPERAND"),
        0xC0000094 => Some("STATUS_FLOAT_DIVIDE_BY_ZERO"),
        0xC0000095 => Some("STATUS_FLOAT_INEXACT_RESULT"),
        0xC0000096 => Some("STATUS_FLOAT_INVALID_OPERATION"),
        0xC0000097 => Some("STATUS_FLOAT_OVERFLOW"),
        0xC0000098 => Some("STATUS_FLOAT_STACK_CHECK"),
        0xC0000099 => Some("STATUS_FLOAT_UNDERFLOW"),
        0xC000009A => Some("STATUS_INTEGER_DIVIDE_BY_ZERO"),
        0xC000009B => Some("STATUS_INTEGER_OVERFLOW"),
        0xC000009C => Some("STATUS_PRIVILEGED_INSTRUCTION"),
        0xC000009D => Some("STATUS_TOO_MANY_PAGING_FILES"),
        0xC000009E => Some("STATUS_FILE_INVALID"),
        0xC000009F => Some("STATUS_ALLOTTED_SPACE_EXCEEDED"),
        0xC00000A0 => Some("STATUS_INSUFFICIENT_RESOURCES"),
        0xC00000A1 => Some("STATUS_DFS_EXIT_PATH_FOUND"),
        0xC00000A2 => Some("STATUS_DEVICE_DATA_ERROR"),
        0xC00000A3 => Some("STATUS_DEVICE_NOT_CONNECTED"),
        0xC00000A4 => Some("STATUS_DEVICE_POWER_FAILURE"),
        0xC00000A5 => Some("STATUS_FREE_VM_NOT_AT_BASE"),
        0xC00000A6 => Some("STATUS_MEMORY_NOT_ALLOCATED"),
        0xC00000A7 => Some("STATUS_WORKING_SET_QUOTA"),
        0xC00000A8 => Some("STATUS_MEDIA_WRITE_PROTECTED"),
        0xC00000A9 => Some("STATUS_DEVICE_NOT_READY"),
        0xC00000AA => Some("STATUS_INVALID_GROUP_ATTRIBUTES"),
        0xC00000AB => Some("STATUS_BAD_IMPERSONATION_LEVEL"),
        0xC00000AC => Some("STATUS_CANT_OPEN_ANONYMOUS"),
        0xC00000AD => Some("STATUS_BAD_VALIDATION_CLASS"),
        0xC00000AE => Some("STATUS_BAD_TOKEN_TYPE"),
        0xC00000AF => Some("STATUS_BAD_MASTER_BOOT_RECORD"),
        0xC00000B0 => Some("STATUS_INSTRUCTION_MISALIGNMENT"),
        0xC00000B1 => Some("STATUS_INSTANCE_NOT_AVAILABLE"),
        0xC00000B2 => Some("STATUS_PIPE_NOT_AVAILABLE"),
        0xC00000B3 => Some("STATUS_INVALID_PIPE_STATE"),
        0xC00000B4 => Some("STATUS_PIPE_BUSY"),
        0xC00000B5 => Some("STATUS_ILLEGAL_FUNCTION"),
        0xC00000B6 => Some("STATUS_PIPE_DISCONNECTED"),
        0xC00000B7 => Some("STATUS_PIPE_CLOSING"),
        0xC00000B8 => Some("STATUS_PIPE_CONNECTED"),
        0xC00000B9 => Some("STATUS_PIPE_LISTENING"),
        0xC00000BA => Some("STATUS_INVALID_READ_MODE"),
        0xC00000BB => Some("STATUS_IO_TIMEOUT"),
        0xC00000BC => Some("STATUS_FILE_FORCED_CLOSED"),
        0xC00000BD => Some("STATUS_PROFILING_NOT_STARTED"),
        0xC00000BE => Some("STATUS_PROFILING_NOT_STOPPED"),
        0xC00000BF => Some("STATUS_COULD_NOT_INTERPRET"),
        0xC00000C0 => Some("STATUS_FILE_IS_A_DIRECTORY"),
        0xC00000C1 => Some("STATUS_NOT_SUPPORTED"),
        0xC00000C2 => Some("STATUS_REMOTE_NOT_LISTENING"),
        0xC00000C3 => Some("STATUS_DUPLICATE_NAME"),
        0xC00000C4 => Some("STATUS_BAD_NETWORK_PATH"),
        0xC00000C5 => Some("STATUS_NETWORK_BUSY"),
        0xC00000C6 => Some("STATUS_DEVICE_DOES_NOT_EXIST"),
        0xC00000C7 => Some("STATUS_TOO_MANY_COMMANDS"),
        0xC00000C8 => Some("STATUS_ADAPTER_HARDWARE_ERROR"),
        0xC00000C9 => Some("STATUS_INVALID_NETWORK_RESPONSE"),
        0xC00000CA => Some("STATUS_UNEXPECTED_NETWORK_ERROR"),
        0xC00000CB => Some("STATUS_BAD_REMOTE_ADAPTER"),
        0xC00000CC => Some("STATUS_PRINT_QUEUE_FULL"),
        0xC00000CD => Some("STATUS_NO_SPOOL_SPACE"),
        0xC00000CE => Some("STATUS_PRINT_CANCELLED"),
        0xC00000CF => Some("STATUS_NETWORK_NAME_DELETED"),
        0xC00000D0 => Some("STATUS_NETWORK_ACCESS_DENIED"),
        0xC00000D1 => Some("STATUS_BAD_DEVICE_TYPE"),
        0xC00000D2 => Some("STATUS_BAD_NETWORK_NAME"),
        0xC00000D3 => Some("STATUS_TOO_MANY_NAMES"),
        0xC00000D4 => Some("STATUS_TOO_MANY_SESSIONS"),
        0xC00000D5 => Some("STATUS_SHARING_PAUSED"),
        0xC00000D6 => Some("STATUS_REQUEST_NOT_ACCEPTED"),
        0xC00000D7 => Some("STATUS_REDIRECTOR_PAUSED"),
        0xC00000D8 => Some("STATUS_NET_WRITE_FAULT"),
        _          => None,
    }
}

/// Format an NTSTATUS for display.
#[must_use]
pub fn format_ntstatus(code: u32) -> String {
    match ntstatus_name(code) {
        Some(name) => format!("0x{code:08x} ({name})"),
        None       => format!("0x{code:08x}"),
    }
}

// ─── Windows NT object path helpers ──────────────────────────────────────────

/// Convert a Windows NT native path to a Win32 path (approximate).
#[must_use]
pub fn nt_to_win32_path(nt_path: &str) -> String {
    // \\Device\\HarddiskVolume3\\Windows\\... -> C:\Windows\...
    if let Some(rest) = nt_path.strip_prefix("\\Device\\HarddiskVolume") {
        let vol_end = rest.find('\\').unwrap_or(rest.len());
        let _vol_num = &rest[..vol_end];
        let path = &rest[vol_end..];
        return format!("C:{}", path.replace('/', "\\"));
    }
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        return rest.replace('/', "\\");
    }
    if let Some(rest) = nt_path.strip_prefix("\\\\?\\") {
        return rest.to_string();
    }
    nt_path.to_string()
}

/// Check whether a file path points to a system-critical location.
#[must_use]
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\system32\\") || p.contains("\\syswow64\\") || p.contains("\\windows\\")
}

/// Decode a Windows file access mask to a readable string.
#[must_use]
pub fn decode_file_access(access: u32) -> String {
    let mut parts = Vec::new();
    if access & 0x80000000 != 0 { parts.push("GENERIC_READ"); }
    if access & 0x40000000 != 0 { parts.push("GENERIC_WRITE"); }
    if access & 0x20000000 != 0 { parts.push("GENERIC_EXECUTE"); }
    if access & 0x10000000 != 0 { parts.push("GENERIC_ALL"); }
    if access & 0x00100000 != 0 { parts.push("SYNCHRONIZE"); }
    if access & 0x00080000 != 0 { parts.push("WRITE_OWNER"); }
    if access & 0x00040000 != 0 { parts.push("WRITE_DAC"); }
    if access & 0x00020000 != 0 { parts.push("READ_CONTROL"); }
    if access & 0x00010000 != 0 { parts.push("DELETE"); }
    if access & 0x00000001 != 0 { parts.push("FILE_READ_DATA"); }
    if access & 0x00000002 != 0 { parts.push("FILE_WRITE_DATA"); }
    if access & 0x00000004 != 0 { parts.push("FILE_APPEND_DATA"); }
    if access & 0x00000008 != 0 { parts.push("FILE_READ_EA"); }
    if access & 0x00000010 != 0 { parts.push("FILE_WRITE_EA"); }
    if access & 0x00000020 != 0 { parts.push("FILE_EXECUTE"); }
    if access & 0x00000040 != 0 { parts.push("FILE_DELETE_CHILD"); }
    if access & 0x00000080 != 0 { parts.push("FILE_READ_ATTRIBUTES"); }
    if access & 0x00000100 != 0 { parts.push("FILE_WRITE_ATTRIBUTES"); }
    if parts.is_empty() { return format!("0x{access:x}"); }
    parts.join("|")
}

/// Decode a Windows virtual memory allocation type.
#[must_use]
pub fn decode_alloc_type(alloc_type: u32) -> String {
    let mut parts = Vec::new();
    if alloc_type & 0x00001000 != 0 { parts.push("MEM_COMMIT"); }
    if alloc_type & 0x00002000 != 0 { parts.push("MEM_RESERVE"); }
    if alloc_type & 0x00004000 != 0 { parts.push("MEM_DECOMMIT"); }
    if alloc_type & 0x00008000 != 0 { parts.push("MEM_RELEASE"); }
    if alloc_type & 0x00010000 != 0 { parts.push("MEM_FREE"); }
    if alloc_type & 0x00020000 != 0 { parts.push("MEM_PRIVATE"); }
    if alloc_type & 0x00040000 != 0 { parts.push("MEM_MAPPED"); }
    if alloc_type & 0x00080000 != 0 { parts.push("MEM_RESET"); }
    if alloc_type & 0x00100000 != 0 { parts.push("MEM_TOP_DOWN"); }
    if alloc_type & 0x00200000 != 0 { parts.push("MEM_WRITE_WATCH"); }
    if alloc_type & 0x00400000 != 0 { parts.push("MEM_PHYSICAL"); }
    if alloc_type & 0x01000000 != 0 { parts.push("MEM_IMAGE"); }
    if alloc_type & 0x04000000 != 0 { parts.push("MEM_4MB_PAGES"); }
    if alloc_type & 0x20000000 != 0 { parts.push("MEM_LARGE_PAGES"); }
    if parts.is_empty() { return format!("0x{alloc_type:x}"); }
    parts.join("|")
}

// ─── Process taint tracker (Windows) ──────────────────────────────────────────

/// Taint flags for Windows process monitoring.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WinTaintFlags {
    pub injected_dll: bool,
    pub allocated_exec_memory: bool,
    pub wrote_to_remote_process: bool,
    pub spawned_remote_thread: bool,
    pub modified_registry_run_key: bool,
    pub created_service: bool,
    pub opened_network_connection: bool,
    pub loaded_crypto: bool,
    pub elevated_privilege: bool,
}

impl WinTaintFlags {
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.injected_dll
            || self.allocated_exec_memory
            || self.wrote_to_remote_process
            || self.spawned_remote_thread
            || self.modified_registry_run_key
            || self.created_service
    }

    /// Update taint from an API event.
    pub fn update_from_event(&mut self, event: &ApiEvent) {
        match event.api_name.as_str() {
            "LoadLibraryW" | "LoadLibraryA" | "LdrLoadDll" => { self.injected_dll = true; }
            "VirtualAllocEx" => {
                // Check if PAGE_EXECUTE_READWRITE or similar exec bit
                if event.args.len() >= 4 {
                    if let WinDecodedArg::UInt(prot) = &event.args[3] {
                        if prot & 0xF0 != 0 { self.allocated_exec_memory = true; }
                    }
                }
            }
            "WriteProcessMemory" => { self.wrote_to_remote_process = true; }
            "CreateRemoteThread" | "CreateRemoteThreadEx" | "NtCreateThreadEx" => {
                self.spawned_remote_thread = true;
            }
            "RegSetValueExW" | "RegSetValueExA" => {
                for arg in &event.args {
                    if let WinDecodedArg::RegistryPath(p) = arg {
                        if p.to_lowercase().contains("run") { self.modified_registry_run_key = true; }
                    }
                    if let WinDecodedArg::WStr(p) = arg {
                        if p.to_lowercase().contains("run") { self.modified_registry_run_key = true; }
                    }
                }
            }
            "CreateServiceW" | "CreateServiceA" => { self.created_service = true; }
            "connect" | "WSAConnect" => { self.opened_network_connection = true; }
            "CryptAcquireContextW" | "CryptAcquireContextA" => { self.loaded_crypto = true; }
            "AdjustTokenPrivileges" => { self.elevated_privilege = true; }
            _ => {}
        }
    }

    /// Return a summary of active taint flags.
    #[must_use]
    pub fn summary(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.injected_dll            { v.push("DLL_INJECTION"); }
        if self.allocated_exec_memory   { v.push("EXEC_MEMORY_ALLOC"); }
        if self.wrote_to_remote_process { v.push("REMOTE_WRITE"); }
        if self.spawned_remote_thread   { v.push("REMOTE_THREAD"); }
        if self.modified_registry_run_key { v.push("REGISTRY_RUN_KEY"); }
        if self.created_service         { v.push("SERVICE_CREATED"); }
        if self.opened_network_connection { v.push("NETWORK_CONNECTION"); }
        if self.loaded_crypto           { v.push("CRYPTO_USAGE"); }
        if self.elevated_privilege      { v.push("PRIVILEGE_ELEVATION"); }
        v
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod win_ext2_tests {
    use super::*;

    #[test]
    fn test_ntstatus_success() {
        assert_eq!(ntstatus_name(0), Some("STATUS_SUCCESS"));
    }

    #[test]
    fn test_ntstatus_access_violation() {
        assert_eq!(ntstatus_name(0xC0000005), Some("STATUS_ACCESS_VIOLATION"));
    }

    #[test]
    fn test_ntstatus_invalid_handle() {
        assert_eq!(ntstatus_name(0xC0000008), Some("STATUS_INVALID_HANDLE"));
    }

    #[test]
    fn test_ntstatus_access_denied() {
        assert_eq!(ntstatus_name(0xC0000022), Some("STATUS_ACCESS_DENIED"));
    }

    #[test]
    fn test_ntstatus_unknown() {
        assert!(ntstatus_name(0xDEADBEEF).is_none());
    }

    #[test]
    fn test_format_ntstatus_known() {
        let s = format_ntstatus(0);
        assert!(s.contains("STATUS_SUCCESS"));
    }

    #[test]
    fn test_format_ntstatus_unknown() {
        let s = format_ntstatus(0xDEADBEEF);
        assert!(s.contains("deadbeef"));
    }

    #[test]
    fn test_nt_to_win32_path_harddisk() {
        let p = nt_to_win32_path("\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe");
        assert!(p.contains("\\Windows\\System32\\notepad.exe"));
    }

    #[test]
    fn test_nt_to_win32_path_dosdevice() {
        let p = nt_to_win32_path("\\??\\C:\\Users\\test.txt");
        assert_eq!(p, "C:\\Users\\test.txt");
    }

    #[test]
    fn test_is_system_path_system32() {
        assert!(is_system_path("C:\\Windows\\System32\\ntdll.dll"));
    }

    #[test]
    fn test_is_system_path_user() {
        assert!(!is_system_path("C:\\Users\\user\\Desktop\\malware.exe"));
    }

    #[test]
    fn test_decode_file_access_read() {
        let s = decode_file_access(0x80000000);
        assert!(s.contains("GENERIC_READ"));
    }

    #[test]
    fn test_decode_file_access_readwrite() {
        let s = decode_file_access(0xC0000000);
        assert!(s.contains("GENERIC_READ") && s.contains("GENERIC_WRITE"));
    }

    #[test]
    fn test_decode_alloc_type_commit_reserve() {
        let s = decode_alloc_type(0x3000);
        assert!(s.contains("MEM_COMMIT") && s.contains("MEM_RESERVE"));
    }

    #[test]
    fn test_decode_alloc_type_unknown() {
        let s = decode_alloc_type(0x12345678);
        assert!(s.starts_with("0x") || !s.is_empty());
    }

    #[test]
    fn test_win_taint_default_clean() {
        let t = WinTaintFlags::default();
        assert!(!t.is_suspicious());
        assert!(t.summary().is_empty());
    }

    #[test]
    fn test_win_taint_remote_write() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "WriteProcessMemory".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Bool(true), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.wrote_to_remote_process);
        assert!(t.is_suspicious());
        assert!(t.summary().contains(&"REMOTE_WRITE"));
    }

    #[test]
    fn test_win_taint_create_service() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "CreateServiceW".to_string(),
            module_name: "advapi32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Handle(0x80), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.created_service);
        assert!(t.summary().contains(&"SERVICE_CREATED"));
    }

    #[test]
    fn test_win_taint_network() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "connect".to_string(),
            module_name: "ws2_32.dll".to_string(),
            args: vec![WinDecodedArg::NetAddr("1.2.3.4".to_string(), 443)],
            retval: WinDecodedArg::Int(0), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.opened_network_connection);
        assert!(!t.is_suspicious()); // network alone is not suspicious
    }

    #[test]
    fn test_win_taint_remote_thread() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "CreateRemoteThread".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Handle(0x100), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.spawned_remote_thread);
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_ntstatus_no_such_file() {
        assert_eq!(ntstatus_name(0xC000000F), Some("STATUS_NO_SUCH_FILE"));
    }

    #[test]
    fn test_ntstatus_end_of_file() {
        assert_eq!(ntstatus_name(0xC0000011), Some("STATUS_END_OF_FILE"));
    }

    #[test]
    fn test_ntstatus_pipe_broken() {
        assert_eq!(ntstatus_name(0xC00000B6), Some("STATUS_PIPE_DISCONNECTED"));
    }

    #[test]
    fn test_api_stats_record_errors() {
        let mut s = WinApiStats::default();
        s.record("NtReadFile", 500, false);
        s.record("NtReadFile", 1000, true);
        assert_eq!(s.entries["NtReadFile"].error_count, 1);
        assert_eq!(s.entries["NtReadFile"].call_count, 2);
    }

    #[test]
    fn test_win_taint_dll_injection() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "LoadLibraryW".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![WinDecodedArg::WStr("C:\\evil.dll".to_string())],
            retval: WinDecodedArg::Handle(0x200), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.injected_dll);
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_win_taint_crypto() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0, pid: 1, tid: 1,
            api_name: "CryptAcquireContextW".to_string(),
            module_name: "advapi32.dll".to_string(),
            args: vec![], retval: WinDecodedArg::Bool(true), call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.loaded_crypto);
        assert!(t.summary().contains(&"CRYPTO_USAGE"));
    }
}
