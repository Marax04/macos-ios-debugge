//! Windows kernel data structures with precise field offsets for memory analysis.
//!
//! This module provides Rust representations of the core Windows kernel data
//! structures (_EPROCESS, _ETHREAD, _KTHREAD, _PEB, _`LDR_DATA_TABLE_ENTRY`,
//! _`RTL_USER_PROCESS_PARAMETERS`, _`VAD_NODE`, _`MMVAD_FLAGS`, _TOKEN, etc.) with
//! correct 64-bit offsets for Windows 10 x64.  Each struct carries offset
//! constants so that callers can index directly into raw memory dumps without
//! needing PDB symbols.
//!
//! Offsets are taken from the Windows 10 x64 public PDB for build 19041 (20H1)
//! unless otherwise noted.  Win7 / Win8.1 / Win11 variants are provided as
//! separate constant sets.

use crate::casts::{u64_to_i32, u64_to_u32};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a `u64` from a raw byte buffer at the given offset, returning `None` if
/// the buffer is too short.
#[inline]
pub fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    buf.get(offset..end).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes)
}

/// Read a `u32` from a raw byte buffer at the given offset.
#[inline]
pub fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    buf.get(offset..end).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

/// Read a `u16` from a raw byte buffer at the given offset.
#[inline]
pub fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    buf.get(offset..end).and_then(|s| s.try_into().ok()).map(u16::from_le_bytes)
}

/// Read a single `u8` from a raw byte buffer at the given offset.
#[inline]
#[must_use] 
pub fn read_u8(buf: &[u8], offset: usize) -> Option<u8> {
    buf.get(offset).copied()
}

/// Read a null-terminated ASCII/ANSI string from a raw byte buffer.
#[must_use]
pub fn read_ansi_string(buf: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(buf.len());
    let slice = &buf[offset.min(buf.len())..end];
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..len]).into_owned()
}

// ===========================================================================
// _EPROCESS offsets — Windows 10 x64 (build 19041)
// ===========================================================================

/// `_EPROCESS.DirectoryTableBase` — CR3 value / page-table base.
pub const EPROCESS_DIRECTORY_TABLE_BASE_OFFSET: usize = 0x028;
/// `_EPROCESS.p_ImageFilePointer` (pointer to `FILE_OBJECT` for image).
pub const EPROCESS_IMAGE_FILE_POINTER_OFFSET: usize = 0x570;
/// `_EPROCESS.UniqueProcessId` (kernel handle, same as PID).
pub const EPROCESS_UNIQUE_PROCESS_ID_OFFSET: usize = 0x2E8;
/// `_EPROCESS.ActiveProcessLinks` (`LIST_ENTRY` linking all EPROCESSes).
pub const EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x2F0;
/// `_EPROCESS.RundownProtect` (`EX_RUNDOWN_REF`).
pub const EPROCESS_RUNDOWN_PROTECT_OFFSET: usize = 0x300;
/// `_EPROCESS.Flags` (process flags bit-field).
pub const EPROCESS_FLAGS_OFFSET: usize = 0x308;
/// `_EPROCESS.Flags2` (second flags bit-field).
pub const EPROCESS_FLAGS2_OFFSET: usize = 0x30C;
/// `_EPROCESS.ExitStatus` (NTSTATUS; `STATUS_PENDING` while alive).
pub const EPROCESS_EXIT_STATUS_OFFSET: usize = 0x47C;
/// `_EPROCESS.CreateTime` (`LARGE_INTEGER`; 100-ns ticks since 1601-01-01).
pub const EPROCESS_CREATE_TIME_OFFSET: usize = 0x2C8;
/// `_EPROCESS.ExitTime` (`LARGE_INTEGER`).
pub const EPROCESS_EXIT_TIME_OFFSET: usize = 0x2D0;
/// `_EPROCESS.ActiveThreads` (count of active threads).
pub const EPROCESS_ACTIVE_THREADS_OFFSET: usize = 0x5F0;
/// `_EPROCESS.ImagePathHash` (hash of the image path).
pub const EPROCESS_IMAGE_PATH_HASH_OFFSET: usize = 0x47C;
/// `_EPROCESS.InheritedFromUniqueProcessId` (parent PID kernel handle).
pub const EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET: usize = 0x3E8;
/// `_EPROCESS.ImageFileName[15]` (short image name, null-terminated ANSI).
pub const EPROCESS_IMAGE_FILE_NAME_OFFSET: usize = 0x450;
/// `_EPROCESS.Peb` (pointer to _PEB in user space).
pub const EPROCESS_PEB_OFFSET: usize = 0x550;
/// `_EPROCESS.VadRoot` (pointer to root of the VAD red-black tree).
pub const EPROCESS_VAD_ROOT_OFFSET: usize = 0x7D8;
/// `_EPROCESS.ObjectTable` (pointer to _`HANDLE_TABLE`).
pub const EPROCESS_OBJECT_TABLE_OFFSET: usize = 0x570;
/// `_EPROCESS.Token` (`EX_FAST_REF` to security token).
pub const EPROCESS_TOKEN_OFFSET: usize = 0x4B8;
/// `_EPROCESS.WorkingSetPage` (page-frame number of working-set list).
pub const EPROCESS_WORKING_SET_PAGE_OFFSET: usize = 0x418;
/// `_EPROCESS.SectionBaseAddress` (base address of the mapped image section).
pub const EPROCESS_SECTION_BASE_ADDRESS_OFFSET: usize = 0x520;
/// `_EPROCESS.Win32Process` (per-session Win32k PPROCESSINFO, or NULL).
pub const EPROCESS_WIN32_PROCESS_OFFSET: usize = 0x850;
/// `_EPROCESS.Session` (pointer to _`MM_SESSION_SPACE`).
pub const EPROCESS_SESSION_OFFSET: usize = 0x848;

// Win7 x64 variants
pub const EPROCESS_WIN7_UNIQUE_PROCESS_ID_OFFSET: usize = 0x180;
pub const EPROCESS_WIN7_ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x188;
pub const EPROCESS_WIN7_IMAGE_FILE_NAME_OFFSET: usize = 0x2D0;
pub const EPROCESS_WIN7_PEB_OFFSET: usize = 0x338;
pub const EPROCESS_WIN7_VAD_ROOT_OFFSET: usize = 0x448;
pub const EPROCESS_WIN7_TOKEN_OFFSET: usize = 0x208;
pub const EPROCESS_WIN7_OBJECT_TABLE_OFFSET: usize = 0x200;
pub const EPROCESS_WIN7_CREATE_TIME_OFFSET: usize = 0x148;
pub const EPROCESS_WIN7_EXIT_TIME_OFFSET: usize = 0x150;

// Win8.1 x64 variants
pub const EPROCESS_WIN81_UNIQUE_PROCESS_ID_OFFSET: usize = 0x2E0;
pub const EPROCESS_WIN81_ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x2E8;
pub const EPROCESS_WIN81_IMAGE_FILE_NAME_OFFSET: usize = 0x438;
pub const EPROCESS_WIN81_PEB_OFFSET: usize = 0x538;
pub const EPROCESS_WIN81_VAD_ROOT_OFFSET: usize = 0x5D8;

// Win11 x64 variants (build 22000+)
pub const EPROCESS_WIN11_UNIQUE_PROCESS_ID_OFFSET: usize = 0x440;
pub const EPROCESS_WIN11_ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x448;
pub const EPROCESS_WIN11_IMAGE_FILE_NAME_OFFSET: usize = 0x5A8;
pub const EPROCESS_WIN11_PEB_OFFSET: usize = 0x6A0;
pub const EPROCESS_WIN11_VAD_ROOT_OFFSET: usize = 0x7D8;

/// High-level parsed representation of an `_EPROCESS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EProcess {
    /// Virtual address of this EPROCESS in kernel space.
    pub address: u64,
    /// Process ID (`UniqueProcessId`).
    pub pid: u32,
    /// Parent process ID (`InheritedFromUniqueProcessId`).
    pub ppid: u32,
    /// Short image name (up to 15 chars, ANSI).
    pub image_file_name: String,
    /// Virtual address of the PEB (in user space).
    pub peb: u64,
    /// Virtual address of the VAD root node.
    pub vad_root: u64,
    /// Pointer to the `HANDLE_TABLE`.
    pub object_table: u64,
    /// `EX_FAST_REF` to the security token.
    pub token: u64,
    /// Process creation time (FILETIME / 100-ns intervals since 1601).
    pub create_time: u64,
    /// Process exit time (0 if still running).
    pub exit_time: u64,
    /// Number of active threads.
    pub active_threads: u32,
    /// Exit status (`STATUS_PENDING` = 0x103 while alive).
    pub exit_status: i32,
    /// Virtual base address of the mapped section (image base).
    pub section_base_address: u64,
    /// Pointer to the Win32 process (W32PROCESS), or 0.
    pub win32_process: u64,
    /// Pointer to the session space.
    pub session: u64,
    /// CR3 / directory table base (page-table root).
    pub directory_table_base: u64,
    /// Forward/backward links (Flink/Blink of `ActiveProcessLinks`).
    pub active_process_links_flink: u64,
    pub active_process_links_blink: u64,
}

impl EProcess {
    /// Parse an `_EPROCESS` from a raw byte buffer, using Win10 x64 offsets.
    #[must_use]
    pub fn parse_win10(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            pid: u64_to_u32(read_u64(buf, EPROCESS_UNIQUE_PROCESS_ID_OFFSET)?),
            ppid: u64_to_u32(read_u64(buf, EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET)?),
            image_file_name: read_ansi_string(buf, EPROCESS_IMAGE_FILE_NAME_OFFSET, 15),
            peb: read_u64(buf, EPROCESS_PEB_OFFSET)?,
            vad_root: read_u64(buf, EPROCESS_VAD_ROOT_OFFSET)?,
            object_table: read_u64(buf, EPROCESS_OBJECT_TABLE_OFFSET)?,
            token: read_u64(buf, EPROCESS_TOKEN_OFFSET)?,
            create_time: read_u64(buf, EPROCESS_CREATE_TIME_OFFSET)?,
            exit_time: read_u64(buf, EPROCESS_EXIT_TIME_OFFSET).unwrap_or(0),
            active_threads: read_u32(buf, EPROCESS_ACTIVE_THREADS_OFFSET).unwrap_or(0),
            exit_status: read_u32(buf, EPROCESS_EXIT_STATUS_OFFSET).unwrap_or(0x103).cast_signed(),
            section_base_address: read_u64(buf, EPROCESS_SECTION_BASE_ADDRESS_OFFSET)
                .unwrap_or(0),
            win32_process: read_u64(buf, EPROCESS_WIN32_PROCESS_OFFSET).unwrap_or(0),
            session: read_u64(buf, EPROCESS_SESSION_OFFSET).unwrap_or(0),
            directory_table_base: read_u64(buf, EPROCESS_DIRECTORY_TABLE_BASE_OFFSET)?,
            active_process_links_flink: read_u64(buf, EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET)?,
            active_process_links_blink: read_u64(buf, EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET + 8)?,
        })
    }

    /// Returns `true` if the process has already exited.
    #[must_use]
    pub const fn has_exited(&self) -> bool {
        // STATUS_PENDING = 0x103
        self.exit_status != 0x103_i32 && self.exit_time != 0
    }

    /// Returns the token physical pointer (strips the `RefCnt` from `EX_FAST_REF`).
    #[must_use]
    pub const fn token_ptr(&self) -> u64 {
        self.token & !0xF
    }
}

// ===========================================================================
// _ETHREAD offsets — Windows 10 x64
// ===========================================================================

/// `_ETHREAD` starts with the embedded `_KTHREAD` (Tcb).
pub const ETHREAD_TCB_OFFSET: usize = 0x000;
/// `_ETHREAD.Cid` — `CLIENT_ID` (`ProcessId` + `ThreadId`), each 8 bytes on x64.
pub const ETHREAD_CID_OFFSET: usize = 0x3F8;
/// `_ETHREAD.Cid.UniqueProcess` (8 bytes).
pub const ETHREAD_CID_PROCESS_OFFSET: usize = 0x3F8;
/// `_ETHREAD.Cid.UniqueThread` (8 bytes).
pub const ETHREAD_CID_THREAD_OFFSET: usize = 0x400;
/// `_ETHREAD.Win32StartAddress` (user-mode start address).
pub const ETHREAD_WIN32_START_ADDRESS_OFFSET: usize = 0x450;
/// `_ETHREAD.ThreadListEntry` (`LIST_ENTRY` in process thread list).
pub const ETHREAD_THREAD_LIST_ENTRY_OFFSET: usize = 0x4E8;
/// `_ETHREAD.CreateTime` (`LARGE_INTEGER`, 100-ns ticks).
pub const ETHREAD_CREATE_TIME_OFFSET: usize = 0x2C8;
/// `_ETHREAD.ExitTime` (`LARGE_INTEGER`).
pub const ETHREAD_EXIT_TIME_OFFSET: usize = 0x2D0;
/// `_ETHREAD.ExitStatus` (NTSTATUS).
pub const ETHREAD_EXIT_STATUS_OFFSET: usize = 0x468;
/// `_ETHREAD.LpcReceivedMsgIdValid` (flag).
pub const ETHREAD_LPC_RECEIVED_MSG_ID_VALID_OFFSET: usize = 0x47C;
/// `_ETHREAD.GrantedAccess` (`ACCESS_MASK` for the thread object).
pub const ETHREAD_GRANTED_ACCESS_OFFSET: usize = 0x080;

// Win7 x64 variants
pub const ETHREAD_WIN7_CID_OFFSET: usize = 0x3B0;
pub const ETHREAD_WIN7_WIN32_START_ADDRESS_OFFSET: usize = 0x3F8;
pub const ETHREAD_WIN7_CREATE_TIME_OFFSET: usize = 0x200;

/// Parsed representation of an `_ETHREAD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EThread {
    pub address: u64,
    pub pid: u32,
    pub tid: u32,
    pub win32_start_address: u64,
    pub create_time: u64,
    pub exit_time: u64,
    pub exit_status: i32,
    pub granted_access: u32,
    pub thread_list_flink: u64,
    pub thread_list_blink: u64,
}

impl EThread {
    #[must_use]
    pub fn parse_win10(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            pid: u64_to_u32(read_u64(buf, ETHREAD_CID_PROCESS_OFFSET)?),
            tid: u64_to_u32(read_u64(buf, ETHREAD_CID_THREAD_OFFSET)?),
            win32_start_address: read_u64(buf, ETHREAD_WIN32_START_ADDRESS_OFFSET)?,
            create_time: read_u64(buf, ETHREAD_CREATE_TIME_OFFSET).unwrap_or(0),
            exit_time: read_u64(buf, ETHREAD_EXIT_TIME_OFFSET).unwrap_or(0),
            exit_status: read_u32(buf, ETHREAD_EXIT_STATUS_OFFSET).unwrap_or(0x103).cast_signed(),
            granted_access: read_u32(buf, ETHREAD_GRANTED_ACCESS_OFFSET).unwrap_or(0),
            thread_list_flink: read_u64(buf, ETHREAD_THREAD_LIST_ENTRY_OFFSET).unwrap_or(0),
            thread_list_blink: read_u64(buf, ETHREAD_THREAD_LIST_ENTRY_OFFSET + 8).unwrap_or(0),
        })
    }
}

// ===========================================================================
// _KTHREAD offsets — Windows 10 x64
// ===========================================================================

/// `_KTHREAD.Header` — `DISPATCHER_HEADER` (24 bytes).
pub const KTHREAD_HEADER_OFFSET: usize = 0x000;
/// `_KTHREAD.InitialStack` — top of the kernel stack.
pub const KTHREAD_INITIAL_STACK_OFFSET: usize = 0x028;
/// `_KTHREAD.StackLimit` — bottom guard page of the kernel stack.
pub const KTHREAD_STACK_LIMIT_OFFSET: usize = 0x030;
/// `_KTHREAD.KernelStack` — current kernel stack pointer (RSP/ESP).
pub const KTHREAD_KERNEL_STACK_OFFSET: usize = 0x058;
/// `_KTHREAD.ThreadLock` (`KSPIN_LOCK`).
pub const KTHREAD_THREAD_LOCK_OFFSET: usize = 0x060;
/// `_KTHREAD.CycleTime` (total cycle count).
pub const KTHREAD_CYCLE_TIME_OFFSET: usize = 0x068;
/// `_KTHREAD.CurrentRunTime` (current run-time in 100-ns ticks).
pub const KTHREAD_CURRENT_RUN_TIME_OFFSET: usize = 0x070;
/// `_KTHREAD.ExpectedRunTime`.
pub const KTHREAD_EXPECTED_RUN_TIME_OFFSET: usize = 0x074;
/// `_KTHREAD.KernelTime` (time spent in kernel mode, in clock ticks).
pub const KTHREAD_KERNEL_TIME_OFFSET: usize = 0x1B4;
/// `_KTHREAD.UserTime` (time spent in user mode, in clock ticks).
pub const KTHREAD_USER_TIME_OFFSET: usize = 0x1B8;
/// `_KTHREAD.ReadyTime`.
pub const KTHREAD_READY_TIME_OFFSET: usize = 0x1BC;
/// `_KTHREAD.TrapFrame` (pointer to _`KTRAP_FRAME`, or NULL).
pub const KTHREAD_TRAP_FRAME_OFFSET: usize = 0x090;
/// `_KTHREAD.ApcState` (embedded `KAPC_STATE`, 48 bytes).
pub const KTHREAD_APC_STATE_OFFSET: usize = 0x098;
/// `_KTHREAD.Priority` (current scheduling priority, signed byte).
pub const KTHREAD_PRIORITY_OFFSET: usize = 0x184;
/// `_KTHREAD.BasePriority` (base priority).
pub const KTHREAD_BASE_PRIORITY_OFFSET: usize = 0x185;
/// `_KTHREAD.PriorityDecrement`.
pub const KTHREAD_PRIORITY_DECREMENT_OFFSET: usize = 0x186;
/// `_KTHREAD.AdjustReason` (reason for last priority adjustment).
pub const KTHREAD_ADJUST_REASON_OFFSET: usize = 0x187;
/// `_KTHREAD.Teb` (pointer to the TEB, user-mode accessible).
pub const KTHREAD_TEB_OFFSET: usize = 0x0F0;
/// `_KTHREAD.NpxState` (floating-point state byte).
pub const KTHREAD_NPX_STATE_OFFSET: usize = 0x18C;
/// `_KTHREAD.WaitStatus` (NTSTATUS result of the wait).
pub const KTHREAD_WAIT_STATUS_OFFSET: usize = 0x0C0;
/// `_KTHREAD.WaitBlockList` (pointer to first `KWAIT_BLOCK`).
pub const KTHREAD_WAIT_BLOCK_LIST_OFFSET: usize = 0x0C8;
/// `_KTHREAD.WaitListEntry` (`LIST_ENTRY` in wait-list).
pub const KTHREAD_WAIT_LIST_ENTRY_OFFSET: usize = 0x0D0;
/// `_KTHREAD.ContextSwitches` (total number of context switches).
pub const KTHREAD_CONTEXT_SWITCHES_OFFSET: usize = 0x1C0;
/// `_KTHREAD.State` (thread scheduling state byte, 0..7).
pub const KTHREAD_STATE_OFFSET: usize = 0x188;

/// Parsed `_KTHREAD` inner state.
#[derive(Debug, Clone)]
pub struct KThread {
    pub address: u64,
    pub initial_stack: u64,
    pub stack_limit: u64,
    pub kernel_stack: u64,
    pub teb: u64,
    pub priority: i8,
    pub base_priority: i8,
    pub state: u8,
    pub context_switches: u32,
    pub cycle_time: u64,
    pub kernel_time: u32,
    pub user_time: u32,
    pub trap_frame: u64,
    pub wait_status: i32,
}

impl KThread {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            initial_stack: read_u64(buf, KTHREAD_INITIAL_STACK_OFFSET)?,
            stack_limit: read_u64(buf, KTHREAD_STACK_LIMIT_OFFSET)?,
            kernel_stack: read_u64(buf, KTHREAD_KERNEL_STACK_OFFSET)?,
            teb: read_u64(buf, KTHREAD_TEB_OFFSET)?,
            priority: (read_u8(buf, KTHREAD_PRIORITY_OFFSET)?).cast_signed(),
            base_priority: (read_u8(buf, KTHREAD_BASE_PRIORITY_OFFSET)?).cast_signed(),
            state: read_u8(buf, KTHREAD_STATE_OFFSET)?,
            context_switches: read_u32(buf, KTHREAD_CONTEXT_SWITCHES_OFFSET).unwrap_or(0),
            cycle_time: read_u64(buf, KTHREAD_CYCLE_TIME_OFFSET).unwrap_or(0),
            kernel_time: read_u32(buf, KTHREAD_KERNEL_TIME_OFFSET).unwrap_or(0),
            user_time: read_u32(buf, KTHREAD_USER_TIME_OFFSET).unwrap_or(0),
            trap_frame: read_u64(buf, KTHREAD_TRAP_FRAME_OFFSET).unwrap_or(0),
            wait_status: u64_to_i32(read_u64(buf, KTHREAD_WAIT_STATUS_OFFSET).unwrap_or(0)),
        })
    }

    /// State as a human-readable string.
    #[must_use]
    pub const fn state_str(&self) -> &'static str {
        match self.state {
            0 => "Initialized",
            1 => "Ready",
            2 => "Running",
            3 => "Standby",
            4 => "Terminated",
            5 => "Wait",
            6 => "Transition",
            7 => "DeferredReady",
            _ => "Unknown",
        }
    }
}

// ===========================================================================
// _PEB offsets — Windows 10 x64
// ===========================================================================

pub const PEB_INHERITED_ADDRESS_SPACE_OFFSET: usize = 0x000;
pub const PEB_READ_IMAGE_FILE_EXEC_OPTIONS_OFFSET: usize = 0x001;
pub const PEB_BEING_DEBUGGED_OFFSET: usize = 0x002;
pub const PEB_BIT_FIELD_OFFSET: usize = 0x003;
pub const PEB_MUTANT_OFFSET: usize = 0x008;
pub const PEB_IMAGE_BASE_ADDRESS_OFFSET: usize = 0x010;
pub const PEB_LDR_OFFSET: usize = 0x018;
pub const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x020;
pub const PEB_SUB_SYSTEM_DATA_OFFSET: usize = 0x028;
pub const PEB_PROCESS_HEAP_OFFSET: usize = 0x030;
pub const PEB_FAST_PEB_LOCK_OFFSET: usize = 0x038;
pub const PEB_ATL_THUNK_SLIST_PTR_OFFSET: usize = 0x040;
pub const PEB_IFEO_KEY_OFFSET: usize = 0x048;
pub const PEB_CROSS_PROCESS_FLAGS_OFFSET: usize = 0x050;
pub const PEB_KERNEL_CALLBACK_TABLE_OFFSET: usize = 0x058;
pub const PEB_SYSTEM_RESERVED_OFFSET: usize = 0x060;
pub const PEB_ATL_THUNK_SLIST_PTR32_OFFSET: usize = 0x064;
pub const PEB_API_SET_MAP_OFFSET: usize = 0x068;
pub const PEB_TLS_EXPANSION_COUNTER_OFFSET: usize = 0x070;
pub const PEB_TLS_BITMAP_OFFSET: usize = 0x078;
pub const PEB_TLS_BITMAP_BITS_OFFSET: usize = 0x080;
pub const PEB_READ_ONLY_SHARED_MEMORY_BASE_OFFSET: usize = 0x090;
pub const PEB_HOTPATCH_INFORMATION_OFFSET: usize = 0x098;
pub const PEB_READ_ONLY_STATIC_SERVER_DATA_OFFSET: usize = 0x0A0;
pub const PEB_ANSI_CODE_PAGE_DATA_OFFSET: usize = 0x0A8;
pub const PEB_OEM_CODE_PAGE_DATA_OFFSET: usize = 0x0B0;
pub const PEB_UNICODE_CASE_TABLE_DATA_OFFSET: usize = 0x0B8;
pub const PEB_NUMBER_OF_PROCESSORS_OFFSET: usize = 0x0C0;
pub const PEB_NT_GLOBAL_FLAG_OFFSET: usize = 0x0C4;
pub const PEB_CRITICAL_SECTION_TIMEOUT_OFFSET: usize = 0x0C8;
pub const PEB_HEAP_SEGMENT_RESERVE_OFFSET: usize = 0x0D0;
pub const PEB_HEAP_SEGMENT_COMMIT_OFFSET: usize = 0x0D8;
pub const PEB_HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD_OFFSET: usize = 0x0E0;
pub const PEB_HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD_OFFSET: usize = 0x0E8;
pub const PEB_NUMBER_OF_HEAPS_OFFSET: usize = 0x0F0;
pub const PEB_MAXIMUM_NUMBER_OF_HEAPS_OFFSET: usize = 0x0F4;
pub const PEB_PROCESS_HEAPS_OFFSET: usize = 0x0F8;
pub const PEB_GDI_SHARED_HANDLE_TABLE_OFFSET: usize = 0x100;
pub const PEB_PROCESS_STARTER_HELPER_OFFSET: usize = 0x108;
pub const PEB_GDI_DC_ATTRIBUTE_LIST_OFFSET: usize = 0x110;
pub const PEB_LOADER_LOCK_OFFSET: usize = 0x118;
pub const PEB_OS_MAJOR_VERSION_OFFSET: usize = 0x120;
pub const PEB_OS_MINOR_VERSION_OFFSET: usize = 0x124;
pub const PEB_OS_BUILD_NUMBER_OFFSET: usize = 0x128;
pub const PEB_OS_CSD_VERSION_OFFSET: usize = 0x12A;
pub const PEB_OS_PLATFORM_ID_OFFSET: usize = 0x12C;
pub const PEB_IMAGE_SUBSYSTEM_OFFSET: usize = 0x130;
pub const PEB_IMAGE_SUBSYSTEM_MAJOR_VERSION_OFFSET: usize = 0x134;
pub const PEB_IMAGE_SUBSYSTEM_MINOR_VERSION_OFFSET: usize = 0x138;
pub const PEB_ACTIVE_PROCESS_AFFINITY_MASK_OFFSET: usize = 0x140;
pub const PEB_GDI_HANDLE_BUFFER_OFFSET: usize = 0x148;
pub const PEB_POST_PROCESS_INIT_ROUTINE_OFFSET: usize = 0x230;
pub const PEB_TLS_EXPANSION_BITMAP_OFFSET: usize = 0x238;
pub const PEB_TLS_EXPANSION_BITMAP_BITS_OFFSET: usize = 0x240;
pub const PEB_SESSION_ID_OFFSET: usize = 0x2C0;
pub const PEB_APP_COMPAT_FLAGS_OFFSET: usize = 0x2C8;
pub const PEB_APP_COMPAT_FLAGS_USER_OFFSET: usize = 0x2D0;
pub const PEB_P_SHIM_DATA_OFFSET: usize = 0x2D8;
pub const PEB_APP_COMPAT_INFO_OFFSET: usize = 0x2E0;
pub const PEB_CSD_VERSION_OFFSET: usize = 0x2E8;
pub const PEB_ACTIVATION_CONTEXT_DATA_OFFSET: usize = 0x2F8;
pub const PEB_PROCESS_ASSEMBLY_STORAGE_MAP_OFFSET: usize = 0x300;
pub const PEB_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA_OFFSET: usize = 0x308;
pub const PEB_SYSTEM_ASSEMBLY_STORAGE_MAP_OFFSET: usize = 0x310;
pub const PEB_MINIMUM_STACK_COMMIT_OFFSET: usize = 0x318;
pub const PEB_FLS_CALLBACK_OFFSET: usize = 0x320;
pub const PEB_FLS_LIST_HEAD_OFFSET: usize = 0x328;
pub const PEB_FLS_BITMAP_OFFSET: usize = 0x338;
pub const PEB_FLS_BITMAP_BITS_OFFSET: usize = 0x340;
pub const PEB_FLS_HIGH_INDEX_OFFSET: usize = 0x360;
pub const PEB_WER_REGISTRATION_DATA_OFFSET: usize = 0x368;
pub const PEB_WER_SHIP_ASSERT_PTR_OFFSET: usize = 0x370;
pub const PEB_P_CONTEXT_DATA_OFFSET: usize = 0x378;
pub const PEB_P_IMAGE_HEADER_HASH_OFFSET: usize = 0x380;
pub const PEB_TRACING_FLAGS_OFFSET: usize = 0x388;
pub const PEB_CSR_SERVER_READ_ONLY_SHARED_MEMORY_BASE_OFFSET: usize = 0x390;
pub const PEB_TPP_WORKER_LIST_LOCK_OFFSET: usize = 0x398;
pub const PEB_TPP_WORKER_LIST_OFFSET: usize = 0x3A0;
pub const PEB_WAIT_ON_ADDRESS_HASH_TABLE_OFFSET: usize = 0x3B0;
pub const PEB_TELEMETRY_COVERAGE_HEADER_OFFSET: usize = 0x3D0;
pub const PEB_CLOUD_FILE_FLAGS_OFFSET: usize = 0x3D8;
pub const PEB_CLOUD_FILE_DIAG_FLAGS_OFFSET: usize = 0x3DC;
pub const PEB_PLACEHOLDER_COMPATIBILITY_MODE_OFFSET: usize = 0x3E0;
pub const PEB_PLACEHOLDER_COMPATIBILITY_MODE_RESERVED_OFFSET: usize = 0x3E1;

/// Parsed `_PEB` structure.
#[derive(Debug, Clone)]
pub struct Peb {
    pub address: u64,
    pub being_debugged: bool,
    pub image_base_address: u64,
    pub ldr: u64,
    pub process_parameters: u64,
    pub process_heap: u64,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub session_id: u32,
    pub image_subsystem: u32,
}

impl Peb {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            being_debugged: read_u8(buf, PEB_BEING_DEBUGGED_OFFSET)? != 0,
            image_base_address: read_u64(buf, PEB_IMAGE_BASE_ADDRESS_OFFSET)?,
            ldr: read_u64(buf, PEB_LDR_OFFSET)?,
            process_parameters: read_u64(buf, PEB_PROCESS_PARAMETERS_OFFSET)?,
            process_heap: read_u64(buf, PEB_PROCESS_HEAP_OFFSET)?,
            number_of_processors: read_u32(buf, PEB_NUMBER_OF_PROCESSORS_OFFSET).unwrap_or(1),
            nt_global_flag: read_u32(buf, PEB_NT_GLOBAL_FLAG_OFFSET).unwrap_or(0),
            os_major_version: read_u32(buf, PEB_OS_MAJOR_VERSION_OFFSET).unwrap_or(0),
            os_minor_version: read_u32(buf, PEB_OS_MINOR_VERSION_OFFSET).unwrap_or(0),
            os_build_number: read_u16(buf, PEB_OS_BUILD_NUMBER_OFFSET).unwrap_or(0),
            session_id: read_u32(buf, PEB_SESSION_ID_OFFSET).unwrap_or(0),
            image_subsystem: read_u32(buf, PEB_IMAGE_SUBSYSTEM_OFFSET).unwrap_or(0),
        })
    }
}

// ===========================================================================
// _PEB_LDR_DATA offsets — Windows 10 x64
// ===========================================================================

pub const PEB_LDR_DATA_LENGTH_OFFSET: usize = 0x000;
pub const PEB_LDR_DATA_INITIALIZED_OFFSET: usize = 0x004;
pub const PEB_LDR_DATA_SS_HANDLE_OFFSET: usize = 0x008;
pub const PEB_LDR_DATA_IN_LOAD_ORDER_MODULE_LIST_OFFSET: usize = 0x010;
pub const PEB_LDR_DATA_IN_MEMORY_ORDER_MODULE_LIST_OFFSET: usize = 0x020;
pub const PEB_LDR_DATA_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET: usize = 0x030;
pub const PEB_LDR_DATA_ENTRY_IN_PROGRESS_OFFSET: usize = 0x040;
pub const PEB_LDR_DATA_SHUTDOWN_IN_PROGRESS_OFFSET: usize = 0x048;
pub const PEB_LDR_DATA_SHUTDOWN_THREAD_ID_OFFSET: usize = 0x050;

/// Parsed `_PEB_LDR_DATA`.
#[derive(Debug, Clone)]
pub struct PebLdrData {
    pub address: u64,
    pub length: u32,
    pub initialized: bool,
    pub ss_handle: u64,
    pub in_load_order_module_list_flink: u64,
    pub in_load_order_module_list_blink: u64,
    pub in_memory_order_module_list_flink: u64,
    pub in_memory_order_module_list_blink: u64,
    pub in_init_order_module_list_flink: u64,
    pub in_init_order_module_list_blink: u64,
    pub shutdown_in_progress: bool,
}

impl PebLdrData {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            length: read_u32(buf, PEB_LDR_DATA_LENGTH_OFFSET)?,
            initialized: read_u8(buf, PEB_LDR_DATA_INITIALIZED_OFFSET)? != 0,
            ss_handle: read_u64(buf, PEB_LDR_DATA_SS_HANDLE_OFFSET)?,
            in_load_order_module_list_flink: read_u64(
                buf,
                PEB_LDR_DATA_IN_LOAD_ORDER_MODULE_LIST_OFFSET,
            )?,
            in_load_order_module_list_blink: read_u64(
                buf,
                PEB_LDR_DATA_IN_LOAD_ORDER_MODULE_LIST_OFFSET + 8,
            )?,
            in_memory_order_module_list_flink: read_u64(
                buf,
                PEB_LDR_DATA_IN_MEMORY_ORDER_MODULE_LIST_OFFSET,
            )?,
            in_memory_order_module_list_blink: read_u64(
                buf,
                PEB_LDR_DATA_IN_MEMORY_ORDER_MODULE_LIST_OFFSET + 8,
            )?,
            in_init_order_module_list_flink: read_u64(
                buf,
                PEB_LDR_DATA_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET,
            )?,
            in_init_order_module_list_blink: read_u64(
                buf,
                PEB_LDR_DATA_IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET + 8,
            )?,
            shutdown_in_progress: read_u8(buf, PEB_LDR_DATA_SHUTDOWN_IN_PROGRESS_OFFSET)? != 0,
        })
    }
}

// ===========================================================================
// _LDR_DATA_TABLE_ENTRY offsets — Windows 10 x64
// ===========================================================================

pub const LDR_IN_LOAD_ORDER_LINKS_OFFSET: usize = 0x000;
pub const LDR_IN_MEMORY_ORDER_LINKS_OFFSET: usize = 0x010;
pub const LDR_IN_INITIALIZATION_ORDER_LINKS_OFFSET: usize = 0x020;
pub const LDR_DLL_BASE_OFFSET: usize = 0x030;
pub const LDR_ENTRY_POINT_OFFSET: usize = 0x038;
pub const LDR_SIZE_OF_IMAGE_OFFSET: usize = 0x040;
pub const LDR_FULL_DLL_NAME_OFFSET: usize = 0x048;
pub const LDR_BASE_DLL_NAME_OFFSET: usize = 0x058;
pub const LDR_FLAG_GROUP_OFFSET: usize = 0x068;
pub const LDR_FLAGS_OFFSET: usize = 0x06C;
pub const LDR_LOAD_COUNT_OFFSET: usize = 0x070;
pub const LDR_TLS_INDEX_OFFSET: usize = 0x072;
pub const LDR_HASH_LINKS_OFFSET: usize = 0x078;
pub const LDR_TIME_DATE_STAMP_OFFSET: usize = 0x088;
pub const LDR_ENTRY_POINT_ACTIVATION_CONTEXT_OFFSET: usize = 0x090;
pub const LDR_PATCH_INFORMATION_OFFSET: usize = 0x098;
pub const LDR_FORWARDER_LINKS_OFFSET: usize = 0x0A0;
pub const LDR_SERVICE_TAG_LINKS_OFFSET: usize = 0x0B0;
pub const LDR_STATIC_LINKS_OFFSET: usize = 0x0C0;
pub const LDR_CONTEXT_INFORMATION_OFFSET: usize = 0x0D0;
pub const LDR_ORIGINAL_BASE_OFFSET: usize = 0x0D8;
pub const LDR_LOAD_TIME_OFFSET: usize = 0x0E0;

/// A `_UNICODE_STRING` as it appears embedded in kernel structures.
/// On x64: Length(2) + MaximumLength(2) + pad(4) + Buffer(8) = 16 bytes.
pub const UNICODE_STRING_LENGTH_OFFSET: usize = 0x000;
pub const UNICODE_STRING_MAXIMUM_LENGTH_OFFSET: usize = 0x002;
pub const UNICODE_STRING_BUFFER_OFFSET: usize = 0x008;

/// Parsed `_UNICODE_STRING` header (does not include the string data itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicodeStringHeader {
    /// Current length of the string in bytes (not chars).
    pub length: u16,
    /// Maximum capacity in bytes.
    pub maximum_length: u16,
    /// Pointer to the UTF-16 string buffer.
    pub buffer_ptr: u64,
}

impl UnicodeStringHeader {
    #[must_use]
    pub fn parse(buf: &[u8], offset: usize) -> Option<Self> {
        Some(Self {
            length: read_u16(buf, offset + UNICODE_STRING_LENGTH_OFFSET)?,
            maximum_length: read_u16(buf, offset + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET)?,
            buffer_ptr: read_u64(buf, offset + UNICODE_STRING_BUFFER_OFFSET)?,
        })
    }

    /// Number of UTF-16 code units (chars) in the string.
    #[must_use]
    pub const fn char_count(&self) -> u16 {
        self.length / 2
    }
}

/// Parsed `_LDR_DATA_TABLE_ENTRY`.
#[derive(Debug, Clone)]
pub struct LdrDataTableEntry {
    pub address: u64,
    pub in_load_order_flink: u64,
    pub in_load_order_blink: u64,
    pub in_memory_order_flink: u64,
    pub in_memory_order_blink: u64,
    pub in_init_order_flink: u64,
    pub in_init_order_blink: u64,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeStringHeader,
    pub base_dll_name: UnicodeStringHeader,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub time_date_stamp: u32,
    pub original_base: u64,
    pub load_time: u64,
}

impl LdrDataTableEntry {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            in_load_order_flink: read_u64(buf, LDR_IN_LOAD_ORDER_LINKS_OFFSET)?,
            in_load_order_blink: read_u64(buf, LDR_IN_LOAD_ORDER_LINKS_OFFSET + 8)?,
            in_memory_order_flink: read_u64(buf, LDR_IN_MEMORY_ORDER_LINKS_OFFSET)?,
            in_memory_order_blink: read_u64(buf, LDR_IN_MEMORY_ORDER_LINKS_OFFSET + 8)?,
            in_init_order_flink: read_u64(buf, LDR_IN_INITIALIZATION_ORDER_LINKS_OFFSET)?,
            in_init_order_blink: read_u64(buf, LDR_IN_INITIALIZATION_ORDER_LINKS_OFFSET + 8)?,
            dll_base: read_u64(buf, LDR_DLL_BASE_OFFSET)?,
            entry_point: read_u64(buf, LDR_ENTRY_POINT_OFFSET)?,
            size_of_image: read_u32(buf, LDR_SIZE_OF_IMAGE_OFFSET)?,
            full_dll_name: UnicodeStringHeader::parse(buf, LDR_FULL_DLL_NAME_OFFSET)?,
            base_dll_name: UnicodeStringHeader::parse(buf, LDR_BASE_DLL_NAME_OFFSET)?,
            flags: read_u32(buf, LDR_FLAGS_OFFSET)?,
            load_count: read_u16(buf, LDR_LOAD_COUNT_OFFSET).unwrap_or(0),
            tls_index: read_u16(buf, LDR_TLS_INDEX_OFFSET).unwrap_or(0),
            time_date_stamp: read_u32(buf, LDR_TIME_DATE_STAMP_OFFSET).unwrap_or(0),
            original_base: read_u64(buf, LDR_ORIGINAL_BASE_OFFSET).unwrap_or(0),
            load_time: read_u64(buf, LDR_LOAD_TIME_OFFSET).unwrap_or(0),
        })
    }

    /// Returns `true` if the module is not in the load-order list (hidden/unlinked).
    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.in_load_order_flink == 0
    }
}

// ===========================================================================
// _RTL_USER_PROCESS_PARAMETERS offsets — Windows 10 x64
// ===========================================================================

pub const RTL_PP_MAXIMUM_LENGTH_OFFSET: usize = 0x000;
pub const RTL_PP_LENGTH_OFFSET: usize = 0x004;
pub const RTL_PP_FLAGS_OFFSET: usize = 0x008;
pub const RTL_PP_DEBUG_FLAGS_OFFSET: usize = 0x00C;
pub const RTL_PP_CONSOLE_HANDLE_OFFSET: usize = 0x010;
pub const RTL_PP_CONSOLE_FLAGS_OFFSET: usize = 0x018;
pub const RTL_PP_STANDARD_INPUT_OFFSET: usize = 0x020;
pub const RTL_PP_STANDARD_OUTPUT_OFFSET: usize = 0x028;
pub const RTL_PP_STANDARD_ERROR_OFFSET: usize = 0x030;
pub const RTL_PP_CURRENT_DIRECTORY_OFFSET: usize = 0x038;
pub const RTL_PP_DLL_PATH_OFFSET: usize = 0x050;
pub const RTL_PP_IMAGE_PATH_NAME_OFFSET: usize = 0x060;
pub const RTL_PP_COMMAND_LINE_OFFSET: usize = 0x070;
pub const RTL_PP_ENVIRONMENT_OFFSET: usize = 0x080;
pub const RTL_PP_STARTING_X_OFFSET: usize = 0x088;
pub const RTL_PP_STARTING_Y_OFFSET: usize = 0x08C;
pub const RTL_PP_COUNT_X_OFFSET: usize = 0x090;
pub const RTL_PP_COUNT_Y_OFFSET: usize = 0x094;
pub const RTL_PP_COUNT_CHARS_X_OFFSET: usize = 0x098;
pub const RTL_PP_COUNT_CHARS_Y_OFFSET: usize = 0x09C;
pub const RTL_PP_FILL_ATTRIBUTE_OFFSET: usize = 0x0A0;
pub const RTL_PP_WINDOW_FLAGS_OFFSET: usize = 0x0A4;
pub const RTL_PP_SHOW_WINDOW_FLAGS_OFFSET: usize = 0x0A8;
pub const RTL_PP_WINDOW_TITLE_OFFSET: usize = 0x0B0;
pub const RTL_PP_DESKTOP_INFO_OFFSET: usize = 0x0C0;
pub const RTL_PP_SHELL_INFO_OFFSET: usize = 0x0D0;
pub const RTL_PP_RUNTIME_DATA_OFFSET: usize = 0x0E0;
pub const RTL_PP_CURRENT_DIRECTORIES_OFFSET: usize = 0x0F0;
pub const RTL_PP_ENVIRONMENT_SIZE_OFFSET: usize = 0x3F0;
pub const RTL_PP_ENVIRONMENT_VERSION_OFFSET: usize = 0x3F8;
pub const RTL_PP_PACKAGE_DEPENDENCY_DATA_OFFSET: usize = 0x400;
pub const RTL_PP_PROCESS_GROUP_ID_OFFSET: usize = 0x408;
pub const RTL_PP_LOADER_THREADS_OFFSET: usize = 0x40C;

/// Parsed `_RTL_USER_PROCESS_PARAMETERS`.
#[derive(Debug, Clone)]
pub struct RtlUserProcessParameters {
    pub address: u64,
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: u64,
    pub console_flags: u32,
    pub standard_input: u64,
    pub standard_output: u64,
    pub standard_error: u64,
    pub image_path_name: UnicodeStringHeader,
    pub command_line: UnicodeStringHeader,
    pub environment: u64,
    pub window_title: UnicodeStringHeader,
    pub desktop_info: UnicodeStringHeader,
    pub shell_info: UnicodeStringHeader,
    pub environment_size: u64,
    pub environment_version: u64,
}

impl RtlUserProcessParameters {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            maximum_length: read_u32(buf, RTL_PP_MAXIMUM_LENGTH_OFFSET)?,
            length: read_u32(buf, RTL_PP_LENGTH_OFFSET)?,
            flags: read_u32(buf, RTL_PP_FLAGS_OFFSET)?,
            debug_flags: read_u32(buf, RTL_PP_DEBUG_FLAGS_OFFSET)?,
            console_handle: read_u64(buf, RTL_PP_CONSOLE_HANDLE_OFFSET)?,
            console_flags: read_u32(buf, RTL_PP_CONSOLE_FLAGS_OFFSET).unwrap_or(0),
            standard_input: read_u64(buf, RTL_PP_STANDARD_INPUT_OFFSET)?,
            standard_output: read_u64(buf, RTL_PP_STANDARD_OUTPUT_OFFSET)?,
            standard_error: read_u64(buf, RTL_PP_STANDARD_ERROR_OFFSET)?,
            image_path_name: UnicodeStringHeader::parse(buf, RTL_PP_IMAGE_PATH_NAME_OFFSET)?,
            command_line: UnicodeStringHeader::parse(buf, RTL_PP_COMMAND_LINE_OFFSET)?,
            environment: read_u64(buf, RTL_PP_ENVIRONMENT_OFFSET)?,
            window_title: UnicodeStringHeader::parse(buf, RTL_PP_WINDOW_TITLE_OFFSET)
                .unwrap_or(UnicodeStringHeader { length: 0, maximum_length: 0, buffer_ptr: 0 }),
            desktop_info: UnicodeStringHeader::parse(buf, RTL_PP_DESKTOP_INFO_OFFSET)
                .unwrap_or(UnicodeStringHeader { length: 0, maximum_length: 0, buffer_ptr: 0 }),
            shell_info: UnicodeStringHeader::parse(buf, RTL_PP_SHELL_INFO_OFFSET)
                .unwrap_or(UnicodeStringHeader { length: 0, maximum_length: 0, buffer_ptr: 0 }),
            environment_size: read_u64(buf, RTL_PP_ENVIRONMENT_SIZE_OFFSET).unwrap_or(0),
            environment_version: read_u64(buf, RTL_PP_ENVIRONMENT_VERSION_OFFSET).unwrap_or(0),
        })
    }
}

// ===========================================================================
// _VAD_NODE / _MMVAD offsets — Windows 10 x64
// ===========================================================================

pub const VAD_LEFT_CHILD_OFFSET: usize = 0x000;
pub const VAD_RIGHT_CHILD_OFFSET: usize = 0x008;
pub const VAD_PARENT_VALUE_OFFSET: usize = 0x010;
/// Starting virtual page number (`StartingVpn`), multiply by `PAGE_SIZE` for address.
pub const VAD_STARTING_VPN_OFFSET: usize = 0x018;
/// Ending virtual page number (`EndingVpn`), inclusive.
pub const VAD_ENDING_VPN_OFFSET: usize = 0x020;
pub const VAD_PUSH_LOCK_OFFSET: usize = 0x028;
/// Union containing `VadFlags` (u/Flags).
pub const VAD_FLAGS_OFFSET: usize = 0x030;
/// Pointer to first prototype PTE (u1/FirstPrototypePte).
pub const VAD_FIRST_PROTOTYPE_PTE_OFFSET: usize = 0x038;
pub const VAD_LAST_CONTIGUOUS_PTE_OFFSET: usize = 0x040;
pub const VAD_LIST_LINKS_OFFSET: usize = 0x048;
/// `VadType` field within `VadFlags` union (bits [2:0] in the lower DWORD).
pub const VAD_TYPE_BITS_SHIFT: u32 = 2;
pub const VAD_TYPE_BITS_MASK: u32 = 0x7;
/// Subsection pointer (for mapped files).
pub const VAD_SUBSECTION_OFFSET: usize = 0x058;
/// `ExtendedVpn` fields for large address space (`VpnExtrasHigh`, u2).
pub const VAD_VPN_EXTRAS_HIGH_OFFSET: usize = 0x060;

/// Protection bits within _`MMVAD_FLAGS`.
pub const MMVAD_PROTECTION_SHIFT: u32 = 7;
pub const MMVAD_PROTECTION_MASK: u32 = 0x1F;
/// `CommitCharge` bits.
pub const MMVAD_COMMIT_CHARGE_MASK: u64 = 0x7F_FF_FF_FF_FF_FF_FF;
/// `PrivateMemory` bit (sits immediately above the 5-bit Protection field).
pub const MMVAD_PRIVATE_MEMORY_BIT: u64 = 1 << 21;

/// `_MMVAD_FLAGS` decoded values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmVadFlags {
    pub raw: u64,
    pub commit_charge: u64,
    pub no_change: bool,
    pub vad_type: u8,
    pub mem_commit: bool,
    pub protection: u8,
    pub private_memory: bool,
}

impl MmVadFlags {
    #[must_use]
    pub const fn parse(raw: u64) -> Self {
        Self {
            raw,
            commit_charge: raw & 0x7FF,
            no_change: (raw >> 11) & 1 != 0,
            vad_type: ((raw >> 12) & 0x7) as u8,
            mem_commit: (raw >> 15) & 1 != 0,
            protection: ((raw >> 16) & 0x1F) as u8,
            // PrivateMemory occupies the bit immediately above the 5-bit Protection field.
            private_memory: (raw >> 21) & 1 != 0,
        }
    }

    /// Decode the protection into a human-readable Windows protection constant name.
    #[must_use]
    pub const fn protection_str(&self) -> &'static str {
        match self.protection {
            0x01 => "PAGE_NOACCESS",
            0x02 => "PAGE_READONLY",
            0x04 => "PAGE_READWRITE",
            0x08 => "PAGE_WRITECOPY",
            0x10 => "PAGE_EXECUTE",
            0x12 => "PAGE_EXECUTE_READ",
            0x14 => "PAGE_EXECUTE_READWRITE",
            0x18 => "PAGE_EXECUTE_WRITECOPY",
            _ => "PAGE_UNKNOWN",
        }
    }

    /// Returns `true` for RWX private memory — a classic injection indicator.
    #[must_use]
    pub const fn is_rwx_private(&self) -> bool {
        self.private_memory && self.protection == 0x14
    }
}

/// Parsed `_VAD_NODE` (short form, i.e., only the red-black tree node part).
#[derive(Debug, Clone)]
pub struct VadNode {
    pub address: u64,
    pub left_child: u64,
    pub right_child: u64,
    pub parent_value: u64,
    pub starting_vpn: u64,
    pub ending_vpn: u64,
    pub flags: MmVadFlags,
    /// Subsection pointer (non-zero for mapped files and image sections).
    pub subsection: u64,
}

impl VadNode {
    /// Page size constant.
    pub const PAGE_SIZE: u64 = 0x1000;

    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        let raw_flags = read_u64(buf, VAD_FLAGS_OFFSET)?;
        Some(Self {
            address: base_addr,
            left_child: read_u64(buf, VAD_LEFT_CHILD_OFFSET)?,
            right_child: read_u64(buf, VAD_RIGHT_CHILD_OFFSET)?,
            parent_value: read_u64(buf, VAD_PARENT_VALUE_OFFSET)?,
            starting_vpn: read_u64(buf, VAD_STARTING_VPN_OFFSET)?,
            ending_vpn: read_u64(buf, VAD_ENDING_VPN_OFFSET)?,
            flags: MmVadFlags::parse(raw_flags),
            subsection: read_u64(buf, VAD_SUBSECTION_OFFSET).unwrap_or(0),
        })
    }

    /// Start virtual address of the region.
    #[must_use]
    pub const fn start_addr(&self) -> u64 {
        self.starting_vpn * Self::PAGE_SIZE
    }

    /// End virtual address of the region (inclusive last byte).
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        (self.ending_vpn + 1) * Self::PAGE_SIZE - 1
    }

    /// Size in bytes of the region.
    #[must_use]
    pub const fn size(&self) -> u64 {
        (self.ending_vpn - self.starting_vpn + 1) * Self::PAGE_SIZE
    }

    /// Returns `true` if this VAD node has a file backing (mapped file / image).
    #[must_use]
    pub const fn is_file_backed(&self) -> bool {
        self.subsection != 0
    }

    /// Strip the color bits from the parent pointer to obtain the real pointer.
    #[must_use]
    pub const fn parent_ptr(&self) -> u64 {
        self.parent_value & !0x3
    }
}

// ===========================================================================
// _TOKEN offsets — Windows 10 x64
// ===========================================================================

pub const TOKEN_TOKEN_SOURCE_OFFSET: usize = 0x000;
pub const TOKEN_TOKEN_ID_OFFSET: usize = 0x010;
pub const TOKEN_AUTHENTICATION_ID_OFFSET: usize = 0x018;
pub const TOKEN_PARENT_TOKEN_ID_OFFSET: usize = 0x020;
pub const TOKEN_EXPIRATION_TIME_OFFSET: usize = 0x028;
pub const TOKEN_TOKEN_LOCK_OFFSET: usize = 0x030;
pub const TOKEN_MODIFIED_ID_OFFSET: usize = 0x038;
pub const TOKEN_PRIVILEGES_OFFSET: usize = 0x040;
pub const TOKEN_DEFAULT_DACL_OFFSET: usize = 0x078;
pub const TOKEN_TOKEN_TYPE_OFFSET: usize = 0x080;
pub const TOKEN_IMPERSONATION_LEVEL_OFFSET: usize = 0x084;
pub const TOKEN_TOKEN_FLAGS_OFFSET: usize = 0x088;
pub const TOKEN_TOKEN_IN_USE_OFFSET: usize = 0x08C;
pub const TOKEN_INTEGRITY_LEVEL_INDEX_OFFSET: usize = 0x090;
pub const TOKEN_MANDATORY_POLICY_OFFSET: usize = 0x094;
pub const TOKEN_PROXY_DATA_OFFSET: usize = 0x098;
pub const TOKEN_AUDIT_DATA_OFFSET: usize = 0x0A0;
pub const TOKEN_LOGON_SESSION_OFFSET: usize = 0x0A8;
pub const TOKEN_ORIGINATING_LOGON_SESSION_OFFSET: usize = 0x0B8;
pub const TOKEN_SID_COUNT_OFFSET: usize = 0x0C0;
pub const TOKEN_USER_AND_GROUP_COUNT_OFFSET: usize = 0x0C4;
pub const TOKEN_RESTRICTED_SID_COUNT_OFFSET: usize = 0x0C8;
pub const TOKEN_VARIABLE_LENGTH_OFFSET: usize = 0x0CC;
pub const TOKEN_DYNAMIC_CHARGED_OFFSET: usize = 0x0D0;
pub const TOKEN_DYNAMIC_AVAILABLE_OFFSET: usize = 0x0D4;
pub const TOKEN_DEFAULT_OWNER_INDEX_OFFSET: usize = 0x0D8;
pub const TOKEN_USER_AND_GROUPS_OFFSET: usize = 0x0E0;
pub const TOKEN_RESTRICTED_SIDS_OFFSET: usize = 0x0E8;
pub const TOKEN_PRIMARY_GROUP_OFFSET: usize = 0x0F0;
pub const TOKEN_DYNAMIC_PART_OFFSET: usize = 0x0F8;
pub const TOKEN_DEFAULT_DACL_PTR_OFFSET: usize = 0x100;
pub const TOKEN_TOKEN_AUDIT_POLICY_OFFSET: usize = 0x108;
pub const TOKEN_SESSION_ID_OFFSET: usize = 0x138;
pub const TOKEN_AUX_DATA_OFFSET: usize = 0x140;
pub const TOKEN_PRIVILEGED_ACCESS_TOKEN_OFFSET: usize = 0x148;
pub const TOKEN_VIRTUAL_MEMORY_ALLOCATION_COUNT_OFFSET: usize = 0x150;
pub const TOKEN_HANDLE_TABLE_ENTRY_OFFSET: usize = 0x158;
pub const TOKEN_SESSION_OBJECT_OFFSET: usize = 0x160;
pub const TOKEN_SECURITY_ATTRIBUTES_OFFSET: usize = 0x168;
pub const TOKEN_CLAIM_PTR_OFFSET: usize = 0x170;
pub const TOKEN_DEVICE_GROUPS_OFFSET: usize = 0x178;
pub const TOKEN_RESTRICTED_DEVICE_GROUPS_OFFSET: usize = 0x180;
pub const TOKEN_SECURITY_POLICY_OFFSET: usize = 0x188;
pub const TOKEN_TRUST_LEVEL_SID_OFFSET: usize = 0x190;
pub const TOKEN_TRUST_LINKED_TOKEN_OFFSET: usize = 0x198;

/// Well-known token privilege LUIDs (Low part only; High part is always 0).
pub const SE_CREATE_TOKEN_PRIVILEGE: u32 = 2;
pub const SE_ASSIGNPRIMARYTOKEN_PRIVILEGE: u32 = 3;
pub const SE_LOCK_MEMORY_PRIVILEGE: u32 = 4;
pub const SE_INCREASE_QUOTA_PRIVILEGE: u32 = 5;
pub const SE_MACHINE_ACCOUNT_PRIVILEGE: u32 = 6;
pub const SE_TCB_PRIVILEGE: u32 = 7;
pub const SE_SECURITY_PRIVILEGE: u32 = 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u32 = 9;
pub const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;
pub const SE_SYSTEM_PROFILE_PRIVILEGE: u32 = 11;
pub const SE_SYSTEMTIME_PRIVILEGE: u32 = 12;
pub const SE_PROFILE_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
pub const SE_INCREASE_BASE_PRIORITY_PRIVILEGE: u32 = 14;
pub const SE_CREATE_PAGEFILE_PRIVILEGE: u32 = 15;
pub const SE_CREATE_PERMANENT_PRIVILEGE: u32 = 16;
pub const SE_BACKUP_PRIVILEGE: u32 = 17;
pub const SE_RESTORE_PRIVILEGE: u32 = 18;
pub const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
pub const SE_DEBUG_PRIVILEGE: u32 = 20;
pub const SE_AUDIT_PRIVILEGE: u32 = 21;
pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: u32 = 22;
pub const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;
pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: u32 = 24;
pub const SE_UNDOCK_PRIVILEGE: u32 = 25;
pub const SE_SYNC_AGENT_PRIVILEGE: u32 = 26;
pub const SE_ENABLE_DELEGATION_PRIVILEGE: u32 = 27;
pub const SE_MANAGE_VOLUME_PRIVILEGE: u32 = 28;
pub const SE_IMPERSONATE_PRIVILEGE: u32 = 29;
pub const SE_CREATE_GLOBAL_PRIVILEGE: u32 = 30;
pub const SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE: u32 = 31;
pub const SE_RELABEL_PRIVILEGE: u32 = 32;
pub const SE_INCREASE_WORKING_SET_PRIVILEGE: u32 = 33;
pub const SE_TIME_ZONE_PRIVILEGE: u32 = 34;
pub const SE_CREATE_SYMBOLIC_LINK_PRIVILEGE: u32 = 35;
pub const SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE: u32 = 36;

/// `_SEP_TOKEN_PRIVILEGES` (three u64 bitmasks: Present, Enabled, `EnabledByDefault`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SepTokenPrivileges {
    pub present: u64,
    pub enabled: u64,
    pub enabled_by_default: u64,
}

impl SepTokenPrivileges {
    #[must_use]
    pub fn parse(buf: &[u8], offset: usize) -> Option<Self> {
        Some(Self {
            present: read_u64(buf, offset)?,
            enabled: read_u64(buf, offset + 8)?,
            enabled_by_default: read_u64(buf, offset + 16)?,
        })
    }

    /// Returns `true` if the privilege identified by `luid_low` is enabled.
    #[must_use]
    pub const fn is_enabled(&self, luid_low: u32) -> bool {
        if luid_low >= 64 { return false; }
        self.enabled & (1u64 << luid_low) != 0
    }

    /// Returns `true` if the Debug privilege is enabled.
    #[must_use]
    pub const fn has_debug(&self) -> bool {
        self.is_enabled(SE_DEBUG_PRIVILEGE)
    }

    /// Returns `true` if the TCB (System) privilege is enabled.
    #[must_use]
    pub const fn has_tcb(&self) -> bool {
        self.is_enabled(SE_TCB_PRIVILEGE)
    }
}

/// Integrity level SID values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted = 0x0000,
    Low = 0x1000,
    Medium = 0x2000,
    MediumPlus = 0x2100,
    High = 0x3000,
    System = 0x4000,
    Protected = 0x5000,
    Unknown = 0xFFFF,
}

impl IntegrityLevel {
    #[must_use]
    pub const fn from_rid(rid: u32) -> Self {
        match rid {
            0x0000 => Self::Untrusted,
            0x1000 => Self::Low,
            0x2000 => Self::Medium,
            0x2100 => Self::MediumPlus,
            0x3000 => Self::High,
            0x4000 => Self::System,
            0x5000 => Self::Protected,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Untrusted => "Untrusted",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::MediumPlus => "MediumPlus",
            Self::High => "High",
            Self::System => "System",
            Self::Protected => "Protected",
            Self::Unknown => "Unknown",
        }
    }
}

/// Parsed `_TOKEN` (key fields only).
#[derive(Debug, Clone)]
pub struct Token {
    pub address: u64,
    pub token_id: u64,
    pub authentication_id: u64,
    pub parent_token_id: u64,
    pub expiration_time: u64,
    pub modified_id: u64,
    pub privileges: SepTokenPrivileges,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub token_flags: u32,
    pub token_in_use: bool,
    pub integrity_level_index: u32,
    pub mandatory_policy: u32,
    pub sid_count: u32,
    pub user_and_group_count: u32,
    pub restricted_sid_count: u32,
    pub session_id: u32,
    pub user_and_groups: u64,
    pub restricted_sids: u64,
    pub primary_group: u64,
    pub trust_level_sid: u64,
    pub trust_linked_token: u64,
}

impl Token {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            token_id: read_u64(buf, TOKEN_TOKEN_ID_OFFSET)?,
            authentication_id: read_u64(buf, TOKEN_AUTHENTICATION_ID_OFFSET)?,
            parent_token_id: read_u64(buf, TOKEN_PARENT_TOKEN_ID_OFFSET)?,
            expiration_time: read_u64(buf, TOKEN_EXPIRATION_TIME_OFFSET)?,
            modified_id: read_u64(buf, TOKEN_MODIFIED_ID_OFFSET)?,
            privileges: SepTokenPrivileges::parse(buf, TOKEN_PRIVILEGES_OFFSET)?,
            token_type: read_u32(buf, TOKEN_TOKEN_TYPE_OFFSET)?,
            impersonation_level: read_u32(buf, TOKEN_IMPERSONATION_LEVEL_OFFSET)?,
            token_flags: read_u32(buf, TOKEN_TOKEN_FLAGS_OFFSET)?,
            token_in_use: read_u32(buf, TOKEN_TOKEN_IN_USE_OFFSET).unwrap_or(0) != 0,
            integrity_level_index: read_u32(buf, TOKEN_INTEGRITY_LEVEL_INDEX_OFFSET)?,
            mandatory_policy: read_u32(buf, TOKEN_MANDATORY_POLICY_OFFSET)?,
            sid_count: read_u32(buf, TOKEN_SID_COUNT_OFFSET)?,
            user_and_group_count: read_u32(buf, TOKEN_USER_AND_GROUP_COUNT_OFFSET)?,
            restricted_sid_count: read_u32(buf, TOKEN_RESTRICTED_SID_COUNT_OFFSET)?,
            session_id: read_u32(buf, TOKEN_SESSION_ID_OFFSET)?,
            user_and_groups: read_u64(buf, TOKEN_USER_AND_GROUPS_OFFSET)?,
            restricted_sids: read_u64(buf, TOKEN_RESTRICTED_SIDS_OFFSET).unwrap_or(0),
            primary_group: read_u64(buf, TOKEN_PRIMARY_GROUP_OFFSET).unwrap_or(0),
            trust_level_sid: read_u64(buf, TOKEN_TRUST_LEVEL_SID_OFFSET).unwrap_or(0),
            trust_linked_token: read_u64(buf, TOKEN_TRUST_LINKED_TOKEN_OFFSET).unwrap_or(0),
        })
    }

    /// Returns `true` for primary tokens (`TokenType` == 1).
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.token_type == 1
    }

    /// Returns `true` for impersonation tokens (`TokenType` == 2).
    #[must_use]
    pub const fn is_impersonation(&self) -> bool {
        self.token_type == 2
    }
}

// ===========================================================================
// _DISPATCHER_HEADER offsets
// ===========================================================================

pub const DISPATCHER_HEADER_TYPE_OFFSET: usize = 0x000;
pub const DISPATCHER_HEADER_SIGNAL_STATE_OFFSET: usize = 0x004;
pub const DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET: usize = 0x008;

/// Kernel object type codes for the `DISPATCHER_HEADER.Type` field.
pub const KOBJECT_TYPE_EVENT: u8 = 0x00;
pub const KOBJECT_TYPE_MUTEX: u8 = 0x01;
pub const KOBJECT_TYPE_SEMAPHORE: u8 = 0x05;
pub const KOBJECT_TYPE_THREAD: u8 = 0x06;
pub const KOBJECT_TYPE_GATE64: u8 = 0x08;
pub const KOBJECT_TYPE_TIMER: u8 = 0x0E;
pub const KOBJECT_TYPE_PROCESS: u8 = 0x07;

/// Parsed `_DISPATCHER_HEADER`.
#[derive(Debug, Clone)]
pub struct DispatcherHeader {
    pub object_type: u8,
    pub signal_state: i32,
    pub wait_list_flink: u64,
    pub wait_list_blink: u64,
}

impl DispatcherHeader {
    #[must_use]
    pub fn parse(buf: &[u8], offset: usize) -> Option<Self> {
        Some(Self {
            object_type: read_u8(buf, offset + DISPATCHER_HEADER_TYPE_OFFSET)?,
            signal_state: (read_u32(buf, offset + DISPATCHER_HEADER_SIGNAL_STATE_OFFSET)?).cast_signed(),
            wait_list_flink: read_u64(buf, offset + DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET)?,
            wait_list_blink: read_u64(buf, offset + DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET + 8)?,
        })
    }

    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.object_type {
            KOBJECT_TYPE_EVENT => "Event",
            KOBJECT_TYPE_MUTEX => "Mutex",
            KOBJECT_TYPE_SEMAPHORE => "Semaphore",
            KOBJECT_TYPE_THREAD => "Thread",
            KOBJECT_TYPE_PROCESS => "Process",
            KOBJECT_TYPE_TIMER => "Timer",
            _ => "Unknown",
        }
    }
}

// ===========================================================================
// _OBJECT_HEADER offsets — Windows 10 x64
// ===========================================================================

pub const OBJECT_HEADER_POINTER_COUNT_OFFSET: usize = 0x000;
pub const OBJECT_HEADER_HANDLE_COUNT_OFFSET: usize = 0x008;
pub const OBJECT_HEADER_LOCK_OFFSET: usize = 0x010;
pub const OBJECT_HEADER_TYPE_INDEX_OFFSET: usize = 0x018;
pub const OBJECT_HEADER_TRACE_FLAGS_OFFSET: usize = 0x019;
pub const OBJECT_HEADER_INFO_MASK_OFFSET: usize = 0x01A;
pub const OBJECT_HEADER_FLAGS_OFFSET: usize = 0x01B;
pub const OBJECT_HEADER_BODY_OFFSET: usize = 0x030;

/// Parsed `_OBJECT_HEADER`.
#[derive(Debug, Clone)]
pub struct ObjectHeader {
    pub address: u64,
    pub pointer_count: i64,
    pub handle_count: i64,
    pub type_index: u8,
    pub info_mask: u8,
    pub flags: u8,
}

impl ObjectHeader {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            pointer_count: (read_u64(buf, OBJECT_HEADER_POINTER_COUNT_OFFSET)?).cast_signed(),
            handle_count: (read_u64(buf, OBJECT_HEADER_HANDLE_COUNT_OFFSET)?).cast_signed(),
            type_index: read_u8(buf, OBJECT_HEADER_TYPE_INDEX_OFFSET)?,
            info_mask: read_u8(buf, OBJECT_HEADER_INFO_MASK_OFFSET)?,
            flags: read_u8(buf, OBJECT_HEADER_FLAGS_OFFSET)?,
        })
    }

    /// Compute the address of the object body from the header address.
    #[must_use]
    pub const fn body_addr(&self) -> u64 {
        self.address + OBJECT_HEADER_BODY_OFFSET as u64
    }
}

// ===========================================================================
// _HANDLE_TABLE offsets — Windows 10 x64
// ===========================================================================

pub const HANDLE_TABLE_CODE_OFFSET: usize = 0x000;
pub const HANDLE_TABLE_NEXT_HANDLE_NEED_INGRESS_OFFSET: usize = 0x008;
pub const HANDLE_TABLE_QUOTA_PROCESS_OFFSET: usize = 0x010;
pub const HANDLE_TABLE_UNIQUE_PROCESS_ID_OFFSET: usize = 0x018;
pub const HANDLE_TABLE_HANDLE_LOCK_OFFSET: usize = 0x020;
pub const HANDLE_TABLE_HANDLE_TABLE_LIST_OFFSET: usize = 0x028;
pub const HANDLE_TABLE_AUDITING_OFFSET: usize = 0x038;
pub const HANDLE_TABLE_TABLE_CODE_OFFSET: usize = 0x000;

/// The low 2 bits of HandleTable.Code indicate the depth of indirection.
pub const HANDLE_TABLE_DEPTH_MASK: u64 = 0x3;
pub const HANDLE_TABLE_TABLE_PAGE_MASK: u64 = !0x3;

// ===========================================================================
// Windows page protection constants (VirtualAlloc / VirtualProtect)
// ===========================================================================

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

/// Return a human-readable name for a Windows page protection value.
#[must_use]
pub const fn protection_name(prot: u32) -> &'static str {
    let base = prot & 0xFF;
    match base {
        PAGE_NOACCESS => "PAGE_NOACCESS",
        PAGE_READONLY => "PAGE_READONLY",
        PAGE_READWRITE => "PAGE_READWRITE",
        PAGE_WRITECOPY => "PAGE_WRITECOPY",
        PAGE_EXECUTE => "PAGE_EXECUTE",
        PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
        PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
        _ => "PAGE_UNKNOWN",
    }
}

// ===========================================================================
// Version-aware offset resolver
// ===========================================================================

/// Windows version selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinVersion {
    Win7,
    Win81,
    Win10,
    Win11,
}

/// Returns the `_EPROCESS.UniqueProcessId` offset for a given Windows version.
#[must_use]
pub const fn eprocess_pid_offset(ver: WinVersion) -> usize {
    match ver {
        WinVersion::Win7 => EPROCESS_WIN7_UNIQUE_PROCESS_ID_OFFSET,
        WinVersion::Win81 => EPROCESS_WIN81_UNIQUE_PROCESS_ID_OFFSET,
        WinVersion::Win10 => EPROCESS_UNIQUE_PROCESS_ID_OFFSET,
        WinVersion::Win11 => EPROCESS_WIN11_UNIQUE_PROCESS_ID_OFFSET,
    }
}

/// Returns the `_EPROCESS.ActiveProcessLinks` offset for a given Windows version.
#[must_use]
pub const fn eprocess_apl_offset(ver: WinVersion) -> usize {
    match ver {
        WinVersion::Win7 => EPROCESS_WIN7_ACTIVE_PROCESS_LINKS_OFFSET,
        WinVersion::Win81 => EPROCESS_WIN81_ACTIVE_PROCESS_LINKS_OFFSET,
        WinVersion::Win10 => EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET,
        WinVersion::Win11 => EPROCESS_WIN11_ACTIVE_PROCESS_LINKS_OFFSET,
    }
}

/// Returns the `_EPROCESS.ImageFileName` offset for a given Windows version.
#[must_use]
pub const fn eprocess_image_file_name_offset(ver: WinVersion) -> usize {
    match ver {
        WinVersion::Win7 => EPROCESS_WIN7_IMAGE_FILE_NAME_OFFSET,
        WinVersion::Win81 => EPROCESS_WIN81_IMAGE_FILE_NAME_OFFSET,
        WinVersion::Win10 => EPROCESS_IMAGE_FILE_NAME_OFFSET,
        WinVersion::Win11 => EPROCESS_WIN11_IMAGE_FILE_NAME_OFFSET,
    }
}

/// Returns the `_EPROCESS.Peb` offset for a given Windows version.
#[must_use]
pub const fn eprocess_peb_offset(ver: WinVersion) -> usize {
    match ver {
        WinVersion::Win7 => EPROCESS_WIN7_PEB_OFFSET,
        WinVersion::Win81 => EPROCESS_WIN81_PEB_OFFSET,
        WinVersion::Win10 => EPROCESS_PEB_OFFSET,
        WinVersion::Win11 => EPROCESS_WIN11_PEB_OFFSET,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Build a synthetic _EPROCESS buffer for Win10 x64
    fn make_eprocess_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x900];
        // DirectoryTableBase
        buf[EPROCESS_DIRECTORY_TABLE_BASE_OFFSET..EPROCESS_DIRECTORY_TABLE_BASE_OFFSET + 8]
            .copy_from_slice(&0x1A3001u64.to_le_bytes());
        // UniqueProcessId = 1337
        buf[EPROCESS_UNIQUE_PROCESS_ID_OFFSET..EPROCESS_UNIQUE_PROCESS_ID_OFFSET + 8]
            .copy_from_slice(&1337u64.to_le_bytes());
        // InheritedFromUniqueProcessId = 4
        buf[EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET
            ..EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET + 8]
            .copy_from_slice(&4u64.to_le_bytes());
        // ImageFileName = "malware.exe\0"
        let name = b"malware.exe\0";
        buf[EPROCESS_IMAGE_FILE_NAME_OFFSET..EPROCESS_IMAGE_FILE_NAME_OFFSET + name.len()]
            .copy_from_slice(name);
        // Peb
        buf[EPROCESS_PEB_OFFSET..EPROCESS_PEB_OFFSET + 8]
            .copy_from_slice(&0x7FF_DEAD_0000u64.to_le_bytes());
        // VadRoot
        buf[EPROCESS_VAD_ROOT_OFFSET..EPROCESS_VAD_ROOT_OFFSET + 8]
            .copy_from_slice(&0xFFFF_A000_1234_0000u64.to_le_bytes());
        // ObjectTable
        buf[EPROCESS_OBJECT_TABLE_OFFSET..EPROCESS_OBJECT_TABLE_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F801_2345_0000u64.to_le_bytes());
        // Token (EX_FAST_REF with RefCnt=3 in low bits)
        buf[EPROCESS_TOKEN_OFFSET..EPROCESS_TOKEN_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F801_9876_0003u64.to_le_bytes());
        // CreateTime
        buf[EPROCESS_CREATE_TIME_OFFSET..EPROCESS_CREATE_TIME_OFFSET + 8]
            .copy_from_slice(&132_000_000_000u64.to_le_bytes());
        // ActiveThreads
        buf[EPROCESS_ACTIVE_THREADS_OFFSET..EPROCESS_ACTIVE_THREADS_OFFSET + 4]
            .copy_from_slice(&5u32.to_le_bytes());
        // ExitStatus = STATUS_PENDING
        buf[EPROCESS_EXIT_STATUS_OFFSET..EPROCESS_EXIT_STATUS_OFFSET + 4]
            .copy_from_slice(&0x0000_0103u32.to_le_bytes());
        // ActiveProcessLinks (Flink/Blink)
        buf[EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET..EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F801_ABCD_EF00u64.to_le_bytes());
        buf[EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET + 8
            ..EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET + 16]
            .copy_from_slice(&0xFFFF_F801_1234_5678u64.to_le_bytes());
        buf
    }

    #[test]
    fn eprocess_parse_pid() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0xFFFF_F801_0000_0000).unwrap();
        assert_eq!(ep.pid, 1337);
    }

    #[test]
    fn eprocess_parse_ppid() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0xFFFF_F801_0000_0000).unwrap();
        assert_eq!(ep.ppid, 4);
    }

    #[test]
    fn eprocess_parse_image_name() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0xFFFF_F801_0000_0000).unwrap();
        assert_eq!(ep.image_file_name, "malware.exe");
    }

    #[test]
    fn eprocess_parse_peb() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0xFFFF_F801_0000_0000).unwrap();
        assert_eq!(ep.peb, 0x7FF_DEAD_0000);
    }

    #[test]
    fn eprocess_parse_active_threads() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0xFFFF_F801_0000_0000).unwrap();
        assert_eq!(ep.active_threads, 5);
    }

    #[test]
    fn eprocess_not_exited() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0).unwrap();
        assert!(!ep.has_exited());
    }

    #[test]
    fn eprocess_token_ptr_strips_refcnt() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0).unwrap();
        assert_eq!(ep.token_ptr(), 0xFFFF_F801_9876_0000);
    }

    #[test]
    fn eprocess_vad_root() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0).unwrap();
        assert_eq!(ep.vad_root, 0xFFFF_A000_1234_0000);
    }

    #[test]
    fn eprocess_apl_flink_blink() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0).unwrap();
        assert_eq!(ep.active_process_links_flink, 0xFFFF_F801_ABCD_EF00);
        assert_eq!(ep.active_process_links_blink, 0xFFFF_F801_1234_5678);
    }

    // ---- _KTHREAD tests ----

    fn make_kthread_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x300];
        buf[KTHREAD_INITIAL_STACK_OFFSET..KTHREAD_INITIAL_STACK_OFFSET + 8]
            .copy_from_slice(&0xFFFF_B001_0001_0000u64.to_le_bytes());
        buf[KTHREAD_STACK_LIMIT_OFFSET..KTHREAD_STACK_LIMIT_OFFSET + 8]
            .copy_from_slice(&0xFFFF_B001_0000_E000u64.to_le_bytes());
        buf[KTHREAD_KERNEL_STACK_OFFSET..KTHREAD_KERNEL_STACK_OFFSET + 8]
            .copy_from_slice(&0xFFFF_B001_0000_FE80u64.to_le_bytes());
        buf[KTHREAD_TEB_OFFSET..KTHREAD_TEB_OFFSET + 8]
            .copy_from_slice(&0x0000_7FF8_DEAD_0000u64.to_le_bytes());
        buf[KTHREAD_PRIORITY_OFFSET] = 8u8;
        buf[KTHREAD_BASE_PRIORITY_OFFSET] = 8u8;
        buf[KTHREAD_STATE_OFFSET] = 2u8; // Running
        buf[KTHREAD_CONTEXT_SWITCHES_OFFSET..KTHREAD_CONTEXT_SWITCHES_OFFSET + 4]
            .copy_from_slice(&42u32.to_le_bytes());
        buf[KTHREAD_CYCLE_TIME_OFFSET..KTHREAD_CYCLE_TIME_OFFSET + 8]
            .copy_from_slice(&999_999u64.to_le_bytes());
        buf
    }

    #[test]
    fn kthread_parse_state_running() {
        let buf = make_kthread_buf();
        let kt = KThread::parse(&buf, 0).unwrap();
        assert_eq!(kt.state, 2);
        assert_eq!(kt.state_str(), "Running");
    }

    #[test]
    fn kthread_parse_priority() {
        let buf = make_kthread_buf();
        let kt = KThread::parse(&buf, 0).unwrap();
        assert_eq!(kt.priority, 8);
        assert_eq!(kt.base_priority, 8);
    }

    #[test]
    fn kthread_parse_context_switches() {
        let buf = make_kthread_buf();
        let kt = KThread::parse(&buf, 0).unwrap();
        assert_eq!(kt.context_switches, 42);
    }

    #[test]
    fn kthread_parse_cycle_time() {
        let buf = make_kthread_buf();
        let kt = KThread::parse(&buf, 0).unwrap();
        assert_eq!(kt.cycle_time, 999_999);
    }

    // ---- _PEB tests ----

    fn make_peb_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        buf[PEB_BEING_DEBUGGED_OFFSET] = 0;
        buf[PEB_IMAGE_BASE_ADDRESS_OFFSET..PEB_IMAGE_BASE_ADDRESS_OFFSET + 8]
            .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf[PEB_LDR_OFFSET..PEB_LDR_OFFSET + 8]
            .copy_from_slice(&0x7FFAB000u64.to_le_bytes());
        buf[PEB_PROCESS_PARAMETERS_OFFSET..PEB_PROCESS_PARAMETERS_OFFSET + 8]
            .copy_from_slice(&0x2D1B70u64.to_le_bytes());
        buf[PEB_PROCESS_HEAP_OFFSET..PEB_PROCESS_HEAP_OFFSET + 8]
            .copy_from_slice(&0x1F0000u64.to_le_bytes());
        buf[PEB_NUMBER_OF_PROCESSORS_OFFSET..PEB_NUMBER_OF_PROCESSORS_OFFSET + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        buf[PEB_OS_BUILD_NUMBER_OFFSET..PEB_OS_BUILD_NUMBER_OFFSET + 2]
            .copy_from_slice(&19041u16.to_le_bytes());
        buf[PEB_SESSION_ID_OFFSET..PEB_SESSION_ID_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf
    }

    #[test]
    fn peb_parse_image_base() {
        let buf = make_peb_buf();
        let peb = Peb::parse(&buf, 0).unwrap();
        assert_eq!(peb.image_base_address, 0x0000_0001_4000_0000);
    }

    #[test]
    fn peb_parse_being_debugged_false() {
        let buf = make_peb_buf();
        let peb = Peb::parse(&buf, 0).unwrap();
        assert!(!peb.being_debugged);
    }

    #[test]
    fn peb_parse_being_debugged_true() {
        let mut buf = make_peb_buf();
        buf[PEB_BEING_DEBUGGED_OFFSET] = 1;
        let peb = Peb::parse(&buf, 0).unwrap();
        assert!(peb.being_debugged);
    }

    #[test]
    fn peb_parse_os_build_number() {
        let buf = make_peb_buf();
        let peb = Peb::parse(&buf, 0).unwrap();
        assert_eq!(peb.os_build_number, 19041);
    }

    #[test]
    fn peb_parse_session_id() {
        let buf = make_peb_buf();
        let peb = Peb::parse(&buf, 0).unwrap();
        assert_eq!(peb.session_id, 1);
    }

    // ---- _MMVAD_FLAGS tests ----

    #[test]
    fn mmvad_flags_rwx_private_detection() {
        // protection = 0x14 (RWX), private_memory = bit 20 set
        // PrivateMemory bit sits at bit 21, just above the 5-bit Protection field.
        let raw: u64 = (0x14u64 << 16) | (1u64 << 21);
        let flags = MmVadFlags::parse(raw);
        assert!(flags.is_rwx_private());
    }

    #[test]
    fn mmvad_flags_readonly_not_rwx() {
        // PrivateMemory bit sits at bit 21, just above the 5-bit Protection field.
        let raw: u64 = (0x02u64 << 16) | (1u64 << 21);
        let flags = MmVadFlags::parse(raw);
        assert!(!flags.is_rwx_private());
    }

    #[test]
    fn mmvad_flags_mapped_not_private() {
        // protection = RWX but private_memory bit not set
        let raw: u64 = 0x14u64 << 16;
        let flags = MmVadFlags::parse(raw);
        assert!(!flags.is_rwx_private());
    }

    #[test]
    fn mmvad_flags_protection_str() {
        let raw: u64 = 0x02u64 << 16;
        let flags = MmVadFlags::parse(raw);
        assert_eq!(flags.protection_str(), "PAGE_READONLY");
    }

    // ---- VadNode tests ----

    fn make_vad_buf(starting_vpn: u64, ending_vpn: u64, raw_flags: u64, subsection: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        buf[VAD_LEFT_CHILD_OFFSET..VAD_LEFT_CHILD_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VAD_RIGHT_CHILD_OFFSET..VAD_RIGHT_CHILD_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VAD_PARENT_VALUE_OFFSET..VAD_PARENT_VALUE_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        buf[VAD_STARTING_VPN_OFFSET..VAD_STARTING_VPN_OFFSET + 8]
            .copy_from_slice(&starting_vpn.to_le_bytes());
        buf[VAD_ENDING_VPN_OFFSET..VAD_ENDING_VPN_OFFSET + 8]
            .copy_from_slice(&ending_vpn.to_le_bytes());
        buf[VAD_FLAGS_OFFSET..VAD_FLAGS_OFFSET + 8].copy_from_slice(&raw_flags.to_le_bytes());
        buf[VAD_SUBSECTION_OFFSET..VAD_SUBSECTION_OFFSET + 8]
            .copy_from_slice(&subsection.to_le_bytes());
        buf
    }

    #[test]
    fn vad_node_start_addr() {
        let buf = make_vad_buf(0x100, 0x1FF, 0, 0);
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert_eq!(vad.start_addr(), 0x100 * 0x1000);
    }

    #[test]
    fn vad_node_end_addr() {
        let buf = make_vad_buf(0x100, 0x1FF, 0, 0);
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert_eq!(vad.end_addr(), 0x200 * 0x1000 - 1);
    }

    #[test]
    fn vad_node_size() {
        let buf = make_vad_buf(0x100, 0x1FF, 0, 0);
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert_eq!(vad.size(), 0x100 * 0x1000);
    }

    #[test]
    fn vad_node_file_backed() {
        let buf = make_vad_buf(0, 1, 0, 0xFFFF_A000_1234);
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert!(vad.is_file_backed());
    }

    #[test]
    fn vad_node_not_file_backed() {
        let buf = make_vad_buf(0, 1, 0, 0);
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert!(!vad.is_file_backed());
    }

    // ---- _TOKEN tests ----

    fn make_token_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];
        buf[TOKEN_TOKEN_ID_OFFSET..TOKEN_TOKEN_ID_OFFSET + 8]
            .copy_from_slice(&0xABCD_1234u64.to_le_bytes());
        buf[TOKEN_TOKEN_TYPE_OFFSET..TOKEN_TOKEN_TYPE_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes()); // Primary
        buf[TOKEN_IMPERSONATION_LEVEL_OFFSET..TOKEN_IMPERSONATION_LEVEL_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        buf[TOKEN_SESSION_ID_OFFSET..TOKEN_SESSION_ID_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[TOKEN_USER_AND_GROUP_COUNT_OFFSET..TOKEN_USER_AND_GROUP_COUNT_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        // Privileges: enabled = SE_DEBUG (bit 20)
        let priv_enabled: u64 = 1u64 << SE_DEBUG_PRIVILEGE;
        buf[TOKEN_PRIVILEGES_OFFSET + 8..TOKEN_PRIVILEGES_OFFSET + 16]
            .copy_from_slice(&priv_enabled.to_le_bytes());
        buf
    }

    #[test]
    fn token_parse_is_primary() {
        let buf = make_token_buf();
        let tok = Token::parse(&buf, 0).unwrap();
        assert!(tok.is_primary());
        assert!(!tok.is_impersonation());
    }

    #[test]
    fn token_parse_session_id() {
        let buf = make_token_buf();
        let tok = Token::parse(&buf, 0).unwrap();
        assert_eq!(tok.session_id, 1);
    }

    #[test]
    fn token_parse_group_count() {
        let buf = make_token_buf();
        let tok = Token::parse(&buf, 0).unwrap();
        assert_eq!(tok.user_and_group_count, 3);
    }

    #[test]
    fn token_has_debug_privilege() {
        let buf = make_token_buf();
        let tok = Token::parse(&buf, 0).unwrap();
        assert!(tok.privileges.has_debug());
    }

    #[test]
    fn token_no_tcb_privilege() {
        let buf = make_token_buf();
        let tok = Token::parse(&buf, 0).unwrap();
        assert!(!tok.privileges.has_tcb());
    }

    // ---- UnicodeStringHeader tests ----

    fn make_unicode_string_buf(length: u16, max_length: u16, buffer_ptr: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x10];
        buf[0..2].copy_from_slice(&length.to_le_bytes());
        buf[2..4].copy_from_slice(&max_length.to_le_bytes());
        buf[8..16].copy_from_slice(&buffer_ptr.to_le_bytes());
        buf
    }

    #[test]
    fn unicode_string_parse() {
        let buf = make_unicode_string_buf(0x1E, 0x20, 0x7FFF_0000_0000);
        let us = UnicodeStringHeader::parse(&buf, 0).unwrap();
        assert_eq!(us.length, 0x1E);
        assert_eq!(us.maximum_length, 0x20);
        assert_eq!(us.buffer_ptr, 0x7FFF_0000_0000);
    }

    #[test]
    fn unicode_string_char_count() {
        let buf = make_unicode_string_buf(0x1E, 0x20, 0);
        let us = UnicodeStringHeader::parse(&buf, 0).unwrap();
        assert_eq!(us.char_count(), 15);
    }

    // ---- DispatcherHeader tests ----

    #[test]
    fn dispatcher_header_thread_type() {
        let mut buf = vec![0u8; 0x20];
        buf[0] = KOBJECT_TYPE_THREAD;
        buf[DISPATCHER_HEADER_SIGNAL_STATE_OFFSET..DISPATCHER_HEADER_SIGNAL_STATE_OFFSET + 4]
            .copy_from_slice(&0i32.to_le_bytes());
        buf[DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET..DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        buf[DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET + 8..DISPATCHER_HEADER_WAIT_LIST_HEAD_OFFSET + 16]
            .copy_from_slice(&0u64.to_le_bytes());
        let hdr = DispatcherHeader::parse(&buf, 0).unwrap();
        assert_eq!(hdr.type_name(), "Thread");
    }

    // ---- IntegrityLevel tests ----

    #[test]
    fn integrity_level_from_rid_high() {
        assert_eq!(IntegrityLevel::from_rid(0x3000), IntegrityLevel::High);
    }

    #[test]
    fn integrity_level_name() {
        assert_eq!(IntegrityLevel::System.name(), "System");
        assert_eq!(IntegrityLevel::Low.name(), "Low");
    }

    #[test]
    fn integrity_level_ordering() {
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
        assert!(IntegrityLevel::System > IntegrityLevel::High);
    }

    // ---- Version-aware offset tests ----

    #[test]
    fn eprocess_pid_offset_win7() {
        assert_eq!(eprocess_pid_offset(WinVersion::Win7), EPROCESS_WIN7_UNIQUE_PROCESS_ID_OFFSET);
    }

    #[test]
    fn eprocess_pid_offset_win10() {
        assert_eq!(eprocess_pid_offset(WinVersion::Win10), EPROCESS_UNIQUE_PROCESS_ID_OFFSET);
    }

    #[test]
    fn eprocess_image_file_name_offset_win81() {
        assert_eq!(
            eprocess_image_file_name_offset(WinVersion::Win81),
            EPROCESS_WIN81_IMAGE_FILE_NAME_OFFSET
        );
    }

    // ---- Protection name tests ----

    #[test]
    fn protection_name_readwrite() {
        assert_eq!(protection_name(PAGE_READWRITE), "PAGE_READWRITE");
    }

    #[test]
    fn protection_name_execute_readwrite() {
        assert_eq!(protection_name(PAGE_EXECUTE_READWRITE), "PAGE_EXECUTE_READWRITE");
    }

    #[test]
    fn protection_name_guard_stripped() {
        // PAGE_GUARD | PAGE_READWRITE — the guard modifier is ignored, base = READWRITE
        assert_eq!(protection_name(PAGE_GUARD | PAGE_READWRITE), "PAGE_READWRITE");
    }

    // ---- read_* helpers ----

    #[test]
    fn read_u64_valid() {
        let buf = 0x1234_5678_ABCD_EF01u64.to_le_bytes();
        assert_eq!(read_u64(&buf, 0), Some(0x1234_5678_ABCD_EF01));
    }

    #[test]
    fn read_u64_out_of_bounds() {
        let buf = vec![0u8; 4];
        assert_eq!(read_u64(&buf, 0), None);
    }

    #[test]
    fn read_ansi_string_null_terminated() {
        let mut buf = vec![0u8; 32];
        buf[..8].copy_from_slice(b"svchost\0");
        let s = read_ansi_string(&buf, 0, 15);
        assert_eq!(s, "svchost");
    }

    #[test]
    fn sep_token_privileges_privilege_bit() {
        let privs = SepTokenPrivileges {
            present: u64::MAX,
            enabled: 1u64 << SE_DEBUG_PRIVILEGE,
            enabled_by_default: 0,
        };
        assert!(privs.has_debug());
        assert!(!privs.has_tcb());
    }

    #[test]
    fn sep_token_privileges_out_of_range() {
        let privs = SepTokenPrivileges {
            present: u64::MAX,
            enabled: u64::MAX,
            enabled_by_default: u64::MAX,
        };
        assert!(!privs.is_enabled(64)); // bit 64 is out of range
    }

    #[test]
    fn eprocess_exit_status_pending() {
        let buf = make_eprocess_buf();
        let ep = EProcess::parse_win10(&buf, 0).unwrap();
        assert_eq!(ep.exit_status, 0x103);
    }

    #[test]
    fn vad_node_parent_ptr_strips_color_bits() {
        let mut buf = make_vad_buf(0, 1, 0, 0);
        let parent: u64 = 0xFFFF_F801_1234_5673; // low 2 bits = color
        buf[VAD_PARENT_VALUE_OFFSET..VAD_PARENT_VALUE_OFFSET + 8]
            .copy_from_slice(&parent.to_le_bytes());
        let vad = VadNode::parse(&buf, 0).unwrap();
        assert_eq!(vad.parent_ptr(), 0xFFFF_F801_1234_5670);
    }

    #[test]
    fn ldr_data_table_entry_parse() {
        let mut buf = vec![0u8; 0x100];
        buf[LDR_DLL_BASE_OFFSET..LDR_DLL_BASE_OFFSET + 8]
            .copy_from_slice(&0x7FFF_1234_0000u64.to_le_bytes());
        buf[LDR_SIZE_OF_IMAGE_OFFSET..LDR_SIZE_OF_IMAGE_OFFSET + 4]
            .copy_from_slice(&0x10_0000u32.to_le_bytes());
        buf[LDR_FLAGS_OFFSET..LDR_FLAGS_OFFSET + 4]
            .copy_from_slice(&0x8000_4000u32.to_le_bytes());
        // Set full_dll_name length
        buf[LDR_FULL_DLL_NAME_OFFSET..LDR_FULL_DLL_NAME_OFFSET + 2]
            .copy_from_slice(&0x1Eu16.to_le_bytes());
        buf[LDR_FULL_DLL_NAME_OFFSET + 8..LDR_FULL_DLL_NAME_OFFSET + 16]
            .copy_from_slice(&0x7FFF_0000_1234u64.to_le_bytes());
        buf[LDR_BASE_DLL_NAME_OFFSET..LDR_BASE_DLL_NAME_OFFSET + 2]
            .copy_from_slice(&0x0Cu16.to_le_bytes());
        buf[LDR_BASE_DLL_NAME_OFFSET + 8..LDR_BASE_DLL_NAME_OFFSET + 16]
            .copy_from_slice(&0x7FFF_0000_5678u64.to_le_bytes());
        let entry = LdrDataTableEntry::parse(&buf, 0x7FFF_0000).unwrap();
        assert_eq!(entry.dll_base, 0x7FFF_1234_0000);
        assert_eq!(entry.size_of_image, 0x10_0000);
        assert_eq!(entry.full_dll_name.length, 0x1E);
        assert_eq!(entry.base_dll_name.length, 0x0C);
    }

    #[test]
    fn mmvad_flags_mem_commit() {
        // bit 15 = MemCommit
        let raw: u64 = 1u64 << 15;
        let flags = MmVadFlags::parse(raw);
        assert!(flags.mem_commit);
    }

    #[test]
    fn mmvad_flags_no_change() {
        // bit 11 = NoChange
        let raw: u64 = 1u64 << 11;
        let flags = MmVadFlags::parse(raw);
        assert!(flags.no_change);
    }
}
