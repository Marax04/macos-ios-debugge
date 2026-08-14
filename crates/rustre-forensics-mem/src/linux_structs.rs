//! Linux kernel data structures with precise field offsets for memory forensics.
//!
//! This module provides Rust representations of the core Linux kernel data
//! structures (`task_struct`, `mm_struct`, `vm_area_struct`, `file`, `inode`,
//! `dentry`, `super_block`, etc.) with correct `x86_64` offsets for kernel 5.15.
//!
//! The offsets were extracted from DWARF debug info of a vanilla kernel 5.15
//! built with `CONFIG_HARDENED_USERCOPY=n`.  They will differ for other
//! configurations or versions but serve as a solid baseline.

// ---------------------------------------------------------------------------
// Re-use the same byte-reading helpers from windows_structs
// ---------------------------------------------------------------------------

use crate::windows_structs::{read_u16, read_u32, read_u64, read_ansi_string};
use crate::casts::u64_to_usize;

// ===========================================================================
// task_struct offsets — Linux kernel 5.15, x86_64
// ===========================================================================

// ------ scheduling state fields -------
/// `task_struct.state` (long, -1=unrunnable, 0=runnable, >0=stopped).
pub const TASK_STATE_OFFSET: usize = 0x0000;
/// `task_struct.stack` (pointer to the kernel stack, bottom).
pub const TASK_STACK_OFFSET: usize = 0x0010;
/// `task_struct.usage` (`refcount_t` = `atomic_t` = i32).
pub const TASK_USAGE_OFFSET: usize = 0x0018;
/// `task_struct.flags` (process flags PF_*).
pub const TASK_FLAGS_OFFSET: usize = 0x001C;
/// `task_struct.ptrace` (`PT_PTRACED` etc.).
pub const TASK_PTRACE_OFFSET: usize = 0x0020;
/// `task_struct.on_rq` (runqueue flag, 1 = runnable).
pub const TASK_ON_RQ_OFFSET: usize = 0x0024;

// ------ priority -------
/// `task_struct.prio` (effective scheduling priority).
pub const TASK_PRIO_OFFSET: usize = 0x0028;
/// `task_struct.static_prio` (static priority set by `nice()`).
pub const TASK_STATIC_PRIO_OFFSET: usize = 0x002C;
/// `task_struct.normal_prio` (normal priority, including RT).
pub const TASK_NORMAL_PRIO_OFFSET: usize = 0x0030;
/// `task_struct.rt_priority` (real-time priority, 0..99).
pub const TASK_RT_PRIORITY_OFFSET: usize = 0x0034;

// ------ CPU affinity / SMP -------
/// `task_struct.cpus_ptr` (pointer to `cpumask_t`).
pub const TASK_CPUS_PTR_OFFSET: usize = 0x0038;
/// `task_struct.nr_cpus_allowed` (number of CPUs in cpumask).
pub const TASK_NR_CPUS_ALLOWED_OFFSET: usize = 0x0040;
/// `task_struct.wake_cpu` (CPU the task was last woken on).
pub const TASK_WAKE_CPU_OFFSET: usize = 0x004C;
/// `task_struct.on_cpu` (currently running on a CPU?).
pub const TASK_ON_CPU_OFFSET: usize = 0x0050;
/// `task_struct.migration_disabled` (migration-disable depth).
pub const TASK_MIGRATION_DISABLED_OFFSET: usize = 0x0054;
/// `task_struct.migration_flags` (migration flags).
pub const TASK_MIGRATION_FLAGS_OFFSET: usize = 0x0058;

// ------ thread_info (embedded at offset 0 on x86_64) -------
/// `task_struct.thread_info` (embedded struct `thread_info`).
pub const TASK_THREAD_INFO_OFFSET: usize = 0x0000;

// ------ memory management -------
/// `task_struct.mm` (pointer to `mm_struct`, NULL for kernel threads).
pub const TASK_MM_OFFSET: usize = 0x0590;
/// `task_struct.active_mm` (active `mm_struct`, same as mm for user tasks).
pub const TASK_ACTIVE_MM_OFFSET: usize = 0x0598;

// ------ process grouping / hierarchy -------
/// `task_struct.thread_group` (`LIST_HEAD` linking threads in the same process).
pub const TASK_THREAD_GROUP_OFFSET: usize = 0x05E0;
/// `task_struct.pid` (thread PID = TID for the main thread).
pub const TASK_PID_OFFSET: usize = 0x02B8;
/// `task_struct.tgid` (thread group ID = PID of the main thread).
pub const TASK_TGID_OFFSET: usize = 0x02BC;
/// `task_struct.real_parent` (pointer to real parent `task_struct`).
pub const TASK_REAL_PARENT_OFFSET: usize = 0x02C0;
/// `task_struct.parent` (pointer to parent `task_struct`, may differ via ptrace).
pub const TASK_PARENT_OFFSET: usize = 0x02C8;
/// `task_struct.children` (`LIST_HEAD` of child tasks).
pub const TASK_CHILDREN_OFFSET: usize = 0x02D0;
/// `task_struct.sibling` (`LIST_ENTRY` in parent's children list).
pub const TASK_SIBLING_OFFSET: usize = 0x02E0;
/// `task_struct.group_leader` (pointer to the main thread's `task_struct`).
pub const TASK_GROUP_LEADER_OFFSET: usize = 0x02F0;
/// `task_struct.thread_pid` (pointer to struct pid).
pub const TASK_THREAD_PID_OFFSET: usize = 0x02F8;
/// `task_struct.pid_links` (`hlist_node` inside the pid struct).
pub const TASK_PID_LINKS_OFFSET: usize = 0x0300;

// ------ credentials / namespace -------
/// `task_struct.user_ns` (pointer to user namespace).
pub const TASK_USER_NS_OFFSET: usize = 0x0318;
/// `task_struct.nsproxy` (pointer to nsproxy struct).
pub const TASK_NSPROXY_OFFSET: usize = 0x0750;
/// `task_struct.cred` (pointer to cred struct, RCU protected).
pub const TASK_CRED_OFFSET: usize = 0x07C8;

// ------ signals -------
/// `task_struct.signal` (pointer to `signal_struct`).
pub const TASK_SIGNAL_OFFSET: usize = 0x0770;
/// `task_struct.sighand` (pointer to `sighand_struct`).
pub const TASK_SIGHAND_OFFSET: usize = 0x0778;
/// `task_struct.blocked` (`sigset_t` — blocked signals, 8 bytes on `x86_64`).
pub const TASK_BLOCKED_OFFSET: usize = 0x0780;
/// `task_struct.real_blocked` (saved blocked set during `rt_sigtimedwait`).
pub const TASK_REAL_BLOCKED_OFFSET: usize = 0x0788;
/// `task_struct.saved_sigmask` (restored on return from sigsuspend).
pub const TASK_SAVED_SIGMASK_OFFSET: usize = 0x0790;
/// `task_struct.pending` (sigpending — list + set).
pub const TASK_PENDING_OFFSET: usize = 0x0798;
/// `task_struct.sas_ss_sp` (signal alternate stack pointer).
pub const TASK_SAS_SS_SP_OFFSET: usize = 0x07B8;
/// `task_struct.sas_ss_size` (signal alternate stack size).
pub const TASK_SAS_SS_SIZE_OFFSET: usize = 0x07C0;
/// `task_struct.sas_ss_flags` (`SS_ONSTACK`, `SS_AUTODISARM`, etc.).
pub const TASK_SAS_SS_FLAGS_OFFSET: usize = 0x07C4;

// ------ seccomp -------
/// `task_struct.seccomp` (struct seccomp embedding).
pub const TASK_SECCOMP_OFFSET: usize = 0x0870;

// ------ exit information -------
/// `task_struct.exit_code` (value returned by `wait4()`).
pub const TASK_EXIT_CODE_OFFSET: usize = 0x0A18;
/// `task_struct.exit_signal` (signal sent to parent on exit, -1 = thread).
pub const TASK_EXIT_SIGNAL_OFFSET: usize = 0x0A1C;
/// `task_struct.pdeath_signal` (signal sent when parent dies).
pub const TASK_PDEATH_SIGNAL_OFFSET: usize = 0x0A20;
/// `task_struct.jobctl` (JOBCTL_* flags for job control).
pub const TASK_JOBCTL_OFFSET: usize = 0x0A24;

// ------ personality / exec flags -------
/// `task_struct.personality` (execution domain).
pub const TASK_PERSONALITY_OFFSET: usize = 0x0A28;
/// `task_struct.in_execve` (currently in an `execve()`).
pub const TASK_IN_EXECVE_OFFSET: usize = 0x0A2C;
/// `task_struct.in_iowait` (in an I/O wait?).
pub const TASK_IN_IOWAIT_OFFSET: usize = 0x0A2D;

// ------ timing -------
/// `task_struct.start_time` (monotonic clock at task creation, 8 bytes).
pub const TASK_START_TIME_OFFSET: usize = 0x0B30;
/// `task_struct.real_start_time` (boot-based clock at creation).
pub const TASK_REAL_START_TIME_OFFSET: usize = 0x0B38;

// ------ task command name -------
/// `task_struct.comm[TASK_COMM_LEN]` (16-byte short task name).
pub const TASK_COMM_OFFSET: usize = 0x0650;
pub const TASK_COMM_LEN: usize = 16;

// ------ io context / audit -------
/// `task_struct.io_context` (pointer to `io_context`).
pub const TASK_IO_CONTEXT_OFFSET: usize = 0x0D80;
/// `task_struct.audit_context` (pointer to `audit_context`, NULL if no audit).
pub const TASK_AUDIT_CONTEXT_OFFSET: usize = 0x0D88;

// ------ OOM -------
/// `task_struct.oom_score_adj` (OOM score adjustment, -1000..1000).
pub const TASK_OOM_SCORE_ADJ_OFFSET: usize = 0x0E00;
/// `task_struct.oom_score_adj_min` (minimum adjustment allowed).
pub const TASK_OOM_SCORE_ADJ_MIN_OFFSET: usize = 0x0E02;

// ------ audit / login uid -------
/// `task_struct.loginuid` (`kuid_t` of the login user).
pub const TASK_LOGINUID_OFFSET: usize = 0x0E10;
/// `task_struct.sessionid` (audit session ID).
pub const TASK_SESSIONID_OFFSET: usize = 0x0E14;

// ------ exec IDs -------
/// `task_struct.self_exec_id` (exec generation counter for this task).
pub const TASK_SELF_EXEC_ID_OFFSET: usize = 0x0E18;
/// `task_struct.parent_exec_id` (exec ID of parent at fork time).
pub const TASK_PARENT_EXEC_ID_OFFSET: usize = 0x0E1C;

// ------ robust futex list -------
/// `task_struct.robust_list` (pointer to `robust_list_head`).
pub const TASK_ROBUST_LIST_OFFSET: usize = 0x0F00;
/// `task_struct.compat_robust_list` (compat version).
pub const TASK_COMPAT_ROBUST_LIST_OFFSET: usize = 0x0F08;

// ------ PI state -------
/// `task_struct.pi_state_list` (`LIST_HEAD` of PI futex states).
pub const TASK_PI_STATE_LIST_OFFSET: usize = 0x0F10;
/// `task_struct.pi_state_cache` (pointer to last `pi_state`, fast path).
pub const TASK_PI_STATE_CACHE_OFFSET: usize = 0x0F20;

// ------ files / fs -------
/// `task_struct.files` (pointer to `files_struct`).
pub const TASK_FILES_OFFSET: usize = 0x0740;
/// `task_struct.fs` (pointer to `fs_struct`).
pub const TASK_FS_OFFSET: usize = 0x0748;

// ------ cgroups -------
/// `task_struct.cgroups` (pointer to `css_set`, RCU protected).
pub const TASK_CGROUPS_OFFSET: usize = 0x0980;
/// `task_struct.cg_list` (`list_head` in `css_set` `cset_links`).
pub const TASK_CG_LIST_OFFSET: usize = 0x0988;

// ------ NUMA -------
/// `task_struct.numa_preferred_nid` (preferred NUMA node, -1 = none).
pub const TASK_NUMA_PREFERRED_NID_OFFSET: usize = 0x09C0;
/// `task_struct.numa_scan_period` (NUMA scan interval in ms).
pub const TASK_NUMA_SCAN_PERIOD_OFFSET: usize = 0x09C4;
/// `task_struct.total_numa_faults` (total NUMA migration faults).
pub const TASK_TOTAL_NUMA_FAULTS_OFFSET: usize = 0x09D0;

/// Parsed `task_struct` (key fields only).
#[derive(Debug, Clone)]
pub struct TaskStruct {
    pub address: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub state: i64,
    pub flags: u32,
    pub ptrace: u32,
    pub prio: i32,
    pub static_prio: i32,
    pub normal_prio: i32,
    pub rt_priority: u32,
    pub mm: u64,
    pub active_mm: u64,
    pub real_parent: u64,
    pub parent: u64,
    pub group_leader: u64,
    pub thread_pid: u64,
    pub nsproxy: u64,
    pub cred: u64,
    pub signal: u64,
    pub sighand: u64,
    pub blocked: u64,
    pub files: u64,
    pub fs: u64,
    pub exit_code: i32,
    pub exit_signal: i32,
    pub start_time: u64,
    pub real_start_time: u64,
    pub on_rq: i32,
    pub oom_score_adj: i16,
    pub loginuid: u32,
    pub sessionid: u32,
}

impl TaskStruct {
    /// Parse a `task_struct` from a raw byte buffer using Linux 5.15 `x86_64` offsets.
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            pid: read_u32(buf, TASK_PID_OFFSET)?,
            tgid: read_u32(buf, TASK_TGID_OFFSET)?,
            comm: read_ansi_string(buf, TASK_COMM_OFFSET, TASK_COMM_LEN),
            state: read_u64(buf, TASK_STATE_OFFSET).unwrap_or(0).cast_signed(),
            flags: read_u32(buf, TASK_FLAGS_OFFSET).unwrap_or(0),
            ptrace: read_u32(buf, TASK_PTRACE_OFFSET).unwrap_or(0),
            prio: read_u32(buf, TASK_PRIO_OFFSET).unwrap_or(120).cast_signed(),
            static_prio: read_u32(buf, TASK_STATIC_PRIO_OFFSET).unwrap_or(120).cast_signed(),
            normal_prio: read_u32(buf, TASK_NORMAL_PRIO_OFFSET).unwrap_or(120).cast_signed(),
            rt_priority: read_u32(buf, TASK_RT_PRIORITY_OFFSET).unwrap_or(0),
            mm: read_u64(buf, TASK_MM_OFFSET)?,
            active_mm: read_u64(buf, TASK_ACTIVE_MM_OFFSET)?,
            real_parent: read_u64(buf, TASK_REAL_PARENT_OFFSET)?,
            parent: read_u64(buf, TASK_PARENT_OFFSET)?,
            group_leader: read_u64(buf, TASK_GROUP_LEADER_OFFSET)?,
            thread_pid: read_u64(buf, TASK_THREAD_PID_OFFSET)?,
            nsproxy: read_u64(buf, TASK_NSPROXY_OFFSET)?,
            cred: read_u64(buf, TASK_CRED_OFFSET)?,
            signal: read_u64(buf, TASK_SIGNAL_OFFSET)?,
            sighand: read_u64(buf, TASK_SIGHAND_OFFSET)?,
            blocked: read_u64(buf, TASK_BLOCKED_OFFSET).unwrap_or(0),
            files: read_u64(buf, TASK_FILES_OFFSET)?,
            fs: read_u64(buf, TASK_FS_OFFSET)?,
            exit_code: read_u32(buf, TASK_EXIT_CODE_OFFSET).unwrap_or(0).cast_signed(),
            exit_signal: read_u32(buf, TASK_EXIT_SIGNAL_OFFSET).unwrap_or(0).cast_signed(),
            start_time: read_u64(buf, TASK_START_TIME_OFFSET).unwrap_or(0),
            real_start_time: read_u64(buf, TASK_REAL_START_TIME_OFFSET).unwrap_or(0),
            on_rq: read_u32(buf, TASK_ON_RQ_OFFSET).unwrap_or(0).cast_signed(),
            oom_score_adj: read_u16(buf, TASK_OOM_SCORE_ADJ_OFFSET).unwrap_or(0).cast_signed(),
            loginuid: read_u32(buf, TASK_LOGINUID_OFFSET).unwrap_or(u32::MAX),
            sessionid: read_u32(buf, TASK_SESSIONID_OFFSET).unwrap_or(u32::MAX),
        })
    }

    /// Returns `true` if this is a kernel thread (mm == NULL).
    #[must_use]
    pub const fn is_kernel_thread(&self) -> bool {
        self.mm == 0
    }

    /// Returns `true` if the process is currently being ptraced.
    #[must_use]
    pub const fn is_ptraced(&self) -> bool {
        self.ptrace != 0
    }

    /// Nice value computed from `static_prio`.
    #[must_use]
    pub const fn nice(&self) -> i32 {
        self.static_prio - 120
    }

    /// Returns `true` if the task is the main thread (pid == tgid).
    #[must_use]
    pub const fn is_thread_group_leader(&self) -> bool {
        self.pid == self.tgid
    }
}

// ===========================================================================
// Process flags (PF_*) — used in task_struct.flags
// ===========================================================================

pub const PF_IDLE: u32 = 0x0000_0002;
pub const PF_EXITING: u32 = 0x0000_0004;
pub const PF_POSTCOREDUMP: u32 = 0x0000_0008;
pub const PF_IO_WORKER: u32 = 0x0000_0010;
pub const PF_WQ_WORKER: u32 = 0x0000_0020;
pub const PF_FORKNOEXEC: u32 = 0x0000_0040;
pub const PF_MCE_PROCESS: u32 = 0x0000_0080;
pub const PF_SUPERPRIV: u32 = 0x0000_0100;
pub const PF_DUMPCORE: u32 = 0x0000_0200;
pub const PF_SIGNALED: u32 = 0x0000_0400;
pub const PF_MEMALLOC: u32 = 0x0000_0800;
pub const PF_NPROC_EXCEEDED: u32 = 0x0000_1000;
pub const PF_USED_MATH: u32 = 0x0000_2000;
pub const PF_USER_WORKER: u32 = 0x0000_4000;
pub const PF_NOFREEZE: u32 = 0x0000_8000;
pub const PF_KSWAPD: u32 = 0x0002_0000;
pub const PF_MEMALLOC_NOFS: u32 = 0x0004_0000;
pub const PF_MEMALLOC_NOIO: u32 = 0x0008_0000;
pub const PF_LOCAL_THROTTLE: u32 = 0x0010_0000;
pub const PF_KTHREAD: u32 = 0x0020_0000;
pub const PF_RANDOMIZE: u32 = 0x0040_0000;
pub const PF_SWAPWRITE: u32 = 0x0080_0000;
pub const PF_NO_SETAFFINITY: u32 = 0x0400_0000;
pub const PF_MCE_EARLY: u32 = 0x0800_0000;
pub const PF_MEMALLOC_PIN: u32 = 0x1000_0000;

// ===========================================================================
// mm_struct offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `mm_struct.mmap` (pointer to the first VMA, or NULL if no VMAs).
pub const MM_MMAP_OFFSET: usize = 0x0000;
/// `mm_struct.pgd` (pointer to the page-global directory).
pub const MM_PGD_OFFSET: usize = 0x0040;
/// `mm_struct.arg_start` / `arg_end` (argument region boundaries).
pub const MM_ARG_START_OFFSET: usize = 0x0480;
pub const MM_ARG_END_OFFSET: usize = 0x0488;
/// `mm_struct.env_start` / `env_end` (environment region boundaries).
pub const MM_ENV_START_OFFSET: usize = 0x0490;
pub const MM_ENV_END_OFFSET: usize = 0x0498;
/// `mm_struct.start_code` / `end_code` (code segment boundaries).
pub const MM_START_CODE_OFFSET: usize = 0x0460;
pub const MM_END_CODE_OFFSET: usize = 0x0468;
/// `mm_struct.start_data` / `end_data` (data segment boundaries).
pub const MM_START_DATA_OFFSET: usize = 0x0470;
pub const MM_END_DATA_OFFSET: usize = 0x0478;
/// `mm_struct.start_brk` / `brk` (heap boundaries).
pub const MM_START_BRK_OFFSET: usize = 0x04A0;
pub const MM_BRK_OFFSET: usize = 0x04A8;
/// `mm_struct.start_stack` (start of the stack).
pub const MM_START_STACK_OFFSET: usize = 0x04B0;
/// `mm_struct.task_size` (size of the user address space).
pub const MM_TASK_SIZE_OFFSET: usize = 0x0370;
/// `mm_struct.total_vm` (total pages mapped).
pub const MM_TOTAL_VM_OFFSET: usize = 0x02B0;
/// `mm_struct.locked_vm` (locked pages, counted for mlock).
pub const MM_LOCKED_VM_OFFSET: usize = 0x02B8;
/// `mm_struct.pinned_vm` (unevictable pinned pages).
pub const MM_PINNED_VM_OFFSET: usize = 0x02C0;
/// `mm_struct.data_vm` (data section pages).
pub const MM_DATA_VM_OFFSET: usize = 0x02C8;
/// `mm_struct.exec_vm` (executable pages).
pub const MM_EXEC_VM_OFFSET: usize = 0x02D0;
/// `mm_struct.stack_vm` (stack pages).
pub const MM_STACK_VM_OFFSET: usize = 0x02D8;
/// `mm_struct.def_flags` (default protection flags for new VMAs).
pub const MM_DEF_FLAGS_OFFSET: usize = 0x02E0;
/// `mm_struct.mm_count` (number of lazy tlb users + 1).
pub const MM_MM_COUNT_OFFSET: usize = 0x0038;
/// `mm_struct.mm_users` (number of tasks using this mm).
pub const MM_MM_USERS_OFFSET: usize = 0x0030;
/// `mm_struct.pgtables_bytes` (size of page tables in bytes).
pub const MM_PGTABLES_BYTES_OFFSET: usize = 0x0140;
/// `mm_struct.map_count` (number of VMAs).
pub const MM_MAP_COUNT_OFFSET: usize = 0x0150;
/// `mm_struct.mmap_base` (base of mmap region).
pub const MM_MMAP_BASE_OFFSET: usize = 0x03D0;
/// `mm_struct.mmap_legacy_base` (mmap base in legacy mmap layout).
pub const MM_MMAP_LEGACY_BASE_OFFSET: usize = 0x03D8;
/// `mm_struct.task_unmapped_base` (base for unmapped area).
pub const MM_TASK_UNMAPPED_BASE_OFFSET: usize = 0x03E0;
/// `mm_struct.exe_file` (pointer to the executable file's struct file).
pub const MM_EXE_FILE_OFFSET: usize = 0x03F8;
/// `mm_struct.owner` (pointer to the owner `task_struct`).
pub const MM_OWNER_OFFSET: usize = 0x0408;
/// `mm_struct.mm_list` (`list_head` linking all `mm_structs` in memory).
pub const MM_MM_LIST_OFFSET: usize = 0x0418;
/// `mm_struct.saved_auxv` (saved auxiliary vector).
pub const MM_SAVED_AUXV_OFFSET: usize = 0x0440;

/// Parsed `mm_struct`.
#[derive(Debug, Clone)]
pub struct MmStruct {
    pub address: u64,
    pub mmap: u64,
    pub pgd: u64,
    pub mm_users: i32,
    pub mm_count: i32,
    pub map_count: i32,
    pub total_vm: u64,
    pub locked_vm: u64,
    pub pinned_vm: u64,
    pub data_vm: u64,
    pub exec_vm: u64,
    pub stack_vm: u64,
    pub def_flags: u64,
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub task_size: u64,
    pub mmap_base: u64,
    pub exe_file: u64,
    pub owner: u64,
    pub pgtables_bytes: u64,
}

impl MmStruct {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            mmap: read_u64(buf, MM_MMAP_OFFSET)?,
            pgd: read_u64(buf, MM_PGD_OFFSET)?,
            mm_users: (read_u32(buf, MM_MM_USERS_OFFSET)?).cast_signed(),
            mm_count: (read_u32(buf, MM_MM_COUNT_OFFSET)?).cast_signed(),
            map_count: (read_u32(buf, MM_MAP_COUNT_OFFSET)?).cast_signed(),
            total_vm: read_u64(buf, MM_TOTAL_VM_OFFSET)?,
            locked_vm: read_u64(buf, MM_LOCKED_VM_OFFSET)?,
            pinned_vm: read_u64(buf, MM_PINNED_VM_OFFSET)?,
            data_vm: read_u64(buf, MM_DATA_VM_OFFSET)?,
            exec_vm: read_u64(buf, MM_EXEC_VM_OFFSET)?,
            stack_vm: read_u64(buf, MM_STACK_VM_OFFSET)?,
            def_flags: read_u64(buf, MM_DEF_FLAGS_OFFSET)?,
            start_code: read_u64(buf, MM_START_CODE_OFFSET)?,
            end_code: read_u64(buf, MM_END_CODE_OFFSET)?,
            start_data: read_u64(buf, MM_START_DATA_OFFSET)?,
            end_data: read_u64(buf, MM_END_DATA_OFFSET)?,
            start_brk: read_u64(buf, MM_START_BRK_OFFSET)?,
            brk: read_u64(buf, MM_BRK_OFFSET)?,
            start_stack: read_u64(buf, MM_START_STACK_OFFSET)?,
            arg_start: read_u64(buf, MM_ARG_START_OFFSET)?,
            arg_end: read_u64(buf, MM_ARG_END_OFFSET)?,
            env_start: read_u64(buf, MM_ENV_START_OFFSET)?,
            env_end: read_u64(buf, MM_ENV_END_OFFSET)?,
            task_size: read_u64(buf, MM_TASK_SIZE_OFFSET)?,
            mmap_base: read_u64(buf, MM_MMAP_BASE_OFFSET)?,
            exe_file: read_u64(buf, MM_EXE_FILE_OFFSET)?,
            owner: read_u64(buf, MM_OWNER_OFFSET)?,
            pgtables_bytes: read_u64(buf, MM_PGTABLES_BYTES_OFFSET)?,
        })
    }

    /// Size of the heap in bytes.
    #[must_use]
    pub const fn heap_size(&self) -> u64 {
        self.brk.saturating_sub(self.start_brk)
    }

    /// Size of the code segment in bytes.
    #[must_use]
    pub const fn code_size(&self) -> u64 {
        self.end_code.saturating_sub(self.start_code)
    }
}

// ===========================================================================
// vm_area_struct offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `vm_area_struct.vm_start` (start virtual address of this VMA, inclusive).
pub const VMA_VM_START_OFFSET: usize = 0x0000;
/// `vm_area_struct.vm_end` (end virtual address of this VMA, exclusive).
pub const VMA_VM_END_OFFSET: usize = 0x0008;
/// `vm_area_struct.vm_next` (pointer to next VMA in address order).
pub const VMA_VM_NEXT_OFFSET: usize = 0x0010;
/// `vm_area_struct.vm_prev` (pointer to previous VMA).
pub const VMA_VM_PREV_OFFSET: usize = 0x0018;
/// `vm_area_struct.vm_rb` (red-black tree node inside the mm).
pub const VMA_VM_RB_OFFSET: usize = 0x0020;
/// `vm_area_struct.rb_subtree_gap` (cached maximum gap for rb tree).
pub const VMA_RB_SUBTREE_GAP_OFFSET: usize = 0x0038;
/// `vm_area_struct.vm_mm` (back-pointer to `mm_struct`).
pub const VMA_VM_MM_OFFSET: usize = 0x0040;
/// `vm_area_struct.vm_page_prot` (access permissions — `pgprot_t`).
pub const VMA_VM_PAGE_PROT_OFFSET: usize = 0x0048;
/// `vm_area_struct.vm_flags` (VMA flags `VM_READ`, `VM_WRITE`, `VM_EXEC`, etc.).
pub const VMA_VM_FLAGS_OFFSET: usize = 0x0050;
/// `vm_area_struct.shared` (shared mapping union: rb / file/page nodes).
pub const VMA_SHARED_OFFSET: usize = 0x0058;
/// `vm_area_struct.anon_vma_chain` (`list_head` for `anon_vma` chain).
pub const VMA_ANON_VMA_CHAIN_OFFSET: usize = 0x0068;
/// `vm_area_struct.anon_vma` (pointer to `anon_vma` for anonymous VMAs).
pub const VMA_ANON_VMA_OFFSET: usize = 0x0078;
/// `vm_area_struct.vm_ops` (pointer to `vm_operations_struct`).
pub const VMA_VM_OPS_OFFSET: usize = 0x0080;
/// `vm_area_struct.vm_pgoff` (page offset within the file, in pages).
pub const VMA_VM_PGOFF_OFFSET: usize = 0x0088;
/// `vm_area_struct.vm_file` (pointer to struct file, or NULL for anonymous).
pub const VMA_VM_FILE_OFFSET: usize = 0x0090;
/// `vm_area_struct.vm_private_data` (private data for the mapping driver).
pub const VMA_VM_PRIVATE_DATA_OFFSET: usize = 0x0098;
/// `vm_area_struct.swap_readahead_info` (swap readahead counter).
pub const VMA_SWAP_READAHEAD_INFO_OFFSET: usize = 0x00A0;
/// `vm_area_struct.vm_userfaultfd_ctx` (userfaultfd context).
pub const VMA_VM_USERFAULTFD_CTX_OFFSET: usize = 0x00B0;

// VMA flags
pub const VM_READ: u64 = 0x0000_0001;
pub const VM_WRITE: u64 = 0x0000_0002;
pub const VM_EXEC: u64 = 0x0000_0004;
pub const VM_SHARED: u64 = 0x0000_0008;
pub const VM_MAYREAD: u64 = 0x0000_0010;
pub const VM_MAYWRITE: u64 = 0x0000_0020;
pub const VM_MAYEXEC: u64 = 0x0000_0040;
pub const VM_MAYSHARE: u64 = 0x0000_0080;
pub const VM_GROWSDOWN: u64 = 0x0000_0100;
pub const VM_UFFD_MISSING: u64 = 0x0000_0200;
pub const VM_PFNMAP: u64 = 0x0000_0400;
pub const VM_DENYWRITE: u64 = 0x0000_0800;
pub const VM_UFFD_WP: u64 = 0x0000_1000;
pub const VM_LOCKED: u64 = 0x0000_2000;
pub const VM_IO: u64 = 0x0000_4000;
pub const VM_SEQ_READ: u64 = 0x0000_8000;
pub const VM_RAND_READ: u64 = 0x0001_0000;
pub const VM_DONTCOPY: u64 = 0x0002_0000;
pub const VM_DONTEXPAND: u64 = 0x0004_0000;
pub const VM_LOCKONFAULT: u64 = 0x0008_0000;
pub const VM_ACCOUNT: u64 = 0x0010_0000;
pub const VM_NORESERVE: u64 = 0x0020_0000;
pub const VM_HUGETLB: u64 = 0x0040_0000;
pub const VM_SYNC: u64 = 0x0080_0000;
pub const VM_ARCH_1: u64 = 0x0100_0000;
pub const VM_WIPEONFORK: u64 = 0x0200_0000;
pub const VM_DONTDUMP: u64 = 0x0400_0000;
pub const VM_MIXEDMAP: u64 = 0x1000_0000;
pub const VM_HUGEPAGE: u64 = 0x2000_0000;
pub const VM_NOHUGEPAGE: u64 = 0x4000_0000;
pub const VM_MERGEABLE: u64 = 0x8000_0000;

/// Parsed `vm_area_struct`.
#[derive(Debug, Clone)]
pub struct VmAreaStruct {
    pub address: u64,
    pub vm_start: u64,
    pub vm_end: u64,
    pub vm_next: u64,
    pub vm_prev: u64,
    pub vm_mm: u64,
    pub vm_page_prot: u64,
    pub vm_flags: u64,
    pub anon_vma: u64,
    pub vm_ops: u64,
    pub vm_pgoff: u64,
    pub vm_file: u64,
    pub vm_private_data: u64,
}

impl VmAreaStruct {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            vm_start: read_u64(buf, VMA_VM_START_OFFSET)?,
            vm_end: read_u64(buf, VMA_VM_END_OFFSET)?,
            vm_next: read_u64(buf, VMA_VM_NEXT_OFFSET)?,
            vm_prev: read_u64(buf, VMA_VM_PREV_OFFSET)?,
            vm_mm: read_u64(buf, VMA_VM_MM_OFFSET)?,
            vm_page_prot: read_u64(buf, VMA_VM_PAGE_PROT_OFFSET)?,
            vm_flags: read_u64(buf, VMA_VM_FLAGS_OFFSET)?,
            anon_vma: read_u64(buf, VMA_ANON_VMA_OFFSET)?,
            vm_ops: read_u64(buf, VMA_VM_OPS_OFFSET)?,
            vm_pgoff: read_u64(buf, VMA_VM_PGOFF_OFFSET)?,
            vm_file: read_u64(buf, VMA_VM_FILE_OFFSET)?,
            vm_private_data: read_u64(buf, VMA_VM_PRIVATE_DATA_OFFSET)?,
        })
    }

    /// Size of the VMA in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.vm_end.saturating_sub(self.vm_start)
    }

    /// Returns `true` if the region is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool { self.vm_flags & VM_READ != 0 }
    /// Returns `true` if the region is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool { self.vm_flags & VM_WRITE != 0 }
    /// Returns `true` if the region is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.vm_flags & VM_EXEC != 0 }
    /// Returns `true` if the region is shared.
    #[must_use]
    pub const fn is_shared(&self) -> bool { self.vm_flags & VM_SHARED != 0 }
    /// Returns `true` for anonymous mappings (no backing file).
    #[must_use]
    pub const fn is_anonymous(&self) -> bool { self.vm_file == 0 }
    /// Returns `true` for suspicious RWX anonymous mappings.
    #[must_use]
    pub const fn is_suspicious_rwx(&self) -> bool {
        self.is_readable() && self.is_writable() && self.is_executable() && self.is_anonymous()
    }

    /// Permissions as a compact 3-character string: "rwx", "r--", etc.
    #[must_use]
    pub fn perm_str(&self) -> String {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

// ===========================================================================
// struct file offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `file.f_path` (embedded path struct: dentry + vfsmount).
pub const FILE_F_PATH_OFFSET: usize = 0x0010;
/// `file.f_path.mnt` (pointer to vfsmount).
pub const FILE_F_MNT_OFFSET: usize = 0x0010;
/// `file.f_path.dentry` (pointer to dentry).
pub const FILE_F_DENTRY_OFFSET: usize = 0x0018;
/// `file.f_inode` (pointer to inode, cached from dentry).
pub const FILE_F_INODE_OFFSET: usize = 0x0020;
/// `file.f_op` (pointer to `file_operations`).
pub const FILE_F_OP_OFFSET: usize = 0x0028;
/// `file.f_lock` (spinlock protecting file).
pub const FILE_F_LOCK_OFFSET: usize = 0x0030;
/// `file.f_write_hint` (write life-time hint).
pub const FILE_F_WRITE_HINT_OFFSET: usize = 0x0038;
/// `file.f_count` (file reference count).
pub const FILE_F_COUNT_OFFSET: usize = 0x0040;
/// `file.f_flags` (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, etc.).
pub const FILE_F_FLAGS_OFFSET: usize = 0x0048;
/// `file.f_mode` (FMODE_* flags).
pub const FILE_F_MODE_OFFSET: usize = 0x004C;
/// `file.f_pos` (current file position).
pub const FILE_F_POS_OFFSET: usize = 0x0068;
/// `file.f_uid` (uid of the file opener).
pub const FILE_F_UID_OFFSET: usize = 0x0070;
/// `file.f_gid` (gid of the file opener).
pub const FILE_F_GID_OFFSET: usize = 0x0074;
/// `file.private_data` (file-type-specific private data pointer).
pub const FILE_PRIVATE_DATA_OFFSET: usize = 0x00B8;

/// Parsed `struct file`.
#[derive(Debug, Clone)]
pub struct FileStruct {
    pub address: u64,
    pub dentry: u64,
    pub inode: u64,
    pub f_count: i64,
    pub f_flags: u32,
    pub f_mode: u32,
    pub f_pos: i64,
    pub f_uid: u32,
    pub f_gid: u32,
    pub private_data: u64,
}

impl FileStruct {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            dentry: read_u64(buf, FILE_F_DENTRY_OFFSET)?,
            inode: read_u64(buf, FILE_F_INODE_OFFSET)?,
            f_count: (read_u64(buf, FILE_F_COUNT_OFFSET)?).cast_signed(),
            f_flags: read_u32(buf, FILE_F_FLAGS_OFFSET)?,
            f_mode: read_u32(buf, FILE_F_MODE_OFFSET)?,
            f_pos: (read_u64(buf, FILE_F_POS_OFFSET)?).cast_signed(),
            f_uid: read_u32(buf, FILE_F_UID_OFFSET).unwrap_or(u32::MAX),
            f_gid: read_u32(buf, FILE_F_GID_OFFSET).unwrap_or(u32::MAX),
            private_data: read_u64(buf, FILE_PRIVATE_DATA_OFFSET).unwrap_or(0),
        })
    }

    /// Returns `true` if the file was opened for reading.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.f_mode & 0x1 != 0
    }

    /// Returns `true` if the file was opened for writing.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.f_mode & 0x2 != 0
    }
}

// ===========================================================================
// struct inode offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `inode.i_mode` (file type + permissions, `umode_t` = u16).
pub const INODE_I_MODE_OFFSET: usize = 0x0000;
/// `inode.i_opflags` (internal inode flags).
pub const INODE_I_OPFLAGS_OFFSET: usize = 0x0002;
/// `inode.i_uid` (owner uid).
pub const INODE_I_UID_OFFSET: usize = 0x0004;
/// `inode.i_gid` (owner gid).
pub const INODE_I_GID_OFFSET: usize = 0x0008;
/// `inode.i_flags` (filesystem flags `MS_SYNC`, etc.).
pub const INODE_I_FLAGS_OFFSET: usize = 0x000C;
/// `inode.i_sb` (pointer to `super_block`).
pub const INODE_I_SB_OFFSET: usize = 0x0028;
/// `inode.i_op` (pointer to `inode_operations`).
pub const INODE_I_OP_OFFSET: usize = 0x0030;
/// `inode.i_fop` (pointer to `file_operations`, const).
pub const INODE_I_FOP_OFFSET: usize = 0x0038;
/// `inode.i_mapping` (pointer to `address_space`).
pub const INODE_I_MAPPING_OFFSET: usize = 0x0040;
/// `inode.i_ino` (inode number).
pub const INODE_I_INO_OFFSET: usize = 0x0048;
/// `inode.i_nlink` (hard link count).
pub const INODE_I_NLINK_OFFSET: usize = 0x0050;
/// `inode.i_rdev` (device identifier for device files).
pub const INODE_I_RDEV_OFFSET: usize = 0x0054;
/// `inode.i_size` (file size in bytes).
pub const INODE_I_SIZE_OFFSET: usize = 0x0058;
/// `inode.i_atime` (last access time, struct timespec64: sec(8)+nsec(4)+pad(4)).
pub const INODE_I_ATIME_OFFSET: usize = 0x0060;
/// `inode.i_mtime` (last modification time).
pub const INODE_I_MTIME_OFFSET: usize = 0x0070;
/// `inode.i_ctime` (last status-change time).
pub const INODE_I_CTIME_OFFSET: usize = 0x0080;
/// `inode.i_blkbits` (block size in bits, i.e., `log2(block_size)`).
pub const INODE_I_BLKBITS_OFFSET: usize = 0x0090;
/// `inode.i_bytes` (partial bytes of the last block used).
pub const INODE_I_BYTES_OFFSET: usize = 0x0092;
/// `inode.i_blksize` (preferred IO block size).
pub const INODE_I_BLKSIZE_OFFSET: usize = 0x0094;
/// `inode.i_blocks` (number of 512-byte blocks allocated).
pub const INODE_I_BLOCKS_OFFSET: usize = 0x0098;

/// Inode file type bits from `i_mode`.
pub const S_IFSOCK: u16 = 0xC000;
pub const S_IFLNK: u16 = 0xA000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFBLK: u16 = 0x6000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFCHR: u16 = 0x2000;
pub const S_IFIFO: u16 = 0x1000;
pub const S_IFMT: u16 = 0xF000;

/// Parsed `struct inode` (key fields).
#[derive(Debug, Clone)]
pub struct Inode {
    pub address: u64,
    pub i_mode: u16,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_flags: u32,
    pub i_sb: u64,
    pub i_ino: u64,
    pub i_nlink: u32,
    pub i_size: i64,
    pub i_blocks: u64,
}

impl Inode {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            i_mode: read_u16(buf, INODE_I_MODE_OFFSET)?,
            i_uid: read_u32(buf, INODE_I_UID_OFFSET)?,
            i_gid: read_u32(buf, INODE_I_GID_OFFSET)?,
            i_flags: read_u32(buf, INODE_I_FLAGS_OFFSET)?,
            i_sb: read_u64(buf, INODE_I_SB_OFFSET)?,
            i_ino: read_u64(buf, INODE_I_INO_OFFSET)?,
            i_nlink: read_u32(buf, INODE_I_NLINK_OFFSET)?,
            i_size: (read_u64(buf, INODE_I_SIZE_OFFSET)?).cast_signed(),
            i_blocks: read_u64(buf, INODE_I_BLOCKS_OFFSET)?,
        })
    }

    /// File type from the mode bits.
    #[must_use]
    pub const fn file_type(&self) -> u16 {
        self.i_mode & S_IFMT
    }

    #[must_use]
    pub const fn is_regular(&self) -> bool { self.file_type() == S_IFREG }
    #[must_use]
    pub const fn is_directory(&self) -> bool { self.file_type() == S_IFDIR }
    #[must_use]
    pub const fn is_symlink(&self) -> bool { self.file_type() == S_IFLNK }
    #[must_use]
    pub const fn is_socket(&self) -> bool { self.file_type() == S_IFSOCK }
    #[must_use]
    pub const fn is_device(&self) -> bool {
        self.file_type() == S_IFBLK || self.file_type() == S_IFCHR
    }
}

// ===========================================================================
// struct dentry offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `dentry.d_flags` (dentry-specific flags).
pub const DENTRY_D_FLAGS_OFFSET: usize = 0x0000;
/// `dentry.d_seq` (seqlock for `d_inode`).
pub const DENTRY_D_SEQ_OFFSET: usize = 0x0004;
/// `dentry.d_hash` (lookup hash list).
pub const DENTRY_D_HASH_OFFSET: usize = 0x0008;
/// `dentry.d_parent` (pointer to parent dentry).
pub const DENTRY_D_PARENT_OFFSET: usize = 0x0018;
/// `dentry.d_name` (embedded qstr: `hash(4)+len(4)+name_ptr(8)` = 16 bytes).
pub const DENTRY_D_NAME_OFFSET: usize = 0x0020;
/// `dentry.d_inode` (pointer to associated inode, or NULL if negative).
pub const DENTRY_D_INODE_OFFSET: usize = 0x0030;
/// `dentry.d_iname[DNAME_INLINE_LEN]` (short inline name buffer, 40 bytes).
pub const DENTRY_D_INAME_OFFSET: usize = 0x0038;
pub const DNAME_INLINE_LEN: usize = 40;
/// `dentry.d_lockref` (lockref combining lock + refcount).
pub const DENTRY_D_LOCKREF_OFFSET: usize = 0x0060;
/// `dentry.d_op` (pointer to `dentry_operations`).
pub const DENTRY_D_OP_OFFSET: usize = 0x0068;
/// `dentry.d_sb` (pointer to `super_block`).
pub const DENTRY_D_SB_OFFSET: usize = 0x0070;
/// `dentry.d_time` (time of last revalidation).
pub const DENTRY_D_TIME_OFFSET: usize = 0x0078;
/// `dentry.d_fsdata` (fs-specific data).
pub const DENTRY_D_FSDATA_OFFSET: usize = 0x0080;
/// `dentry.d_child` (`list_head` in parent's `d_subdirs` list).
pub const DENTRY_D_CHILD_OFFSET: usize = 0x0088;
/// `dentry.d_subdirs` (`list_head` of child dentries).
pub const DENTRY_D_SUBDIRS_OFFSET: usize = 0x0098;
/// `dentry.d_alias` (`list_head` in inode's `i_dentry` list).
pub const DENTRY_D_ALIAS_OFFSET: usize = 0x00A8;
/// `dentry.d_u.d_in_lookup_hash` (in-lookup hash).
pub const DENTRY_D_IN_LOOKUP_HASH_OFFSET: usize = 0x00B8;
/// `dentry.d_rcu` (RCU head for deferred freeing).
pub const DENTRY_D_RCU_OFFSET: usize = 0x00C8;

/// `qstr` — embedded name in dentry.
#[derive(Debug, Clone)]
pub struct Qstr {
    pub hash: u32,
    pub len: u32,
    pub name_ptr: u64,
}

impl Qstr {
    #[must_use]
    pub fn parse(buf: &[u8], offset: usize) -> Option<Self> {
        Some(Self {
            hash: read_u32(buf, offset)?,
            len: read_u32(buf, offset + 4)?,
            name_ptr: read_u64(buf, offset + 8)?,
        })
    }
}

/// Parsed `struct dentry`.
#[derive(Debug, Clone)]
pub struct Dentry {
    pub address: u64,
    pub d_flags: u32,
    pub d_parent: u64,
    pub d_name: Qstr,
    pub d_inode: u64,
    /// Inline short name (up to 40 bytes).
    pub d_iname: String,
    pub d_sb: u64,
    pub d_op: u64,
}

impl Dentry {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            d_flags: read_u32(buf, DENTRY_D_FLAGS_OFFSET)?,
            d_parent: read_u64(buf, DENTRY_D_PARENT_OFFSET)?,
            d_name: Qstr::parse(buf, DENTRY_D_NAME_OFFSET)?,
            d_inode: read_u64(buf, DENTRY_D_INODE_OFFSET)?,
            d_iname: read_ansi_string(buf, DENTRY_D_INAME_OFFSET, DNAME_INLINE_LEN),
            d_sb: read_u64(buf, DENTRY_D_SB_OFFSET)?,
            d_op: read_u64(buf, DENTRY_D_OP_OFFSET)?,
        })
    }

    /// Returns `true` if the dentry is a negative (no inode) dentry.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.d_inode == 0
    }

    /// Returns `true` if this is the root dentry (`d_parent` points to itself).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.d_parent == self.address
    }
}

// ===========================================================================
// struct super_block offsets — Linux kernel 5.15, x86_64
// ===========================================================================

/// `super_block.s_dev` (device identifier).
pub const SB_S_DEV_OFFSET: usize = 0x0000;
/// `super_block.s_blocksize_bits` (log2 of the block size).
pub const SB_S_BLOCKSIZE_BITS_OFFSET: usize = 0x0004;
/// `super_block.s_blocksize` (filesystem block size in bytes).
pub const SB_S_BLOCKSIZE_OFFSET: usize = 0x0008;
/// `super_block.s_maxbytes` (maximum file size).
pub const SB_S_MAXBYTES_OFFSET: usize = 0x0010;
/// `super_block.s_type` (pointer to `file_system_type`).
pub const SB_S_TYPE_OFFSET: usize = 0x0018;
/// `super_block.s_op` (pointer to `super_operations`).
pub const SB_S_OP_OFFSET: usize = 0x0020;
/// `super_block.s_flags` (mount flags `MS_RDONLY`, etc.).
pub const SB_S_FLAGS_OFFSET: usize = 0x0070;
/// `super_block.s_iflags` (internal super block flags SB_*).
pub const SB_S_IFLAGS_OFFSET: usize = 0x0078;
/// `super_block.s_magic` (filesystem magic number).
pub const SB_S_MAGIC_OFFSET: usize = 0x0080;
/// `super_block.s_root` (pointer to the root dentry).
pub const SB_S_ROOT_OFFSET: usize = 0x0088;
/// `super_block.s_inodes` (`list_head` of all inodes on this sb).
pub const SB_S_INODES_OFFSET: usize = 0x0180;
/// `super_block.s_fs_info` (filesystem-specific private info).
pub const SB_S_FS_INFO_OFFSET: usize = 0x0230;

/// Common filesystem magic numbers.
pub const EXT4_SUPER_MAGIC: u64 = 0xEF53;
pub const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
pub const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
pub const PROC_SUPER_MAGIC: u64 = 0x9FA0;
pub const SYSFS_MAGIC: u64 = 0x6269_7473;
pub const DEVTMPFS_MAGIC: u64 = 0x0001_0000;

/// Parsed `struct super_block`.
#[derive(Debug, Clone)]
pub struct SuperBlock {
    pub address: u64,
    pub s_dev: u32,
    pub s_blocksize: u64,
    pub s_maxbytes: i64,
    pub s_flags: u64,
    pub s_magic: u64,
    pub s_root: u64,
    pub s_fs_info: u64,
}

impl SuperBlock {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            s_dev: read_u32(buf, SB_S_DEV_OFFSET)?,
            s_blocksize: read_u64(buf, SB_S_BLOCKSIZE_OFFSET)?,
            s_maxbytes: (read_u64(buf, SB_S_MAXBYTES_OFFSET)?).cast_signed(),
            s_flags: read_u64(buf, SB_S_FLAGS_OFFSET)?,
            s_magic: read_u64(buf, SB_S_MAGIC_OFFSET)?,
            s_root: read_u64(buf, SB_S_ROOT_OFFSET)?,
            s_fs_info: read_u64(buf, SB_S_FS_INFO_OFFSET).unwrap_or(0),
        })
    }

    /// Human-readable filesystem type from magic number.
    #[must_use]
    pub const fn fs_type(&self) -> &'static str {
        match self.s_magic {
            EXT4_SUPER_MAGIC => "ext4",
            XFS_SUPER_MAGIC => "xfs",
            BTRFS_SUPER_MAGIC => "btrfs",
            TMPFS_MAGIC => "tmpfs",
            PROC_SUPER_MAGIC => "proc",
            SYSFS_MAGIC => "sysfs",
            DEVTMPFS_MAGIC => "devtmpfs",
            _ => "unknown",
        }
    }

    /// Returns `true` if the filesystem is mounted read-only.
    #[must_use]
    pub const fn is_readonly(&self) -> bool {
        self.s_flags & 0x0001 != 0
    }
}

// ===========================================================================
// struct cred offsets — Linux kernel 5.15, x86_64
// ===========================================================================

pub const CRED_USAGE_OFFSET: usize = 0x0000;
pub const CRED_UID_OFFSET: usize = 0x0004;
pub const CRED_GID_OFFSET: usize = 0x0008;
pub const CRED_SUID_OFFSET: usize = 0x000C;
pub const CRED_SGID_OFFSET: usize = 0x0010;
pub const CRED_EUID_OFFSET: usize = 0x0014;
pub const CRED_EGID_OFFSET: usize = 0x0018;
pub const CRED_FSUID_OFFSET: usize = 0x001C;
pub const CRED_FSGID_OFFSET: usize = 0x0020;
pub const CRED_SECUREBITS_OFFSET: usize = 0x0024;
pub const CRED_CAP_INHERITABLE_OFFSET: usize = 0x0028;
pub const CRED_CAP_PERMITTED_OFFSET: usize = 0x0030;
pub const CRED_CAP_EFFECTIVE_OFFSET: usize = 0x0038;
pub const CRED_CAP_BSET_OFFSET: usize = 0x0040;
pub const CRED_CAP_AMBIENT_OFFSET: usize = 0x0048;
pub const CRED_USER_OFFSET: usize = 0x0068;
pub const CRED_USER_NS_OFFSET: usize = 0x0070;

/// Linux capability set (`kernel_cap_t` = two u32s = one u64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCap(pub u64);

impl KernelCap {
    /// Returns `true` if the capability bit `cap` is set (0..63).
    #[must_use]
    pub const fn has_cap(&self, cap: u8) -> bool {
        if cap >= 64 { return false; }
        self.0 & (1u64 << cap) != 0
    }

    /// `CAP_SYS_ADMIN` (21).
    #[must_use]
    pub const fn has_sys_admin(&self) -> bool { self.has_cap(21) }

    /// `CAP_NET_RAW` (13).
    #[must_use]
    pub const fn has_net_raw(&self) -> bool { self.has_cap(13) }

    /// Returns `true` if all capability bits are set (full caps, like root).
    #[must_use]
    pub const fn is_full(&self) -> bool { self.0 == u64::MAX }
}

/// Parsed `struct cred`.
#[derive(Debug, Clone)]
pub struct Cred {
    pub address: u64,
    pub uid: u32,
    pub gid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub securebits: u32,
    pub cap_inheritable: KernelCap,
    pub cap_permitted: KernelCap,
    pub cap_effective: KernelCap,
    pub cap_bset: KernelCap,
    pub cap_ambient: KernelCap,
}

impl Cred {
    #[must_use]
    pub fn parse(buf: &[u8], base_addr: u64) -> Option<Self> {
        Some(Self {
            address: base_addr,
            uid: read_u32(buf, CRED_UID_OFFSET)?,
            gid: read_u32(buf, CRED_GID_OFFSET)?,
            suid: read_u32(buf, CRED_SUID_OFFSET)?,
            sgid: read_u32(buf, CRED_SGID_OFFSET)?,
            euid: read_u32(buf, CRED_EUID_OFFSET)?,
            egid: read_u32(buf, CRED_EGID_OFFSET)?,
            fsuid: read_u32(buf, CRED_FSUID_OFFSET)?,
            fsgid: read_u32(buf, CRED_FSGID_OFFSET)?,
            securebits: read_u32(buf, CRED_SECUREBITS_OFFSET)?,
            cap_inheritable: KernelCap(read_u64(buf, CRED_CAP_INHERITABLE_OFFSET)?),
            cap_permitted: KernelCap(read_u64(buf, CRED_CAP_PERMITTED_OFFSET)?),
            cap_effective: KernelCap(read_u64(buf, CRED_CAP_EFFECTIVE_OFFSET)?),
            cap_bset: KernelCap(read_u64(buf, CRED_CAP_BSET_OFFSET)?),
            cap_ambient: KernelCap(read_u64(buf, CRED_CAP_AMBIENT_OFFSET)?),
        })
    }

    /// Returns `true` if the effective user is root (euid == 0).
    #[must_use]
    pub const fn is_root(&self) -> bool { self.euid == 0 }

    /// Returns `true` if the credentials suggest privilege escalation:
    /// non-root UID but effective `CAP_SYS_ADMIN`.
    #[must_use]
    pub const fn is_potentially_escalated(&self) -> bool {
        self.uid != 0 && self.cap_effective.has_sys_admin()
    }
}

// ===========================================================================
// KASLR helpers
// ===========================================================================

/// Well-known kernel base alignment (2 MiB).
pub const KERNEL_BASE_ALIGN: u64 = 0x20_0000;

/// The Linux kernel starts at a randomized offset above `KIMAGE_VADDR`.
/// On `x86_64` with a 4-level page table, the kernel VMA is typically in
/// `0xFFFF_FFFF_8000_0000 .. 0xFFFF_FFFF_FFFF_FFFF`.
pub const KIMAGE_VADDR: u64 = 0xFFFF_FFFF_8000_0000;

/// Physical base of the kernel image in a default layout (without KASLR).
pub const KERNEL_PHYS_BASE: u64 = 0x0100_0000;

/// Canonical "`startup_64`" offset from the kernel base on many builds.
pub const STARTUP_64_OFFSET: u64 = 0x1_0000_0000;

/// Returns `true` if the given address is in the kernel virtual address range.
#[must_use]
pub const fn is_kernel_address(addr: u64) -> bool {
    addr >= 0xFFFF_8000_0000_0000
}

/// Attempt to find the kernel base by searching for ELF magic or the
/// `_text` symbol signature at 2 MiB aligned boundaries.
#[must_use]
pub fn find_kernel_base(memory: &[u8], search_start: u64) -> Option<u64> {
    // Align search_start down to KERNEL_BASE_ALIGN
    let mut addr = search_start & !(KERNEL_BASE_ALIGN - 1);
    let align = u64_to_usize(KERNEL_BASE_ALIGN);
    let mut offset = 0usize;
    while offset + 4 <= memory.len() {
        // ELF magic: \x7FELF
        if &memory[offset..offset + 4] == b"\x7FELF" {
            return Some(addr);
        }
        offset += align;
        addr = addr.wrapping_add(KERNEL_BASE_ALIGN);
    }
    None
}

// ===========================================================================
// Symbol map parser
// ===========================================================================

/// A single entry from `/proc/kallsyms` or `System.map`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolEntry {
    pub address: u64,
    pub sym_type: char,
    pub name: String,
}

/// Parse a `/proc/kallsyms` or `System.map` line.
/// Format: `<hex_addr> <type> <name>`.
#[must_use]
pub fn parse_symbol_line(line: &str) -> Option<SymbolEntry> {
    let mut parts = line.split_whitespace();
    let addr_str = parts.next()?;
    let type_str = parts.next()?;
    let name = parts.next()?.to_string();
    let address = u64::from_str_radix(addr_str, 16).ok()?;
    let sym_type = type_str.chars().next()?;
    Some(SymbolEntry { address, sym_type, name })
}

/// Parse a complete symbol map (multiple lines).
#[must_use]
pub fn parse_symbol_map(text: &str) -> Vec<SymbolEntry> {
    text.lines().filter_map(parse_symbol_line).collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- task_struct tests ----

    fn make_task_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x1000];
        // state = 0 (runnable)
        buf[TASK_STATE_OFFSET..TASK_STATE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        // flags = PF_KTHREAD | PF_SUPERPRIV
        let flags = PF_SUPERPRIV;
        buf[TASK_FLAGS_OFFSET..TASK_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
        // prio = 120 (default)
        buf[TASK_PRIO_OFFSET..TASK_PRIO_OFFSET + 4].copy_from_slice(&120u32.to_le_bytes());
        buf[TASK_STATIC_PRIO_OFFSET..TASK_STATIC_PRIO_OFFSET + 4]
            .copy_from_slice(&120u32.to_le_bytes());
        // pid = 1234, tgid = 1234
        buf[TASK_PID_OFFSET..TASK_PID_OFFSET + 4].copy_from_slice(&1234u32.to_le_bytes());
        buf[TASK_TGID_OFFSET..TASK_TGID_OFFSET + 4].copy_from_slice(&1234u32.to_le_bytes());
        // comm = "init"
        let comm = b"init\0";
        buf[TASK_COMM_OFFSET..TASK_COMM_OFFSET + comm.len()].copy_from_slice(comm);
        // mm = non-zero (user process)
        buf[TASK_MM_OFFSET..TASK_MM_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8800_1234_0000u64.to_le_bytes());
        buf[TASK_ACTIVE_MM_OFFSET..TASK_ACTIVE_MM_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8800_1234_0000u64.to_le_bytes());
        // real_parent / parent
        buf[TASK_REAL_PARENT_OFFSET..TASK_REAL_PARENT_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8801_0000_0000u64.to_le_bytes());
        buf[TASK_PARENT_OFFSET..TASK_PARENT_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8801_0000_0000u64.to_le_bytes());
        buf[TASK_GROUP_LEADER_OFFSET..TASK_GROUP_LEADER_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8802_0000_0000u64.to_le_bytes());
        buf[TASK_THREAD_PID_OFFSET..TASK_THREAD_PID_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8803_0000_0000u64.to_le_bytes());
        buf[TASK_NSPROXY_OFFSET..TASK_NSPROXY_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8804_0000_0000u64.to_le_bytes());
        buf[TASK_CRED_OFFSET..TASK_CRED_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8805_0000_0000u64.to_le_bytes());
        buf[TASK_SIGNAL_OFFSET..TASK_SIGNAL_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8806_0000_0000u64.to_le_bytes());
        buf[TASK_SIGHAND_OFFSET..TASK_SIGHAND_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8807_0000_0000u64.to_le_bytes());
        buf[TASK_FILES_OFFSET..TASK_FILES_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8808_0000_0000u64.to_le_bytes());
        buf[TASK_FS_OFFSET..TASK_FS_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8809_0000_0000u64.to_le_bytes());
        buf[TASK_START_TIME_OFFSET..TASK_START_TIME_OFFSET + 8]
            .copy_from_slice(&123_456_789u64.to_le_bytes());
        buf[TASK_OOM_SCORE_ADJ_OFFSET..TASK_OOM_SCORE_ADJ_OFFSET + 2]
            .copy_from_slice(&0i16.to_le_bytes());
        buf[TASK_LOGINUID_OFFSET..TASK_LOGINUID_OFFSET + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        buf[TASK_SESSIONID_OFFSET..TASK_SESSIONID_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf
    }

    #[test]
    fn task_parse_pid() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0xFFFF_8800_DEAD_0000).unwrap();
        assert_eq!(t.pid, 1234);
    }

    #[test]
    fn task_parse_tgid() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert_eq!(t.tgid, 1234);
    }

    #[test]
    fn task_parse_comm() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert_eq!(t.comm, "init");
    }

    #[test]
    fn task_is_not_kernel_thread() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert!(!t.is_kernel_thread());
    }

    #[test]
    fn task_kernel_thread() {
        let mut buf = make_task_buf();
        buf[TASK_MM_OFFSET..TASK_MM_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert!(t.is_kernel_thread());
    }

    #[test]
    fn task_is_thread_group_leader() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert!(t.is_thread_group_leader());
    }

    #[test]
    fn task_nice_zero() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert_eq!(t.nice(), 0);
    }

    #[test]
    fn task_loginuid() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert_eq!(t.loginuid, 1000);
    }

    #[test]
    fn task_start_time() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert_eq!(t.start_time, 123_456_789);
    }

    // ---- mm_struct tests ----

    fn make_mm_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x600];
        buf[MM_MMAP_OFFSET..MM_MMAP_OFFSET + 8]
            .copy_from_slice(&0x7F00_1234_0000u64.to_le_bytes());
        buf[MM_PGD_OFFSET..MM_PGD_OFFSET + 8]
            .copy_from_slice(&0xA000u64.to_le_bytes());
        buf[MM_MM_USERS_OFFSET..MM_MM_USERS_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[MM_MM_COUNT_OFFSET..MM_MM_COUNT_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[MM_MAP_COUNT_OFFSET..MM_MAP_COUNT_OFFSET + 4].copy_from_slice(&10u32.to_le_bytes());
        buf[MM_TOTAL_VM_OFFSET..MM_TOTAL_VM_OFFSET + 8].copy_from_slice(&2048u64.to_le_bytes());
        buf[MM_LOCKED_VM_OFFSET..MM_LOCKED_VM_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[MM_PINNED_VM_OFFSET..MM_PINNED_VM_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[MM_DATA_VM_OFFSET..MM_DATA_VM_OFFSET + 8].copy_from_slice(&100u64.to_le_bytes());
        buf[MM_EXEC_VM_OFFSET..MM_EXEC_VM_OFFSET + 8].copy_from_slice(&50u64.to_le_bytes());
        buf[MM_STACK_VM_OFFSET..MM_STACK_VM_OFFSET + 8].copy_from_slice(&8u64.to_le_bytes());
        buf[MM_DEF_FLAGS_OFFSET..MM_DEF_FLAGS_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[MM_START_CODE_OFFSET..MM_START_CODE_OFFSET + 8]
            .copy_from_slice(&0x0000_4000_0000u64.to_le_bytes());
        buf[MM_END_CODE_OFFSET..MM_END_CODE_OFFSET + 8]
            .copy_from_slice(&0x0000_4010_0000u64.to_le_bytes());
        buf[MM_START_DATA_OFFSET..MM_START_DATA_OFFSET + 8]
            .copy_from_slice(&0x0000_4010_0000u64.to_le_bytes());
        buf[MM_END_DATA_OFFSET..MM_END_DATA_OFFSET + 8]
            .copy_from_slice(&0x0000_4011_0000u64.to_le_bytes());
        buf[MM_START_BRK_OFFSET..MM_START_BRK_OFFSET + 8]
            .copy_from_slice(&0x0000_4100_0000u64.to_le_bytes());
        buf[MM_BRK_OFFSET..MM_BRK_OFFSET + 8]
            .copy_from_slice(&0x0000_4200_0000u64.to_le_bytes());
        buf[MM_START_STACK_OFFSET..MM_START_STACK_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFE_0000u64.to_le_bytes());
        buf[MM_ARG_START_OFFSET..MM_ARG_START_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFD_0000u64.to_le_bytes());
        buf[MM_ARG_END_OFFSET..MM_ARG_END_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFD_0100u64.to_le_bytes());
        buf[MM_ENV_START_OFFSET..MM_ENV_START_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFD_0100u64.to_le_bytes());
        buf[MM_ENV_END_OFFSET..MM_ENV_END_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFD_0200u64.to_le_bytes());
        buf[MM_TASK_SIZE_OFFSET..MM_TASK_SIZE_OFFSET + 8]
            .copy_from_slice(&0x7FFF_FFFF_F000u64.to_le_bytes());
        buf[MM_MMAP_BASE_OFFSET..MM_MMAP_BASE_OFFSET + 8]
            .copy_from_slice(&0x7F00_0000_0000u64.to_le_bytes());
        buf[MM_EXE_FILE_OFFSET..MM_EXE_FILE_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8800_BEEF_0000u64.to_le_bytes());
        buf[MM_OWNER_OFFSET..MM_OWNER_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8801_0000_0000u64.to_le_bytes());
        buf[MM_PGTABLES_BYTES_OFFSET..MM_PGTABLES_BYTES_OFFSET + 8]
            .copy_from_slice(&0x4000u64.to_le_bytes());
        buf
    }

    #[test]
    fn mm_parse_mmap() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.mmap, 0x7F00_1234_0000);
    }

    #[test]
    fn mm_parse_map_count() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.map_count, 10);
    }

    #[test]
    fn mm_heap_size() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.heap_size(), 0x100_0000);
    }

    #[test]
    fn mm_code_size() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.code_size(), 0x10_0000);
    }

    #[test]
    fn mm_parse_pgd() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.pgd, 0xA000);
    }

    // ---- vm_area_struct tests ----

    fn make_vma_buf(start: u64, end: u64, flags: u64, vm_file: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        buf[VMA_VM_START_OFFSET..VMA_VM_START_OFFSET + 8].copy_from_slice(&start.to_le_bytes());
        buf[VMA_VM_END_OFFSET..VMA_VM_END_OFFSET + 8].copy_from_slice(&end.to_le_bytes());
        buf[VMA_VM_NEXT_OFFSET..VMA_VM_NEXT_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_PREV_OFFSET..VMA_VM_PREV_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_MM_OFFSET..VMA_VM_MM_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_PAGE_PROT_OFFSET..VMA_VM_PAGE_PROT_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_FLAGS_OFFSET..VMA_VM_FLAGS_OFFSET + 8].copy_from_slice(&flags.to_le_bytes());
        buf[VMA_ANON_VMA_OFFSET..VMA_ANON_VMA_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_OPS_OFFSET..VMA_VM_OPS_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_PGOFF_OFFSET..VMA_VM_PGOFF_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[VMA_VM_FILE_OFFSET..VMA_VM_FILE_OFFSET + 8].copy_from_slice(&vm_file.to_le_bytes());
        buf[VMA_VM_PRIVATE_DATA_OFFSET..VMA_VM_PRIVATE_DATA_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        buf
    }

    #[test]
    fn vma_parse_size() {
        let buf = make_vma_buf(0x1000_0000, 0x1010_0000, VM_READ | VM_EXEC, 0);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert_eq!(vma.size(), 0x10_0000);
    }

    #[test]
    fn vma_parse_readable_executable() {
        let buf = make_vma_buf(0x1000_0000, 0x1010_0000, VM_READ | VM_EXEC, 0);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert!(vma.is_readable());
        assert!(vma.is_executable());
        assert!(!vma.is_writable());
    }

    #[test]
    fn vma_is_anonymous() {
        let buf = make_vma_buf(0x1000, 0x2000, VM_READ | VM_WRITE, 0);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert!(vma.is_anonymous());
    }

    #[test]
    fn vma_is_not_anonymous() {
        let buf = make_vma_buf(0x1000, 0x2000, VM_READ | VM_EXEC, 0xFFFF_1234_0000);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert!(!vma.is_anonymous());
    }

    #[test]
    fn vma_suspicious_rwx() {
        let buf = make_vma_buf(0x1000, 0x2000, VM_READ | VM_WRITE | VM_EXEC, 0);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert!(vma.is_suspicious_rwx());
    }

    #[test]
    fn vma_perm_str() {
        let buf = make_vma_buf(0x1000, 0x2000, VM_READ | VM_EXEC, 0);
        let vma = VmAreaStruct::parse(&buf, 0).unwrap();
        assert_eq!(vma.perm_str(), "r-x");
    }

    // ---- inode tests ----

    fn make_inode_buf(mode: u16, size: i64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        buf[INODE_I_MODE_OFFSET..INODE_I_MODE_OFFSET + 2].copy_from_slice(&mode.to_le_bytes());
        buf[INODE_I_UID_OFFSET..INODE_I_UID_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[INODE_I_GID_OFFSET..INODE_I_GID_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[INODE_I_FLAGS_OFFSET..INODE_I_FLAGS_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[INODE_I_SB_OFFSET..INODE_I_SB_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8800_0000_0000u64.to_le_bytes());
        buf[INODE_I_INO_OFFSET..INODE_I_INO_OFFSET + 8].copy_from_slice(&12345u64.to_le_bytes());
        buf[INODE_I_NLINK_OFFSET..INODE_I_NLINK_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[INODE_I_SIZE_OFFSET..INODE_I_SIZE_OFFSET + 8]
            .copy_from_slice(&(size as u64).to_le_bytes());
        buf[INODE_I_BLOCKS_OFFSET..INODE_I_BLOCKS_OFFSET + 8].copy_from_slice(&8u64.to_le_bytes());
        buf
    }

    #[test]
    fn inode_is_regular() {
        let buf = make_inode_buf(S_IFREG | 0o644, 4096);
        let inode = Inode::parse(&buf, 0).unwrap();
        assert!(inode.is_regular());
        assert!(!inode.is_directory());
    }

    #[test]
    fn inode_is_directory() {
        let buf = make_inode_buf(S_IFDIR | 0o755, 4096);
        let inode = Inode::parse(&buf, 0).unwrap();
        assert!(inode.is_directory());
        assert!(!inode.is_regular());
    }

    #[test]
    fn inode_is_symlink() {
        let buf = make_inode_buf(S_IFLNK | 0o777, 7);
        let inode = Inode::parse(&buf, 0).unwrap();
        assert!(inode.is_symlink());
    }

    #[test]
    fn inode_i_ino() {
        let buf = make_inode_buf(S_IFREG | 0o644, 100);
        let inode = Inode::parse(&buf, 0).unwrap();
        assert_eq!(inode.i_ino, 12345);
    }

    #[test]
    fn inode_size() {
        let buf = make_inode_buf(S_IFREG | 0o644, 8192);
        let inode = Inode::parse(&buf, 0).unwrap();
        assert_eq!(inode.i_size, 8192);
    }

    // ---- dentry tests ----

    fn make_dentry_buf(name: &[u8], d_parent: u64, d_inode: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        buf[DENTRY_D_FLAGS_OFFSET..DENTRY_D_FLAGS_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[DENTRY_D_PARENT_OFFSET..DENTRY_D_PARENT_OFFSET + 8]
            .copy_from_slice(&d_parent.to_le_bytes());
        // d_name: hash(4) len(4) ptr(8)
        buf[DENTRY_D_NAME_OFFSET..DENTRY_D_NAME_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let len = name.len() as u32;
        buf[DENTRY_D_NAME_OFFSET + 4..DENTRY_D_NAME_OFFSET + 8]
            .copy_from_slice(&len.to_le_bytes());
        buf[DENTRY_D_NAME_OFFSET + 8..DENTRY_D_NAME_OFFSET + 16]
            .copy_from_slice(&0u64.to_le_bytes()); // ptr irrelevant for inline
        buf[DENTRY_D_INODE_OFFSET..DENTRY_D_INODE_OFFSET + 8]
            .copy_from_slice(&d_inode.to_le_bytes());
        // inline name
        let copy_len = name.len().min(DNAME_INLINE_LEN);
        buf[DENTRY_D_INAME_OFFSET..DENTRY_D_INAME_OFFSET + copy_len]
            .copy_from_slice(&name[..copy_len]);
        buf[DENTRY_D_SB_OFFSET..DENTRY_D_SB_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8800_0000_0000u64.to_le_bytes());
        buf[DENTRY_D_OP_OFFSET..DENTRY_D_OP_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf
    }

    #[test]
    fn dentry_parse_iname() {
        let buf = make_dentry_buf(b"passwd\0", 0, 0xFFFF_1234_0000);
        let d = Dentry::parse(&buf, 0).unwrap();
        assert_eq!(d.d_iname, "passwd");
    }

    #[test]
    fn dentry_not_negative() {
        let buf = make_dentry_buf(b"bin\0", 0, 0xFFFF_1234_0000);
        let d = Dentry::parse(&buf, 0).unwrap();
        assert!(!d.is_negative());
    }

    #[test]
    fn dentry_negative() {
        let buf = make_dentry_buf(b"ghost\0", 0, 0);
        let d = Dentry::parse(&buf, 0).unwrap();
        assert!(d.is_negative());
    }

    #[test]
    fn dentry_root() {
        let addr = 0xFFFF_8801_0000_0000u64;
        let mut buf = make_dentry_buf(b"/\0", addr, 0xFFFF_0000);
        // d_parent already set to addr
        buf[DENTRY_D_PARENT_OFFSET..DENTRY_D_PARENT_OFFSET + 8]
            .copy_from_slice(&addr.to_le_bytes());
        let d = Dentry::parse(&buf, addr).unwrap();
        assert!(d.is_root());
    }

    // ---- super_block tests ----

    fn make_sb_buf(magic: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x300];
        buf[SB_S_DEV_OFFSET..SB_S_DEV_OFFSET + 4].copy_from_slice(&0x0802u32.to_le_bytes());
        buf[SB_S_BLOCKSIZE_OFFSET..SB_S_BLOCKSIZE_OFFSET + 8]
            .copy_from_slice(&4096u64.to_le_bytes());
        buf[SB_S_MAXBYTES_OFFSET..SB_S_MAXBYTES_OFFSET + 8]
            .copy_from_slice(&i64::MAX.to_le_bytes());
        buf[SB_S_FLAGS_OFFSET..SB_S_FLAGS_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        buf[SB_S_MAGIC_OFFSET..SB_S_MAGIC_OFFSET + 8].copy_from_slice(&magic.to_le_bytes());
        buf[SB_S_ROOT_OFFSET..SB_S_ROOT_OFFSET + 8]
            .copy_from_slice(&0xFFFF_8801_0000_0000u64.to_le_bytes());
        buf
    }

    #[test]
    fn superblock_ext4() {
        let buf = make_sb_buf(EXT4_SUPER_MAGIC);
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert_eq!(sb.fs_type(), "ext4");
    }

    #[test]
    fn superblock_xfs() {
        let buf = make_sb_buf(XFS_SUPER_MAGIC);
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert_eq!(sb.fs_type(), "xfs");
    }

    #[test]
    fn superblock_tmpfs() {
        let buf = make_sb_buf(TMPFS_MAGIC);
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert_eq!(sb.fs_type(), "tmpfs");
    }

    #[test]
    fn superblock_not_readonly() {
        let buf = make_sb_buf(EXT4_SUPER_MAGIC);
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert!(!sb.is_readonly());
    }

    #[test]
    fn superblock_readonly() {
        let mut buf = make_sb_buf(EXT4_SUPER_MAGIC);
        buf[SB_S_FLAGS_OFFSET] = 0x01;
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert!(sb.is_readonly());
    }

    // ---- cred tests ----

    fn make_cred_buf(uid: u32, euid: u32, cap_effective: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        buf[CRED_UID_OFFSET..CRED_UID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_GID_OFFSET..CRED_GID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_SUID_OFFSET..CRED_SUID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_SGID_OFFSET..CRED_SGID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_EUID_OFFSET..CRED_EUID_OFFSET + 4].copy_from_slice(&euid.to_le_bytes());
        buf[CRED_EGID_OFFSET..CRED_EGID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_FSUID_OFFSET..CRED_FSUID_OFFSET + 4].copy_from_slice(&euid.to_le_bytes());
        buf[CRED_FSGID_OFFSET..CRED_FSGID_OFFSET + 4].copy_from_slice(&uid.to_le_bytes());
        buf[CRED_SECUREBITS_OFFSET..CRED_SECUREBITS_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        buf[CRED_CAP_INHERITABLE_OFFSET..CRED_CAP_INHERITABLE_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        buf[CRED_CAP_PERMITTED_OFFSET..CRED_CAP_PERMITTED_OFFSET + 8]
            .copy_from_slice(&cap_effective.to_le_bytes());
        buf[CRED_CAP_EFFECTIVE_OFFSET..CRED_CAP_EFFECTIVE_OFFSET + 8]
            .copy_from_slice(&cap_effective.to_le_bytes());
        buf[CRED_CAP_BSET_OFFSET..CRED_CAP_BSET_OFFSET + 8]
            .copy_from_slice(&cap_effective.to_le_bytes());
        buf[CRED_CAP_AMBIENT_OFFSET..CRED_CAP_AMBIENT_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        buf
    }

    #[test]
    fn cred_root() {
        let buf = make_cred_buf(0, 0, u64::MAX);
        let cred = Cred::parse(&buf, 0).unwrap();
        assert!(cred.is_root());
    }

    #[test]
    fn cred_not_root() {
        let buf = make_cred_buf(1000, 1000, 0);
        let cred = Cred::parse(&buf, 0).unwrap();
        assert!(!cred.is_root());
    }

    #[test]
    fn cred_has_sys_admin() {
        let cap = 1u64 << 21; // CAP_SYS_ADMIN
        let buf = make_cred_buf(1000, 1000, cap);
        let cred = Cred::parse(&buf, 0).unwrap();
        assert!(cred.cap_effective.has_sys_admin());
    }

    #[test]
    fn cred_escalated() {
        let cap = 1u64 << 21;
        let buf = make_cred_buf(1000, 1000, cap);
        let cred = Cred::parse(&buf, 0).unwrap();
        assert!(cred.is_potentially_escalated());
    }

    #[test]
    fn cred_full_caps() {
        let buf = make_cred_buf(0, 0, u64::MAX);
        let cred = Cred::parse(&buf, 0).unwrap();
        assert!(cred.cap_effective.is_full());
    }

    // ---- symbol map tests ----

    #[test]
    fn parse_symbol_line_valid() {
        let entry = parse_symbol_line("ffffffff81000000 T startup_64").unwrap();
        assert_eq!(entry.address, 0xFFFF_FFFF_8100_0000);
        assert_eq!(entry.sym_type, 'T');
        assert_eq!(entry.name, "startup_64");
    }

    #[test]
    fn parse_symbol_line_invalid() {
        assert!(parse_symbol_line("not a symbol line").is_none());
    }

    #[test]
    fn parse_symbol_map_multiple() {
        let text = "ffffffff81000000 T startup_64\nffffffff81001000 t secondary_startup_64\n";
        let map = parse_symbol_map(text);
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].name, "startup_64");
        assert_eq!(map[1].name, "secondary_startup_64");
    }

    #[test]
    fn is_kernel_address_true() {
        assert!(is_kernel_address(0xFFFF_8800_0000_0000));
    }

    #[test]
    fn is_kernel_address_false() {
        assert!(!is_kernel_address(0x0000_7FFF_FFFF_F000));
    }

    #[test]
    fn kernel_cap_sys_admin_bit() {
        let cap = KernelCap(1u64 << 21);
        assert!(cap.has_sys_admin());
        assert!(!cap.has_net_raw());
    }

    #[test]
    fn kernel_cap_out_of_range() {
        let cap = KernelCap(u64::MAX);
        assert!(!cap.has_cap(64));
    }

    #[test]
    fn pf_kthread_constant() {
        // PF_KTHREAD = 0x0020_0000
        assert_eq!(PF_KTHREAD, 0x0020_0000);
    }

    #[test]
    fn vm_exec_constant() {
        assert_eq!(VM_EXEC, 0x0000_0004);
    }

    #[test]
    fn find_kernel_base_elf_magic() {
        // Buffer must be large enough to contain 4 bytes at offset = 2 * KERNEL_BASE_ALIGN.
        let mut mem = vec![0u8; 0x40_0000 + 4];
        let offset = KERNEL_BASE_ALIGN as usize * 2; // 4 MiB
        mem[offset..offset + 4].copy_from_slice(b"\x7FELF");
        let base = find_kernel_base(&mem, 0xFFFF_FFFF_8000_0000);
        assert!(base.is_some());
    }

    #[test]
    fn superblock_unknown_magic() {
        let buf = make_sb_buf(0xDEAD_BEEF_1234);
        let sb = SuperBlock::parse(&buf, 0).unwrap();
        assert_eq!(sb.fs_type(), "unknown");
    }

    #[test]
    fn task_not_ptraced() {
        let buf = make_task_buf();
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert!(!t.is_ptraced());
    }

    #[test]
    fn task_ptraced() {
        let mut buf = make_task_buf();
        buf[TASK_PTRACE_OFFSET..TASK_PTRACE_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        let t = TaskStruct::parse(&buf, 0).unwrap();
        assert!(t.is_ptraced());
    }

    #[test]
    fn mm_exe_file() {
        let buf = make_mm_buf();
        let mm = MmStruct::parse(&buf, 0).unwrap();
        assert_eq!(mm.exe_file, 0xFFFF_8800_BEEF_0000);
    }
}
