
// ─── AArch64-specific syscall table ──────────────────────────────────────────
// AArch64 uses a different numbering from x86_64.

pub static AARCH64_SPECIFIC_SYSCALLS: &[StaticSyscall] = &[
    StaticSyscall::new(0,   "io_setup", 2),
    StaticSyscall::new(1,   "io_destroy", 1),
    StaticSyscall::new(2,   "io_submit", 3),
    StaticSyscall::new(3,   "io_cancel", 3),
    StaticSyscall::new(4,   "io_getevents", 5),
    StaticSyscall::new(5,   "setxattr", 5),
    StaticSyscall::new(6,   "lsetxattr", 5),
    StaticSyscall::new(7,   "fsetxattr", 5),
    StaticSyscall::new(8,   "getxattr", 4),
    StaticSyscall::new(9,   "lgetxattr", 4),
    StaticSyscall::new(10,  "fgetxattr", 4),
    StaticSyscall::new(11,  "listxattr", 3),
    StaticSyscall::new(12,  "llistxattr", 3),
    StaticSyscall::new(13,  "flistxattr", 3),
    StaticSyscall::new(14,  "removexattr", 2),
    StaticSyscall::new(15,  "lremovexattr", 2),
    StaticSyscall::new(16,  "fremovexattr", 2),
    StaticSyscall::new(17,  "getcwd", 2),
    StaticSyscall::new(18,  "lookup_dcookie", 3),
    StaticSyscall::new(19,  "eventfd2", 2),
    StaticSyscall::new(20,  "epoll_create1", 1),
    StaticSyscall::new(21,  "epoll_ctl", 4),
    StaticSyscall::new(22,  "epoll_pwait", 6),
    StaticSyscall::new(23,  "dup", 1),
    StaticSyscall::new(24,  "dup3", 3),
    StaticSyscall::new(25,  "fcntl", 3),
    StaticSyscall::new(26,  "inotify_init1", 1),
    StaticSyscall::new(27,  "inotify_add_watch", 3),
    StaticSyscall::new(28,  "inotify_rm_watch", 2),
    StaticSyscall::new(29,  "ioctl", 3),
    StaticSyscall::new(30,  "ioprio_set", 3),
    StaticSyscall::new(31,  "ioprio_get", 2),
    StaticSyscall::new(32,  "flock", 2),
    StaticSyscall::new(33,  "mknodat", 4),
    StaticSyscall::new(34,  "mkdirat", 3),
    StaticSyscall::new(35,  "unlinkat", 3),
    StaticSyscall::new(36,  "symlinkat", 3),
    StaticSyscall::new(37,  "linkat", 5),
    StaticSyscall::new(38,  "renameat", 4),
    StaticSyscall::new(39,  "umount2", 2),
    StaticSyscall::new(40,  "mount", 5),
    StaticSyscall::new(41,  "pivot_root", 2),
    StaticSyscall::new(42,  "nfsservctl", 3),
    StaticSyscall::new(43,  "statfs", 2),
    StaticSyscall::new(44,  "fstatfs", 2),
    StaticSyscall::new(45,  "truncate", 2),
    StaticSyscall::new(46,  "ftruncate", 2),
    StaticSyscall::new(47,  "fallocate", 4),
    StaticSyscall::new(48,  "faccessat", 3),
    StaticSyscall::new(49,  "chdir", 1),
    StaticSyscall::new(50,  "fchdir", 1),
    StaticSyscall::new(51,  "chroot", 1),
    StaticSyscall::new(52,  "fchmod", 2),
    StaticSyscall::new(53,  "fchmodat", 4),
    StaticSyscall::new(54,  "fchownat", 5),
    StaticSyscall::new(55,  "fchown", 3),
    StaticSyscall::new(56,  "openat", 4),
    StaticSyscall::new(57,  "close", 1),
    StaticSyscall::new(58,  "vhangup", 0),
    StaticSyscall::new(59,  "pipe2", 2),
    StaticSyscall::new(60,  "quotactl", 4),
    StaticSyscall::new(61,  "getdents64", 3),
    StaticSyscall::new(62,  "lseek", 3),
    StaticSyscall::new(63,  "read", 3),
    StaticSyscall::new(64,  "write", 3),
    StaticSyscall::new(65,  "readv", 3),
    StaticSyscall::new(66,  "writev", 3),
    StaticSyscall::new(67,  "pread64", 4),
    StaticSyscall::new(68,  "pwrite64", 4),
    StaticSyscall::new(69,  "preadv", 5),
    StaticSyscall::new(70,  "pwritev", 5),
    StaticSyscall::new(71,  "sendfile", 4),
    StaticSyscall::new(72,  "pselect6", 6),
    StaticSyscall::new(73,  "ppoll", 5),
    StaticSyscall::new(74,  "signalfd4", 4),
    StaticSyscall::new(75,  "vmsplice", 4),
    StaticSyscall::new(76,  "splice", 6),
    StaticSyscall::new(77,  "tee", 4),
    StaticSyscall::new(78,  "readlinkat", 4),
    StaticSyscall::new(79,  "newfstatat", 4),
    StaticSyscall::new(80,  "fstat", 2),
    StaticSyscall::new(81,  "sync", 0),
    StaticSyscall::new(82,  "fsync", 1),
    StaticSyscall::new(83,  "fdatasync", 1),
    StaticSyscall::new(84,  "sync_file_range", 4),
    StaticSyscall::new(85,  "timerfd_create", 2),
    StaticSyscall::new(86,  "timerfd_settime", 4),
    StaticSyscall::new(87,  "timerfd_gettime", 2),
    StaticSyscall::new(88,  "utimensat", 4),
    StaticSyscall::new(89,  "acct", 1),
    StaticSyscall::new(90,  "capget", 2),
    StaticSyscall::new(91,  "capset", 2),
    StaticSyscall::new(92,  "personality", 1),
    StaticSyscall::new(93,  "exit", 1),
    StaticSyscall::new(94,  "exit_group", 1),
    StaticSyscall::new(95,  "waitid", 5),
    StaticSyscall::new(96,  "set_tid_address", 1),
    StaticSyscall::new(97,  "unshare", 1),
    StaticSyscall::new(98,  "futex", 6),
    StaticSyscall::new(99,  "set_robust_list", 2),
    StaticSyscall::new(100, "get_robust_list", 3),
    StaticSyscall::new(101, "nanosleep", 2),
    StaticSyscall::new(102, "getitimer", 2),
    StaticSyscall::new(103, "setitimer", 3),
    StaticSyscall::new(104, "kexec_load", 4),
    StaticSyscall::new(105, "init_module", 3),
    StaticSyscall::new(106, "delete_module", 2),
    StaticSyscall::new(107, "timer_create", 3),
    StaticSyscall::new(108, "timer_gettime", 2),
    StaticSyscall::new(109, "timer_getoverrun", 1),
    StaticSyscall::new(110, "timer_settime", 4),
    StaticSyscall::new(111, "timer_delete", 1),
    StaticSyscall::new(112, "clock_settime", 2),
    StaticSyscall::new(113, "clock_gettime", 2),
    StaticSyscall::new(114, "clock_getres", 2),
    StaticSyscall::new(115, "clock_nanosleep", 4),
    StaticSyscall::new(116, "syslog", 3),
    StaticSyscall::new(117, "ptrace", 4),
    StaticSyscall::new(118, "sched_setparam", 2),
    StaticSyscall::new(119, "sched_setscheduler", 3),
    StaticSyscall::new(120, "sched_getscheduler", 1),
    StaticSyscall::new(121, "sched_getparam", 2),
    StaticSyscall::new(122, "sched_setaffinity", 3),
    StaticSyscall::new(123, "sched_getaffinity", 3),
    StaticSyscall::new(124, "sched_yield", 0),
    StaticSyscall::new(125, "sched_get_priority_max", 1),
    StaticSyscall::new(126, "sched_get_priority_min", 1),
    StaticSyscall::new(127, "sched_rr_get_interval", 2),
    StaticSyscall::new(128, "restart_syscall", 0),
    StaticSyscall::new(129, "kill", 2),
    StaticSyscall::new(130, "tkill", 2),
    StaticSyscall::new(131, "tgkill", 3),
    StaticSyscall::new(132, "sigaltstack", 2),
    StaticSyscall::new(133, "rt_sigsuspend", 2),
    StaticSyscall::new(134, "rt_sigaction", 4),
    StaticSyscall::new(135, "rt_sigprocmask", 4),
    StaticSyscall::new(136, "rt_sigpending", 2),
    StaticSyscall::new(137, "rt_sigtimedwait", 4),
    StaticSyscall::new(138, "rt_sigqueueinfo", 3),
    StaticSyscall::new(139, "rt_sigreturn", 0),
    StaticSyscall::new(140, "setpriority", 3),
    StaticSyscall::new(141, "getpriority", 2),
    StaticSyscall::new(142, "reboot", 4),
    StaticSyscall::new(143, "setregid", 2),
    StaticSyscall::new(144, "setgid", 1),
    StaticSyscall::new(145, "setreuid", 2),
    StaticSyscall::new(146, "setuid", 1),
    StaticSyscall::new(147, "setresuid", 3),
    StaticSyscall::new(148, "getresuid", 3),
    StaticSyscall::new(149, "setresgid", 3),
    StaticSyscall::new(150, "getresgid", 3),
    StaticSyscall::new(151, "setfsuid", 1),
    StaticSyscall::new(152, "setfsgid", 1),
    StaticSyscall::new(153, "times", 1),
    StaticSyscall::new(154, "setpgid", 2),
    StaticSyscall::new(155, "getpgid", 1),
    StaticSyscall::new(156, "getsid", 1),
    StaticSyscall::new(157, "setsid", 0),
    StaticSyscall::new(158, "getgroups", 2),
    StaticSyscall::new(159, "setgroups", 2),
    StaticSyscall::new(160, "uname", 1),
    StaticSyscall::new(161, "sethostname", 2),
    StaticSyscall::new(162, "setdomainname", 2),
    StaticSyscall::new(163, "getrlimit", 2),
    StaticSyscall::new(164, "setrlimit", 2),
    StaticSyscall::new(165, "getrusage", 2),
    StaticSyscall::new(166, "umask", 1),
    StaticSyscall::new(167, "prctl", 5),
    StaticSyscall::new(168, "getcpu", 3),
    StaticSyscall::new(169, "gettimeofday", 2),
    StaticSyscall::new(170, "settimeofday", 2),
    StaticSyscall::new(171, "adjtimex", 1),
    StaticSyscall::new(172, "getpid", 0),
    StaticSyscall::new(173, "getppid", 0),
    StaticSyscall::new(174, "getuid", 0),
    StaticSyscall::new(175, "geteuid", 0),
    StaticSyscall::new(176, "getgid", 0),
    StaticSyscall::new(177, "getegid", 0),
    StaticSyscall::new(178, "gettid", 0),
    StaticSyscall::new(179, "sysinfo", 1),
    StaticSyscall::new(180, "mq_open", 4),
    StaticSyscall::new(181, "mq_unlink", 1),
    StaticSyscall::new(182, "mq_timedsend", 5),
    StaticSyscall::new(183, "mq_timedreceive", 5),
    StaticSyscall::new(184, "mq_notify", 2),
    StaticSyscall::new(185, "mq_getsetattr", 3),
    StaticSyscall::new(186, "msgget", 2),
    StaticSyscall::new(187, "msgctl", 3),
    StaticSyscall::new(188, "msgrcv", 5),
    StaticSyscall::new(189, "msgsnd", 4),
    StaticSyscall::new(190, "semget", 3),
    StaticSyscall::new(191, "semctl", 4),
    StaticSyscall::new(192, "semtimedop", 4),
    StaticSyscall::new(193, "semop", 3),
    StaticSyscall::new(194, "shmget", 3),
    StaticSyscall::new(195, "shmctl", 3),
    StaticSyscall::new(196, "shmat", 3),
    StaticSyscall::new(197, "shmdt", 1),
    StaticSyscall::new(198, "socket", 3),
    StaticSyscall::new(199, "socketpair", 4),
    StaticSyscall::new(200, "bind", 3),
    StaticSyscall::new(201, "listen", 2),
    StaticSyscall::new(202, "accept", 3),
    StaticSyscall::new(203, "connect", 3),
    StaticSyscall::new(204, "getsockname", 3),
    StaticSyscall::new(205, "getpeername", 3),
    StaticSyscall::new(206, "sendto", 6),
    StaticSyscall::new(207, "recvfrom", 6),
    StaticSyscall::new(208, "setsockopt", 5),
    StaticSyscall::new(209, "getsockopt", 5),
    StaticSyscall::new(210, "shutdown", 2),
    StaticSyscall::new(211, "sendmsg", 3),
    StaticSyscall::new(212, "recvmsg", 3),
    StaticSyscall::new(213, "readahead", 3),
    StaticSyscall::new(214, "brk", 1),
    StaticSyscall::new(215, "munmap", 2),
    StaticSyscall::new(216, "mremap", 5),
    StaticSyscall::new(217, "add_key", 5),
    StaticSyscall::new(218, "request_key", 4),
    StaticSyscall::new(219, "keyctl", 5),
    StaticSyscall::new(220, "clone", 5),
    StaticSyscall::new(221, "execve", 3),
    StaticSyscall::new(222, "mmap", 6),
    StaticSyscall::new(223, "fadvise64", 4),
    StaticSyscall::new(224, "swapon", 2),
    StaticSyscall::new(225, "swapoff", 1),
    StaticSyscall::new(226, "mprotect", 3),
    StaticSyscall::new(227, "msync", 3),
    StaticSyscall::new(228, "mlock", 2),
    StaticSyscall::new(229, "munlock", 2),
    StaticSyscall::new(230, "mlockall", 1),
    StaticSyscall::new(231, "munlockall", 0),
    StaticSyscall::new(232, "mincore", 3),
    StaticSyscall::new(233, "madvise", 3),
    StaticSyscall::new(234, "remap_file_pages", 5),
    StaticSyscall::new(235, "mbind", 6),
    StaticSyscall::new(236, "get_mempolicy", 5),
    StaticSyscall::new(237, "set_mempolicy", 3),
    StaticSyscall::new(238, "migrate_pages", 4),
    StaticSyscall::new(239, "move_pages", 6),
    StaticSyscall::new(240, "rt_tgsigqueueinfo", 4),
    StaticSyscall::new(241, "perf_event_open", 5),
    StaticSyscall::new(242, "accept4", 4),
    StaticSyscall::new(243, "recvmmsg", 5),
    StaticSyscall::new(260, "wait4", 4),
    StaticSyscall::new(261, "prlimit64", 4),
    StaticSyscall::new(262, "fanotify_init", 2),
    StaticSyscall::new(263, "fanotify_mark", 5),
    StaticSyscall::new(264, "name_to_handle_at", 5),
    StaticSyscall::new(265, "open_by_handle_at", 3),
    StaticSyscall::new(266, "clock_adjtime", 2),
    StaticSyscall::new(267, "syncfs", 1),
    StaticSyscall::new(268, "setns", 2),
    StaticSyscall::new(269, "sendmmsg", 4),
    StaticSyscall::new(270, "process_vm_readv", 6),
    StaticSyscall::new(271, "process_vm_writev", 6),
    StaticSyscall::new(272, "kcmp", 5),
    StaticSyscall::new(273, "finit_module", 3),
    StaticSyscall::new(274, "sched_setattr", 3),
    StaticSyscall::new(275, "sched_getattr", 4),
    StaticSyscall::new(276, "renameat2", 5),
    StaticSyscall::new(277, "seccomp", 3),
    StaticSyscall::new(278, "getrandom", 3),
    StaticSyscall::new(279, "memfd_create", 2),
    StaticSyscall::new(280, "bpf", 3),
    StaticSyscall::new(281, "execveat", 5),
    StaticSyscall::new(282, "userfaultfd", 1),
    StaticSyscall::new(283, "membarrier", 3),
    StaticSyscall::new(284, "mlock2", 3),
    StaticSyscall::new(285, "copy_file_range", 6),
    StaticSyscall::new(286, "preadv2", 6),
    StaticSyscall::new(287, "pwritev2", 6),
    StaticSyscall::new(288, "pkey_mprotect", 4),
    StaticSyscall::new(289, "pkey_alloc", 2),
    StaticSyscall::new(290, "pkey_free", 1),
    StaticSyscall::new(291, "statx", 5),
    StaticSyscall::new(292, "io_pgetevents", 6),
    StaticSyscall::new(293, "rseq", 4),
    StaticSyscall::new(424, "pidfd_send_signal", 4),
    StaticSyscall::new(425, "io_uring_setup", 2),
    StaticSyscall::new(426, "io_uring_enter", 6),
    StaticSyscall::new(427, "io_uring_register", 4),
    StaticSyscall::new(428, "open_tree", 3),
    StaticSyscall::new(429, "move_mount", 5),
    StaticSyscall::new(430, "fsopen", 2),
    StaticSyscall::new(431, "fsconfig", 5),
    StaticSyscall::new(432, "fsmount", 3),
    StaticSyscall::new(433, "fspick", 3),
    StaticSyscall::new(434, "pidfd_open", 2),
    StaticSyscall::new(435, "clone3", 2),
    StaticSyscall::new(436, "close_range", 3),
    StaticSyscall::new(437, "openat2", 4),
    StaticSyscall::new(438, "pidfd_getfd", 3),
    StaticSyscall::new(439, "faccessat2", 4),
    StaticSyscall::new(440, "process_madvise", 5),
    StaticSyscall::new(441, "epoll_pwait2", 6),
    StaticSyscall::new(442, "mount_setattr", 5),
    StaticSyscall::new(443, "quotactl_fd", 4),
    StaticSyscall::new(444, "landlock_create_ruleset", 3),
    StaticSyscall::new(445, "landlock_add_rule", 4),
    StaticSyscall::new(446, "landlock_restrict_self", 2),
    StaticSyscall::new(447, "memfd_secret", 1),
    StaticSyscall::new(448, "process_mrelease", 2),
    StaticSyscall::new(449, "futex_waitv", 5),
    StaticSyscall::new(450, "set_mempolicy_home_node", 4),
];

/// Look up a syscall name by AArch64 number.
#[must_use]
pub fn aarch64_syscall_name(nr: u32) -> Option<&'static str> {
    AARCH64_SPECIFIC_SYSCALLS.iter().find(|s| s.nr == nr).map(|s| s.name)
}

/// Look up a syscall number by name in the AArch64 table.
#[must_use]
pub fn aarch64_syscall_nr(name: &str) -> Option<u32> {
    AARCH64_SPECIFIC_SYSCALLS.iter().find(|s| s.name == name).map(|s| s.nr)
}

// ─── errno decoder ────────────────────────────────────────────────────────────

/// Return the name of a Linux errno value.
#[must_use]
pub fn errno_name(errno: i32) -> Option<&'static str> {
    match errno.unsigned_abs() {
        1  => Some("EPERM"),
        2  => Some("ENOENT"),
        3  => Some("ESRCH"),
        4  => Some("EINTR"),
        5  => Some("EIO"),
        6  => Some("ENXIO"),
        7  => Some("E2BIG"),
        8  => Some("ENOEXEC"),
        9  => Some("EBADF"),
        10 => Some("ECHILD"),
        11 => Some("EAGAIN"),
        12 => Some("ENOMEM"),
        13 => Some("EACCES"),
        14 => Some("EFAULT"),
        15 => Some("ENOTBLK"),
        16 => Some("EBUSY"),
        17 => Some("EEXIST"),
        18 => Some("EXDEV"),
        19 => Some("ENODEV"),
        20 => Some("ENOTDIR"),
        21 => Some("EISDIR"),
        22 => Some("EINVAL"),
        23 => Some("ENFILE"),
        24 => Some("EMFILE"),
        25 => Some("ENOTTY"),
        26 => Some("ETXTBSY"),
        27 => Some("EFBIG"),
        28 => Some("ENOSPC"),
        29 => Some("ESPIPE"),
        30 => Some("EROFS"),
        31 => Some("EMLINK"),
        32 => Some("EPIPE"),
        33 => Some("EDOM"),
        34 => Some("ERANGE"),
        35 => Some("EDEADLK"),
        36 => Some("ENAMETOOLONG"),
        37 => Some("ENOLCK"),
        38 => Some("ENOSYS"),
        39 => Some("ENOTEMPTY"),
        40 => Some("ELOOP"),
        42 => Some("ENOMSG"),
        43 => Some("EIDRM"),
        44 => Some("ECHRNG"),
        60 => Some("ENOSTR"),
        61 => Some("ENODATA"),
        62 => Some("ETIME"),
        63 => Some("ENOSR"),
        67 => Some("ENOLINK"),
        71 => Some("EPROTO"),
        72 => Some("EMULTIHOP"),
        74 => Some("EBADMSG"),
        75 => Some("EOVERFLOW"),
        77 => Some("EBADFD"),
        79 => Some("EREMCHG"),
        84 => Some("EILSEQ"),
        88 => Some("ENOTSOCK"),
        89 => Some("EDESTADDRREQ"),
        90 => Some("EMSGSIZE"),
        91 => Some("EPROTOTYPE"),
        92 => Some("ENOPROTOOPT"),
        93 => Some("EPROTONOSUPPORT"),
        94 => Some("ESOCKTNOSUPPORT"),
        95 => Some("EOPNOTSUPP"),
        96 => Some("EPFNOSUPPORT"),
        97 => Some("EAFNOSUPPORT"),
        98 => Some("EADDRINUSE"),
        99 => Some("EADDRNOTAVAIL"),
        100=> Some("ENETDOWN"),
        101=> Some("ENETUNREACH"),
        102=> Some("ENETRESET"),
        103=> Some("ECONNABORTED"),
        104=> Some("ECONNRESET"),
        105=> Some("ENOBUFS"),
        106=> Some("EISCONN"),
        107=> Some("ENOTCONN"),
        108=> Some("ESHUTDOWN"),
        109=> Some("ETOOMANYREFS"),
        110=> Some("ETIMEDOUT"),
        111=> Some("ECONNREFUSED"),
        112=> Some("EHOSTDOWN"),
        113=> Some("EHOSTUNREACH"),
        114=> Some("EALREADY"),
        115=> Some("EINPROGRESS"),
        116=> Some("ESTALE"),
        125=> Some("ECANCELED"),
        130=> Some("EOWNERDEAD"),
        131=> Some("ENOTRECOVERABLE"),
        _  => None,
    }
}

/// Format a syscall return value with errno decoding when negative.
#[must_use]
pub fn format_retval(retval: i64) -> String {
    if retval >= 0 {
        retval.to_string()
    } else {
        let errno = (-retval) as i32;
        let name = errno_name(-errno).unwrap_or("EUNKNOWN");
        format!("-1 {name} ({name})")
    }
}

// ─── Ioctl command decoder ────────────────────────────────────────────────────

/// Decode a common Linux ioctl command code to a human-readable name.
#[must_use]
pub fn ioctl_name(cmd: u32) -> Option<&'static str> {
    match cmd {
        0x5401 => Some("TCGETS"),
        0x5402 => Some("TCSETS"),
        0x5403 => Some("TCSETSW"),
        0x5404 => Some("TCSETSF"),
        0x5408 => Some("TCSBRK"),
        0x5409 => Some("TCXONC"),
        0x540A => Some("TCFLSH"),
        0x540B => Some("TIOCEXCL"),
        0x540C => Some("TIOCNXCL"),
        0x540E => Some("TIOCSCTTY"),
        0x540F => Some("TIOCGPGRP"),
        0x5410 => Some("TIOCSPGRP"),
        0x5411 => Some("TIOCOUTQ"),
        0x5412 => Some("TIOCSTI"),
        0x5413 => Some("TIOCGWINSZ"),
        0x5414 => Some("TIOCSWINSZ"),
        0x5415 => Some("TIOCMGET"),
        0x5416 => Some("TIOCMBIS"),
        0x5417 => Some("TIOCMBIC"),
        0x5418 => Some("TIOCMSET"),
        0x541B => Some("TIOCGSOFTCAR"),
        0x541C => Some("TIOCSSOFTCAR"),
        0x541D => Some("FIONREAD"),
        0x541E => Some("TIOCLINUX"),
        0x541F => Some("TIOCCONS"),
        0x5420 => Some("TIOCGSERIAL"),
        0x5421 => Some("TIOCSSERIAL"),
        0x5422 => Some("TIOCPKT"),
        0x5423 => Some("FIONBIO"),
        0x5424 => Some("TIOCNOTTY"),
        0x5425 => Some("TIOCSETD"),
        0x5426 => Some("TIOCGETD"),
        0x5427 => Some("TCSBRKP"),
        0x5450 => Some("FIONCLEX"),
        0x5451 => Some("FIOCLEX"),
        0x5452 => Some("FIOASYNC"),
        0x5453 => Some("TIOCSERCONFIG"),
        0x8901 => Some("SIOCGIFNAME"),
        0x8902 => Some("SIOCSIFLINK"),
        0x8910 => Some("SIOCGIFFLAGS"),
        0x8911 => Some("SIOCSIFFLAGS"),
        0x8912 => Some("SIOCGIFADDR"),
        0x8913 => Some("SIOCSIFADDR"),
        0x891B => Some("SIOCGIFMTU"),
        0x891C => Some("SIOCSIFMTU"),
        0x8933 => Some("SIOCGIFINDEX"),
        0x40086601 => Some("BLKGETSIZE"),
        0x00005331 => Some("CDROMSTART"),
        _     => None,
    }
}

// ─── Ptrace request decoder ───────────────────────────────────────────────────

/// Decode a ptrace request number to its symbolic name.
#[must_use]
pub fn ptrace_request_name(req: u64) -> Option<&'static str> {
    match req {
        0  => Some("PTRACE_TRACEME"),
        1  => Some("PTRACE_PEEKTEXT"),
        2  => Some("PTRACE_PEEKDATA"),
        3  => Some("PTRACE_PEEKUSER"),
        4  => Some("PTRACE_POKETEXT"),
        5  => Some("PTRACE_POKEDATA"),
        6  => Some("PTRACE_POKEUSER"),
        7  => Some("PTRACE_CONT"),
        8  => Some("PTRACE_KILL"),
        9  => Some("PTRACE_SINGLESTEP"),
        12 => Some("PTRACE_GETREGS"),
        13 => Some("PTRACE_SETREGS"),
        14 => Some("PTRACE_GETFPREGS"),
        15 => Some("PTRACE_SETFPREGS"),
        16 => Some("PTRACE_ATTACH"),
        17 => Some("PTRACE_DETACH"),
        18 => Some("PTRACE_GETFPXREGS"),
        19 => Some("PTRACE_SETFPXREGS"),
        24 => Some("PTRACE_SYSCALL"),
        25 => Some("PTRACE_SETOPTIONS"),
        26 => Some("PTRACE_GETEVENTMSG"),
        27 => Some("PTRACE_GETSIGINFO"),
        28 => Some("PTRACE_SETSIGINFO"),
        0x4200 => Some("PTRACE_GETREGSET"),
        0x4201 => Some("PTRACE_SETREGSET"),
        0x4202 => Some("PTRACE_SEIZE"),
        0x4203 => Some("PTRACE_INTERRUPT"),
        0x4204 => Some("PTRACE_LISTEN"),
        0x4205 => Some("PTRACE_PEEKSIGINFO"),
        0x4206 => Some("PTRACE_GETSIGMASK"),
        0x4207 => Some("PTRACE_SETSIGMASK"),
        0x4208 => Some("PTRACE_SECCOMP_GET_FILTER"),
        0x420a => Some("PTRACE_GET_SYSCALL_INFO"),
        _  => None,
    }
}

/// Ptrace event codes (from PTRACE_GETEVENTMSG).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtraceEvent {
    Fork,
    Vfork,
    Clone,
    Exec,
    VforkDone,
    Exit,
    Seccomp,
    Stop,
    Unknown(u32),
}

impl PtraceEvent {
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Fork,
            2 => Self::Vfork,
            3 => Self::Clone,
            4 => Self::Exec,
            5 => Self::VforkDone,
            6 => Self::Exit,
            7 => Self::Seccomp,
            128 => Self::Stop,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fork      => "PTRACE_EVENT_FORK",
            Self::Vfork     => "PTRACE_EVENT_VFORK",
            Self::Clone     => "PTRACE_EVENT_CLONE",
            Self::Exec      => "PTRACE_EVENT_EXEC",
            Self::VforkDone => "PTRACE_EVENT_VFORK_DONE",
            Self::Exit      => "PTRACE_EVENT_EXIT",
            Self::Seccomp   => "PTRACE_EVENT_SECCOMP",
            Self::Stop      => "PTRACE_EVENT_STOP",
            Self::Unknown(_)=> "PTRACE_EVENT_UNKNOWN",
        }
    }
}

// ─── mmap protection and flag display helpers ─────────────────────────────────

/// Format mmap prot+flags in strace notation, e.g. `PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS`.
#[must_use]
pub fn format_mmap_args(prot: u64, flags: u64) -> String {
    let p = decode_flags(prot, PROT_FLAGS);
    let f = decode_flags(flags, MAP_FLAGS);
    format!("{p}, {f}")
}

/// Format the open/openat flags argument.
#[must_use]
pub fn format_open_flags(flags: u64) -> String {
    let rdwr = flags & 0o3;
    let mut parts: Vec<&str> = Vec::new();
    match rdwr {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => parts.push("O_RDWR"),
    }
    for bit in O_FLAGS {
        if bit.value > 0o2 && bit.value != 0o3 && (flags & bit.value) == bit.value {
            parts.push(bit.name);
        }
    }
    parts.join("|")
}

// ─── Security taint tracker ───────────────────────────────────────────────────

/// Security taint flags that can be set on a process.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TaintFlags {
    pub executed_code_from_mmap: bool,
    pub used_ptrace: bool,
    pub spawned_child: bool,
    pub opened_network_socket: bool,
    pub changed_uid: bool,
    pub wrote_to_executable_memory: bool,
    pub injected_into_foreign_process: bool,
}

impl TaintFlags {
    /// Returns `true` if any suspicious flag is set.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.executed_code_from_mmap
            || self.used_ptrace
            || self.wrote_to_executable_memory
            || self.injected_into_foreign_process
    }

    /// Update taint based on a completed syscall event.
    pub fn update_from_event(&mut self, event: &SyscallEvent) {
        match event.name.as_str() {
            "mmap" => {
                // If PROT_EXEC is in prot arg
                if let Some(DecodedArg::Flags(raw, _)) = event.args.get(2) {
                    if raw & 0x4 != 0 { self.executed_code_from_mmap = true; }
                }
            }
            "mprotect" => {
                if let Some(DecodedArg::Flags(raw, _)) = event.args.get(2) {
                    if raw & 0x4 != 0 { self.wrote_to_executable_memory = true; }
                }
            }
            "ptrace" => { self.used_ptrace = true; }
            "fork" | "vfork" | "clone" | "clone3" => { self.spawned_child = true; }
            "socket" => { self.opened_network_socket = true; }
            "setuid" | "setgid" | "setresuid" | "setresgid" => { self.changed_uid = true; }
            "process_vm_writev" | "ptrace" => { self.injected_into_foreign_process = true; }
            _ => {}
        }
    }
}

// ─── Additional tests (part 2) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext2_tests {
    use super::*;

    #[test]
    fn test_aarch64_read_nr63() { assert_eq!(aarch64_syscall_name(63), Some("read")); }
    #[test]
    fn test_aarch64_write_nr64() { assert_eq!(aarch64_syscall_name(64), Some("write")); }
    #[test]
    fn test_aarch64_mmap_nr222() { assert_eq!(aarch64_syscall_name(222), Some("mmap")); }
    #[test]
    fn test_aarch64_execve_nr221() { assert_eq!(aarch64_syscall_name(221), Some("execve")); }
    #[test]
    fn test_aarch64_socket_nr198() { assert_eq!(aarch64_syscall_name(198), Some("socket")); }
    #[test]
    fn test_aarch64_unknown() { assert!(aarch64_syscall_name(9999).is_none()); }
    #[test]
    fn test_aarch64_table_len() { assert!(AARCH64_SPECIFIC_SYSCALLS.len() > 100); }
    #[test]
    fn test_aarch64_clone3() { assert_eq!(aarch64_syscall_name(435), Some("clone3")); }
    #[test]
    fn test_aarch64_io_uring_setup() { assert_eq!(aarch64_syscall_name(425), Some("io_uring_setup")); }

    #[test]
    fn test_errno_name_eperm() { assert_eq!(errno_name(1), Some("EPERM")); }
    #[test]
    fn test_errno_name_enoent() { assert_eq!(errno_name(2), Some("ENOENT")); }
    #[test]
    fn test_errno_name_econnrefused() { assert_eq!(errno_name(111), Some("ECONNREFUSED")); }
    #[test]
    fn test_errno_name_negative_input() { assert_eq!(errno_name(-2), Some("ENOENT")); }
    #[test]
    fn test_errno_name_unknown() { assert!(errno_name(999).is_none()); }

    #[test]
    fn test_format_retval_positive() { assert_eq!(format_retval(42), "42"); }
    #[test]
    fn test_format_retval_negative() {
        let s = format_retval(-2);
        assert!(s.contains("ENOENT"), "got: {s}");
    }

    #[test]
    fn test_ioctl_name_tcgets() { assert_eq!(ioctl_name(0x5401), Some("TCGETS")); }
    #[test]
    fn test_ioctl_name_siocgifname() { assert_eq!(ioctl_name(0x8901), Some("SIOCGIFNAME")); }
    #[test]
    fn test_ioctl_name_unknown() { assert!(ioctl_name(0xDEAD).is_none()); }

    #[test]
    fn test_ptrace_request_traceme() { assert_eq!(ptrace_request_name(0), Some("PTRACE_TRACEME")); }
    #[test]
    fn test_ptrace_request_syscall() { assert_eq!(ptrace_request_name(24), Some("PTRACE_SYSCALL")); }
    #[test]
    fn test_ptrace_request_unknown() { assert!(ptrace_request_name(9999).is_none()); }

    #[test]
    fn test_ptrace_event_from_u32() {
        assert_eq!(PtraceEvent::from_u32(1), PtraceEvent::Fork);
        assert_eq!(PtraceEvent::from_u32(4).as_str(), "PTRACE_EVENT_EXEC");
    }

    #[test]
    fn test_format_mmap_args() {
        let s = format_mmap_args(0x7, 0x22);
        assert!(s.contains("PROT_READ"));
        assert!(s.contains("MAP_PRIVATE"));
        assert!(s.contains("MAP_ANONYMOUS"));
    }

    #[test]
    fn test_format_open_flags_rdonly() {
        let s = format_open_flags(0);
        assert_eq!(s, "O_RDONLY");
    }

    #[test]
    fn test_format_open_flags_wronly_creat_trunc() {
        let flags = 0o1 | 0o100 | 0o1000u64;
        let s = format_open_flags(flags);
        assert!(s.contains("O_WRONLY"), "got: {s}");
        assert!(s.contains("O_CREAT"),  "got: {s}");
        assert!(s.contains("O_TRUNC"),  "got: {s}");
    }

    #[test]
    fn test_taint_flags_default_clean() {
        let t = TaintFlags::default();
        assert!(!t.is_suspicious());
    }

    #[test]
    fn test_taint_flags_ptrace_suspicious() {
        let mut t = TaintFlags::default();
        let ev = SyscallEvent {
            timestamp_ns: 0, pid: 1, tid: 1, nr: 101,
            name: "ptrace".to_string(), args: vec![],
            retval: DecodedArg::Int(0), elapsed_ns: 0, is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.used_ptrace);
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_taint_flags_mmap_exec() {
        let mut t = TaintFlags::default();
        let ev = SyscallEvent {
            timestamp_ns: 0, pid: 1, tid: 1, nr: 9,
            name: "mmap".to_string(),
            args: vec![
                DecodedArg::Addr(0),
                DecodedArg::Size(4096),
                DecodedArg::Flags(0x5, "PROT_READ|PROT_EXEC".to_string()), // prot = 0x5 has exec bit
                DecodedArg::Flags(0x22, "MAP_PRIVATE|MAP_ANONYMOUS".to_string()),
                DecodedArg::Fd(-1, "".to_string()),
                DecodedArg::UInt(0),
            ],
            retval: DecodedArg::Addr(0x7fff0000),
            elapsed_ns: 0, is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.executed_code_from_mmap);
    }

    #[test]
    fn test_taint_fork() {
        let mut t = TaintFlags::default();
        let ev = SyscallEvent {
            timestamp_ns: 0, pid: 1, tid: 1, nr: 57,
            name: "fork".to_string(), args: vec![],
            retval: DecodedArg::Int(1234), elapsed_ns: 0, is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.spawned_child);
        assert!(!t.is_suspicious()); // fork alone is not suspicious
    }

    #[test]
    fn test_aarch64_rev_lookup() {
        assert_eq!(aarch64_syscall_nr("read"), Some(63));
        assert_eq!(aarch64_syscall_nr("write"), Some(64));
    }

    #[test]
    fn test_syscall_summary_avg_ns() {
        let mut s = SyscallSummaryEntry::new("test", 0, false);
        s.record(1000, false);
        s.record(3000, false);
        // count=3, total=4000
        assert_eq!(s.avg_ns(), 4000 / 3);
    }

    #[test]
    fn test_fd_table_is_empty() {
        let t = FdTable::default();
        assert!(t.is_empty());
    }
}
