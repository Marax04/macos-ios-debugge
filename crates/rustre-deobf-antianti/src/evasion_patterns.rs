//! Evasion-pattern database and detection subsystems for anti-dump, anti-emulation,
//! sandbox, and anti-hooking techniques.
//!
//! Provides:
//! * [`EvasionPatternDb`] — 60+ pattern records.
//! * [`AntiDumpDetector`] — detects code that obstructs memory dumping.
//! * [`AntiEmulationDetector`] — detects sandbox / emulator evasion.
//! * [`SandboxDetector`] — detects sandbox-specific artefact checks.
//! * [`AntiHookingDetector`] — detects hook-detection / unhooking routines.
//! * [`EvasionScore`] — aggregated per-category confidence scores.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// EvasionCategory
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level category of an evasion technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvasionCategory {
    /// Techniques that prevent or confuse memory dumpers.
    AntiDump,
    /// Techniques that detect or confuse emulators / sandboxes.
    AntiEmulation,
    /// Techniques that detect sandbox-specific artefacts.
    Sandbox,
    /// Techniques that detect or remove API hooks.
    AntiHooking,
    /// Timing-based evasion (beyond basic RDTSC).
    Timing,
    /// Anti-debug catch-all.
    AntiDebug,
    /// Miscellaneous.
    Misc,
}

impl EvasionCategory {
    /// Short label string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AntiDump => "anti-dump",
            Self::AntiEmulation => "anti-emulation",
            Self::Sandbox => "sandbox",
            Self::AntiHooking => "anti-hooking",
            Self::Timing => "timing",
            Self::AntiDebug => "anti-debug",
            Self::Misc => "misc",
        }
    }

    /// Whether this category is considered "sensitive" (high-risk evasion).
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(
            self,
            Self::AntiDump | Self::AntiEmulation | Self::Sandbox | Self::AntiHooking
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single evasion pattern entry in the database.
#[derive(Debug, Clone)]
pub struct EvasionPattern {
    /// Short identifier.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Category.
    pub category: EvasionCategory,
    /// Byte pattern (exact or masked).
    pub pattern: &'static [u8],
    /// Per-byte mask (`0xFF` = exact, `0x00` = wildcard).
    pub mask: &'static [u8],
    /// Default confidence score when matched (0–100).
    pub confidence: u8,
}

impl EvasionPattern {
    /// Return `true` if pattern and mask have equal length.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.pattern.len() == self.mask.len()
    }

    /// Try to match `data[offset..]` against this pattern.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let pat = self.pattern;
        if offset + pat.len() > data.len() {
            return false;
        }
        pat.iter().enumerate().all(|(i, &p)| {
            let m = self.mask[i];
            m == 0x00 || (data[offset + i] & m) == (p & m)
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionPatternDb — 60+ patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A static database of 60+ evasion patterns.
pub struct EvasionPatternDb {
    /// All patterns.
    pub patterns: Vec<EvasionPattern>,
}

impl EvasionPatternDb {
    /// Build the full pattern database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: all_patterns(),
        }
    }

    /// Return the number of patterns.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.patterns.len()
    }

    /// Scan `data` and return all matches as `(pattern_name, offset)` pairs.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EvasionMatch> {
        let mut matches = Vec::new();
        for pat in &self.patterns {
            if pat.pattern.is_empty() {
                continue;
            }
            let mut pos = 0;
            while pos + pat.pattern.len() <= data.len() {
                if pat.matches_at(data, pos) {
                    matches.push(EvasionMatch {
                        name: pat.name,
                        category: pat.category,
                        offset: pos,
                        confidence: pat.confidence,
                        description: pat.description,
                    });
                    pos += pat.pattern.len();
                } else {
                    pos += 1;
                }
            }
        }
        matches.sort_by_key(|m| m.offset);
        matches
    }

    /// Scan and return only matches in a given category.
    #[must_use]
    pub fn scan_category(&self, data: &[u8], cat: EvasionCategory) -> Vec<EvasionMatch> {
        self.scan(data)
            .into_iter()
            .filter(|m| m.category == cat)
            .collect()
    }

    /// Return the number of patterns in a given category.
    #[must_use]
    pub fn category_count(&self, cat: EvasionCategory) -> usize {
        self.patterns.iter().filter(|p| p.category == cat).count()
    }
}

impl Default for EvasionPatternDb {
    fn default() -> Self {
        Self::new()
    }
}

/// A single match from [`EvasionPatternDb::scan`].
#[derive(Debug, Clone)]
pub struct EvasionMatch {
    /// Pattern identifier.
    pub name: &'static str,
    /// Category.
    pub category: EvasionCategory,
    /// Byte offset of the match.
    pub offset: usize,
    /// Confidence (0–100).
    pub confidence: u8,
    /// Human-readable description.
    pub description: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern table (60+ entries)
// ─────────────────────────────────────────────────────────────────────────────

const fn p(
    name: &'static str,
    desc: &'static str,
    cat: EvasionCategory,
    pat: &'static [u8],
    msk: &'static [u8],
    conf: u8,
) -> EvasionPattern {
    EvasionPattern {
        name,
        description: desc,
        category: cat,
        pattern: pat,
        mask: msk,
        confidence: conf,
    }
}

fn all_patterns() -> Vec<EvasionPattern> {
    vec![
        // ── Anti-dump ─────────────────────────────────────────────────────────
        p(
            "size-of-image-zero",
            "Zero SizeOfImage in PE header to confuse dumpers",
            EvasionCategory::AntiDump,
            &[0x00, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            60,
        ),
        p(
            "pe-header-erase",
            "Overwrite MZ/PE header to prevent re-parsing",
            EvasionCategory::AntiDump,
            &[0x4D, 0x5A],
            &[0xFF, 0xFF],
            70,
        ),
        p(
            "section-names-erase",
            "Blank section names to hinder analysis",
            EvasionCategory::AntiDump,
            &[0x2E, 0x74, 0x65, 0x78, 0x74],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            65,
        ),
        p(
            "ntsetinformationprocess-antidump",
            "NtSetInformationProcess(ProcessExecuteFlags) to disable DEP",
            EvasionCategory::AntiDump,
            &[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            55,
        ),
        p(
            "virtualprotect-rwx",
            "VirtualProtect to RWX (common in unpackers)",
            EvasionCategory::AntiDump,
            &[0x40, 0x00, 0x00, 0x00],
            &[0xFF, 0x00, 0x00, 0xFF],
            50,
        ),
        p(
            "ntunmapviewofsection",
            "Unmap PE sections to foil reconstruction",
            EvasionCategory::AntiDump,
            b"NtUnmapViewOfSection",
            &[0xFF; 20],
            85,
        ),
        p(
            "readprocessmemory-self",
            "ReadProcessMemory on own handle",
            EvasionCategory::AntiDump,
            b"ReadProcessMemory",
            &[0xFF; 17],
            70,
        ),
        p(
            "writeprocessmemory-self",
            "WriteProcessMemory to self (SMC / anti-dump)",
            EvasionCategory::AntiDump,
            b"WriteProcessMemory",
            &[0xFF; 18],
            70,
        ),
        p(
            "ntwritevirtualmemory",
            "NtWriteVirtualMemory",
            EvasionCategory::AntiDump,
            b"NtWriteVirtualMemory",
            &[0xFF; 21],
            80,
        ),
        p(
            "zeroing-pe-header",
            "XOR/zero bytes in the PE header region",
            EvasionCategory::AntiDump,
            &[0x30, 0x00],
            &[0xFF, 0xFF],
            40,
        ),
        // ── Anti-emulation ────────────────────────────────────────────────────
        p(
            "cpuid-leaf-2",
            "CPUID leaf 2 (cache info) rarely emulated correctly",
            EvasionCategory::AntiEmulation,
            &[0xB8, 0x02, 0x00, 0x00, 0x00, 0x0F, 0xA2],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            80,
        ),
        p(
            "cpuid-leaf-4",
            "CPUID leaf 4 (det. cache params) emulation gap",
            EvasionCategory::AntiEmulation,
            &[0xB8, 0x04, 0x00, 0x00, 0x00, 0x0F, 0xA2],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            80,
        ),
        p(
            "rdtsc-timing",
            "RDTSC timing (0F 31)",
            EvasionCategory::AntiEmulation,
            &[0x0F, 0x31],
            &[0xFF, 0xFF],
            85,
        ),
        p(
            "rdtscp",
            "RDTSCP (0F 01 F9) — rarely implemented in emulators",
            EvasionCategory::AntiEmulation,
            &[0x0F, 0x01, 0xF9],
            &[0xFF, 0xFF, 0xFF],
            88,
        ),
        p(
            "vmx-check",
            "VMX instructions in ring3 → fault in emulators",
            EvasionCategory::AntiEmulation,
            &[0x0F, 0xC7, 0x30],
            &[0xFF, 0xFF, 0xFF],
            75,
        ),
        p(
            "fpu-tag-word",
            "FSAVE/FRSTOR with FPU tag word check",
            EvasionCategory::AntiEmulation,
            &[0x9B, 0xDD, 0x34, 0x24],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            72,
        ),
        p(
            "sse-denormal",
            "SSE denormal exception probe",
            EvasionCategory::AntiEmulation,
            &[0x0F, 0x2E],
            &[0xFF, 0xFF],
            65,
        ),
        p(
            "exception-filter-check",
            "SetUnhandledExceptionFilter to detect emulator",
            EvasionCategory::AntiEmulation,
            b"SetUnhandledExceptionFilter",
            &[0xFF; 27],
            75,
        ),
        p(
            "nop-slide-check",
            "Detect NOP slide inserted by instrumentation",
            EvasionCategory::AntiEmulation,
            &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            &[0xFF; 8],
            55,
        ),
        p(
            "anti-step-over",
            "GetTickCount + NOP sled anti-step-over",
            EvasionCategory::AntiEmulation,
            &[0xFF, 0xD0, 0x90, 0x90, 0x90],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            60,
        ),
        // ── Sandbox ───────────────────────────────────────────────────────────
        p(
            "sandbox-username-analyst",
            "Username == 'analyst' or 'sandbox' check",
            EvasionCategory::Sandbox,
            b"analyst",
            &[0xFF; 7],
            80,
        ),
        p(
            "sandbox-username-malware",
            "'malware' in username",
            EvasionCategory::Sandbox,
            b"malware",
            &[0xFF; 7],
            85,
        ),
        p(
            "sandbox-computername-win7",
            "'WIN7' hostname — common sandbox name",
            EvasionCategory::Sandbox,
            b"WIN7",
            &[0xFF; 4],
            70,
        ),
        p(
            "sandbox-computername-win10",
            "'WIN10' hostname",
            EvasionCategory::Sandbox,
            b"WIN10",
            &[0xFF; 5],
            68,
        ),
        p(
            "sandbox-pipe-wireshark",
            "Wireshark named pipe artefact",
            EvasionCategory::Sandbox,
            b"\\\\.\\pipe\\wireshark",
            &[0xFF; 18],
            90,
        ),
        p(
            "sandbox-mutex-cuckoo",
            "Cuckoo sandbox mutex 'CuckooMonitorMutex'",
            EvasionCategory::Sandbox,
            b"CuckooMonitorMutex",
            &[0xFF; 18],
            95,
        ),
        p(
            "sandbox-process-cuckoo",
            "'cuckoo' process in process list",
            EvasionCategory::Sandbox,
            b"cuckoo",
            &[0xFF; 6],
            90,
        ),
        p(
            "sandbox-process-vboxsvc",
            "'VBoxSvc' VirtualBox service",
            EvasionCategory::Sandbox,
            b"VBoxSvc",
            &[0xFF; 7],
            92,
        ),
        p(
            "sandbox-process-vmwaretray",
            "'vmwaretray.exe'",
            EvasionCategory::Sandbox,
            b"vmwaretray.exe",
            &[0xFF; 14],
            90,
        ),
        p(
            "sandbox-process-procmon",
            "'procmon.exe'",
            EvasionCategory::Sandbox,
            b"procmon.exe",
            &[0xFF; 11],
            80,
        ),
        p(
            "sandbox-process-wireshark",
            "'wireshark.exe'",
            EvasionCategory::Sandbox,
            b"wireshark.exe",
            &[0xFF; 13],
            82,
        ),
        p(
            "sandbox-process-x64dbg",
            "'x64dbg.exe'",
            EvasionCategory::Sandbox,
            b"x64dbg.exe",
            &[0xFF; 10],
            88,
        ),
        p(
            "sandbox-process-ollydbg",
            "'ollydbg.exe'",
            EvasionCategory::Sandbox,
            b"ollydbg.exe",
            &[0xFF; 11],
            88,
        ),
        p(
            "sandbox-file-sampleexe",
            "'sample.exe' file path check",
            EvasionCategory::Sandbox,
            b"sample.exe",
            &[0xFF; 10],
            75,
        ),
        p(
            "sandbox-file-malwareexe",
            "'malware.exe' file path check",
            EvasionCategory::Sandbox,
            b"malware.exe",
            &[0xFF; 11],
            78,
        ),
        p(
            "sandbox-screen-small",
            "GetSystemMetrics(SM_CXSCREEN) < 800 check",
            EvasionCategory::Sandbox,
            &[0x6A, 0x00, 0xFF, 0x15],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            60,
        ),
        p(
            "sandbox-mouse-check",
            "GetCursorPos — detect absence of mouse movement",
            EvasionCategory::Sandbox,
            b"GetCursorPos",
            &[0xFF; 12],
            72,
        ),
        p(
            "sandbox-disk-small",
            "DeviceIoControl for disk size check",
            EvasionCategory::Sandbox,
            b"DeviceIoControl",
            &[0xFF; 15],
            65,
        ),
        p(
            "sandbox-uptime-low",
            "GetTickCount() < 5min check",
            EvasionCategory::Sandbox,
            &[0x68, 0x00, 0xCA, 0x9A, 0x3B],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            70,
        ),
        p(
            "sandbox-recent-files",
            "SHGetFolderPath for Recent documents",
            EvasionCategory::Sandbox,
            b"SHGetFolderPathW",
            &[0xFF; 16],
            60,
        ),
        // ── Anti-hooking ──────────────────────────────────────────────────────
        p(
            "inline-hook-detect",
            "Check first 5 bytes of a function for JMP (E9)",
            EvasionCategory::AntiHooking,
            &[0x8B, 0x01, 0x3D, 0xE9, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            80,
        ),
        p(
            "ntdll-reload",
            "LoadLibraryA('ntdll.dll') to reload clean ntdll",
            EvasionCategory::AntiHooking,
            b"ntdll.dll",
            &[0xFF; 9],
            85,
        ),
        p(
            "kernel32-reload",
            "LoadLibraryA('kernel32.dll') reload",
            EvasionCategory::AntiHooking,
            b"kernel32.dll",
            &[0xFF; 12],
            80,
        ),
        p(
            "restore-bytes-by-map",
            "NtCreateSection to map ntdll for byte comparison",
            EvasionCategory::AntiHooking,
            b"NtCreateSection",
            &[0xFF; 15],
            88,
        ),
        p(
            "compare-disk-mem",
            "ReadFile on ntdll.dll for hook detection via byte comparison",
            EvasionCategory::AntiHooking,
            b"ntdll.dll",
            &[0xFF; 9],
            70,
        ),
        p(
            "hook-remove-via-write",
            "WriteProcessMemory to restore original bytes",
            EvasionCategory::AntiHooking,
            b"WriteProcessMemory",
            &[0xFF; 18],
            75,
        ),
        p(
            "syscall-direct",
            "Direct syscall (0F 05) to bypass hooks",
            EvasionCategory::AntiHooking,
            &[0x0F, 0x05],
            &[0xFF, 0xFF],
            90,
        ),
        p(
            "int2e-syscall",
            "INT 2E (legacy syscall)",
            EvasionCategory::AntiHooking,
            &[0xCD, 0x2E],
            &[0xFF, 0xFF],
            88,
        ),
        p(
            "sysenter",
            "SYSENTER (0F 34)",
            EvasionCategory::AntiHooking,
            &[0x0F, 0x34],
            &[0xFF, 0xFF],
            88,
        ),
        p(
            "wow64-syscall-stub",
            "Wow64 heaven's gate transition",
            EvasionCategory::AntiHooking,
            &[0xEA, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00],
            &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
            82,
        ),
        p(
            "veh-hook-install",
            "AddVectoredExceptionHandler hook install",
            EvasionCategory::AntiHooking,
            b"AddVectoredExceptionHandler",
            &[0xFF; 27],
            75,
        ),
        p(
            "detour-check-hot-patch",
            "Check for hot-patch prefix (8B FF MOV EDI,EDI)",
            EvasionCategory::AntiHooking,
            &[0x8B, 0xFF, 0x55, 0x8B, 0xEC],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            85,
        ),
        // ── Timing ────────────────────────────────────────────────────────────
        p(
            "sleep-1min",
            "Sleep(60000) anti-sandbox delay",
            EvasionCategory::Timing,
            &[0x68, 0x60, 0xEA, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            85,
        ),
        p(
            "sleep-5min",
            "Sleep(300000) anti-sandbox delay",
            EvasionCategory::Timing,
            &[0x68, 0xE0, 0x93, 0x04, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            88,
        ),
        p(
            "ntdelay-large",
            "NtDelayExecution with large interval",
            EvasionCategory::Timing,
            b"NtDelayExecution",
            &[0xFF; 16],
            80,
        ),
        p(
            "waitforsingleobject-large",
            "WaitForSingleObject(INFINITE)",
            EvasionCategory::Timing,
            &[0x68, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            70,
        ),
        p(
            "qpc-timing",
            "QueryPerformanceCounter timing attack",
            EvasionCategory::Timing,
            b"QueryPerformanceCounter",
            &[0xFF; 23],
            78,
        ),
        p(
            "gettickcount-timing",
            "GetTickCount timing attack",
            EvasionCategory::Timing,
            b"GetTickCount",
            &[0xFF; 12],
            75,
        ),
        // ── Anti-debug ────────────────────────────────────────────────────────
        p(
            "peb-being-debugged",
            "PEB BeingDebugged flag check",
            EvasionCategory::AntiDebug,
            &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            95,
        ),
        p(
            "int3-breakpoint",
            "Explicit INT3 / breakpoint",
            EvasionCategory::AntiDebug,
            &[0xCC],
            &[0xFF],
            70,
        ),
        p(
            "dr-register",
            "Debug register read",
            EvasionCategory::AntiDebug,
            &[0x0F, 0x21, 0xC0],
            &[0xFF, 0xFF, 0xF8],
            85,
        ),
        p(
            "outputdebugstring",
            "OutputDebugString timing trick",
            EvasionCategory::AntiDebug,
            b"OutputDebugStringA",
            &[0xFF; 18],
            80,
        ),
        p(
            "ntqueryinformationprocess",
            "NtQueryInformationProcess anti-debug",
            EvasionCategory::AntiDebug,
            b"NtQueryInformationProcess",
            &[0xFF; 25],
            90,
        ),
        p(
            "heap-flags-ntglobalflag",
            "NtGlobalFlag heap flags",
            EvasionCategory::AntiDebug,
            &[0x64, 0xA1, 0x68, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            90,
        ),
        p(
            "close-invalid-handle",
            "CloseHandle(INVALID_HANDLE_VALUE)",
            EvasionCategory::AntiDebug,
            &[0x6A, 0xFF],
            &[0xFF, 0xFF],
            75,
        ),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionScore
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated evasion score with per-category breakdown.
#[derive(Debug, Clone, Default)]
pub struct EvasionScore {
    /// Per-category hit counts and maximum confidence.
    pub categories: HashMap<String, (usize, u8)>,
    /// Total number of pattern matches.
    pub total_hits: usize,
}

impl EvasionScore {
    /// Create an empty score.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a match for `category` with `confidence`.
    pub fn record(&mut self, category: EvasionCategory, confidence: u8) {
        let label = category.label().to_owned();
        let entry = self.categories.entry(label).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(confidence);
        self.total_hits += 1;
    }

    /// Build a score from a list of matches.
    #[must_use]
    pub fn from_matches(matches: &[EvasionMatch]) -> Self {
        let mut score = Self::new();
        for m in matches {
            score.record(m.category, m.confidence);
        }
        score
    }

    /// Return the overall risk level: "high" (≥5 hits), "medium" (≥2), or "low".
    #[must_use]
    pub const fn risk_level(&self) -> &'static str {
        if self.total_hits >= 5 {
            "high"
        } else if self.total_hits >= 2 {
            "medium"
        } else {
            "low"
        }
    }

    /// Return the maximum confidence across all categories.
    #[must_use]
    pub fn max_confidence(&self) -> u8 {
        self.categories.values().map(|(_, c)| *c).max().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionPatternFilter — filters the pattern database before scanning
// ─────────────────────────────────────────────────────────────────────────────

/// Filter that restricts which patterns are used during a scan.
#[derive(Debug, Clone, Default)]
pub struct EvasionPatternFilter {
    /// Only include patterns in these categories (empty = all).
    pub only_categories: Vec<EvasionCategory>,
    /// Exclude patterns with confidence below this value.
    pub min_confidence: u8,
    /// Exclude patterns with names in this blocklist.
    pub name_blocklist: Vec<&'static str>,
}

impl EvasionPatternFilter {
    /// Create a filter with default settings (no restrictions).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a single category.
    #[must_use]
    pub fn only_category(mut self, cat: EvasionCategory) -> Self {
        self.only_categories.push(cat);
        self
    }

    /// Set minimum confidence.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Check whether a pattern passes the filter.
    #[must_use]
    pub fn passes(&self, p: &EvasionPattern) -> bool {
        if p.confidence < self.min_confidence {
            return false;
        }
        if self.name_blocklist.contains(&p.name) {
            return false;
        }
        if !self.only_categories.is_empty() && !self.only_categories.contains(&p.category) {
            return false;
        }
        true
    }

    /// Apply filter to a slice of patterns and return the matching ones.
    #[must_use]
    pub fn apply<'a>(&self, patterns: &'a [EvasionPattern]) -> Vec<&'a EvasionPattern> {
        patterns.iter().filter(|p| self.passes(p)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionTechniqueIndex — fast lookup of patterns by category and name
// ─────────────────────────────────────────────────────────────────────────────

/// Indexes all evasion patterns by category and by name for fast lookup.
pub struct EvasionTechniqueIndex {
    /// By-category index: category label → list of pattern indices in the flat `patterns` vec.
    by_category: std::collections::HashMap<String, Vec<usize>>,
    /// By-name index: name → index.
    by_name: std::collections::HashMap<&'static str, usize>,
    /// All patterns (shared ownership with the source db).
    patterns: Vec<EvasionPattern>,
}

impl EvasionTechniqueIndex {
    /// Build an index from the default pattern database.
    #[must_use]
    pub fn build() -> Self {
        let db = EvasionPatternDb::new();
        let mut by_category: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        let mut by_name: std::collections::HashMap<&'static str, usize> =
            std::collections::HashMap::new();
        for (i, p) in db.patterns.iter().enumerate() {
            by_category
                .entry(p.category.label().to_owned())
                .or_default()
                .push(i);
            by_name.insert(p.name, i);
        }
        Self {
            by_category,
            by_name,
            patterns: db.patterns,
        }
    }

    /// Look up a pattern by name.
    #[must_use]
    pub fn get_by_name(&self, name: &'static str) -> Option<&EvasionPattern> {
        self.by_name.get(name).map(|&i| &self.patterns[i])
    }

    /// Return all patterns in `category`.
    #[must_use]
    pub fn get_by_category(&self, category: EvasionCategory) -> Vec<&EvasionPattern> {
        self.by_category
            .get(category.label())
            .map(|indices| indices.iter().map(|&i| &self.patterns[i]).collect())
            .unwrap_or_default()
    }

    /// Number of indexed patterns.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Return `true` when the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Return all category labels present in the index.
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.by_category.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternCoverageReport — measures how many unique categories are covered
// ─────────────────────────────────────────────────────────────────────────────

/// Reports which evasion categories are present and missing in a scan result.
#[derive(Debug, Clone, Default)]
pub struct PatternCoverageReport {
    /// Categories observed in the scan.
    pub detected_categories: Vec<String>,
    /// Categories not observed.
    pub missing_categories: Vec<String>,
    /// Fraction of known categories that were detected.
    pub coverage_fraction: f32,
}

impl PatternCoverageReport {
    /// Build a coverage report from a list of evasion matches.
    #[must_use]
    pub fn from_matches(matches: &[EvasionMatch]) -> Self {
        let all_cats = [
            EvasionCategory::AntiDump,
            EvasionCategory::AntiEmulation,
            EvasionCategory::Sandbox,
            EvasionCategory::AntiHooking,
            EvasionCategory::Timing,
            EvasionCategory::AntiDebug,
        ];

        let detected: std::collections::HashSet<String> = matches
            .iter()
            .map(|m| m.category.label().to_owned())
            .collect();

        let detected_categories: Vec<String> = all_cats
            .iter()
            .filter(|c| detected.contains(c.label()))
            .map(|c| c.label().to_owned())
            .collect();

        let missing_categories: Vec<String> = all_cats
            .iter()
            .filter(|c| !detected.contains(c.label()))
            .map(|c| c.label().to_owned())
            .collect();

        let coverage_fraction = detected_categories.len() as f32 / all_cats.len() as f32;

        Self {
            detected_categories,
            missing_categories,
            coverage_fraction,
        }
    }

    /// Return `true` if all known categories are covered.
    #[must_use]
    pub const fn is_full_coverage(&self) -> bool {
        self.missing_categories.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionBypassGenerator — generates bypass suggestions for detected patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A suggested bypass action for a detected evasion pattern.
#[derive(Debug, Clone)]
pub struct BypassSuggestion {
    /// The pattern that triggered this suggestion.
    pub pattern_name: &'static str,
    /// Short description of the bypass.
    pub description: String,
    /// Bypass mechanism.
    pub mechanism: BypassMechanism,
    /// Estimated effectiveness (0–100).
    pub effectiveness: u8,
}

/// How a bypass is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMechanism {
    /// Binary patch (overwrite bytes).
    BinaryPatch,
    /// Frida / DBI hook.
    DbiHook,
    /// Kernel-level bypass (driver / hypervisor).
    KernelLevel,
    /// Static analysis only (no runtime bypass needed).
    StaticOnly,
}

impl BypassMechanism {
    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BinaryPatch => "binary-patch",
            Self::DbiHook => "dbi-hook",
            Self::KernelLevel => "kernel",
            Self::StaticOnly => "static-only",
        }
    }
}

/// Generates bypass suggestions for a list of evasion matches.
#[derive(Debug, Clone, Default)]
pub struct EvasionBypassGenerator;

impl EvasionBypassGenerator {
    /// Create a new generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generate suggestions for all `matches`.
    #[must_use]
    pub fn generate(&self, matches: &[EvasionMatch]) -> Vec<BypassSuggestion> {
        matches.iter().filter_map(|m| self.suggest(m)).collect()
    }

    fn suggest(&self, m: &EvasionMatch) -> Option<BypassSuggestion> {
        let (desc, mech, eff) = match m.category {
            EvasionCategory::AntiDebug => (
                format!("Patch {} to return 0/false", m.name),
                BypassMechanism::BinaryPatch,
                90,
            ),
            EvasionCategory::AntiEmulation => (
                format!("Hook {} to return constant timing value", m.name),
                BypassMechanism::DbiHook,
                80,
            ),
            EvasionCategory::Sandbox => (
                format!("Patch or hook {} to return 'not sandbox'", m.name),
                BypassMechanism::DbiHook,
                75,
            ),
            EvasionCategory::AntiHooking => (
                format!("Patch {} to skip hook-detection", m.name),
                BypassMechanism::BinaryPatch,
                85,
            ),
            EvasionCategory::Timing => (
                format!("Hook timing API to return constant for {}", m.name),
                BypassMechanism::DbiHook,
                88,
            ),
            EvasionCategory::AntiDump => (
                format!("Bypass {} via kernel-level memory protection", m.name),
                BypassMechanism::KernelLevel,
                70,
            ),
            _ => (
                format!("Analyse {} manually", m.name),
                BypassMechanism::StaticOnly,
                40,
            ),
        };
        Some(BypassSuggestion {
            pattern_name: m.name,
            description: desc,
            mechanism: mech,
            effectiveness: eff,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvasionRiskAssessor — combines scores into an overall risk rating
// ─────────────────────────────────────────────────────────────────────────────

/// Dimensions of evasion risk.
#[derive(Debug, Clone, Default)]
pub struct EvasionRiskAssessment {
    /// Risk score in [0.0, 1.0].
    pub score: f32,
    /// Human-readable risk level: "critical", "high", "medium", "low".
    pub level: &'static str,
    /// Category breakdown: label → `hit_count`.
    pub breakdown: std::collections::HashMap<String, usize>,
    /// Top detected techniques (name, confidence).
    pub top_techniques: Vec<(&'static str, u8)>,
}

impl EvasionRiskAssessment {
    /// Compute a risk assessment from a list of evasion matches.
    #[must_use]
    pub fn from_matches(matches: &[EvasionMatch]) -> Self {
        let mut breakdown: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for m in matches {
            *breakdown.entry(m.category.label().to_owned()).or_insert(0) += 1;
        }

        let mut top: Vec<(&'static str, u8)> =
            matches.iter().map(|m| (m.name, m.confidence)).collect();
        top.sort_by_key(|b| std::cmp::Reverse(b.1));
        top.dedup_by_key(|t| t.0);
        top.truncate(5);

        // Score: weighted sum of category counts normalised by severity.
        let score = Self::compute_score(&breakdown).clamp(0.0, 1.0);
        let level = match (score * 10.0) as u32 {
            9..=10 => "critical",
            6..=8 => "high",
            3..=5 => "medium",
            _ => "low",
        };

        Self {
            score,
            level,
            breakdown,
            top_techniques: top,
        }
    }

    fn compute_score(breakdown: &std::collections::HashMap<String, usize>) -> f32 {
        // Each category contributes a weighted fraction to the score.
        let weights = [
            ("anti-debug", 0.25),
            ("anti-dump", 0.20),
            ("anti-emulation", 0.20),
            ("sandbox", 0.15),
            ("anti-hooking", 0.10),
            ("timing", 0.05),
            ("misc", 0.05),
        ];
        let mut score = 0.0_f32;
        for (label, weight) in &weights {
            let count = breakdown.get(*label).copied().unwrap_or(0);
            score += f32::min(count as f32, 5.0) / 5.0 * weight;
        }
        score
    }

    /// Return `true` if the assessment indicates active evasion.
    #[must_use]
    pub fn is_evasive(&self) -> bool {
        self.score >= 0.2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDumpDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects code that obstructs or confuses memory dumping tools.
#[derive(Debug, Clone, Default)]
pub struct AntiDumpDetector;

impl AntiDumpDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for anti-dump patterns.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EvasionMatch> {
        EvasionPatternDb::new().scan_category(data, EvasionCategory::AntiDump)
    }

    /// Return `true` if any anti-dump pattern is found.
    #[must_use]
    pub fn is_present(&self, data: &[u8]) -> bool {
        !self.scan(data).is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiEmulationDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects emulator / sandbox evasion via CPU instruction tricks.
#[derive(Debug, Clone, Default)]
pub struct AntiEmulationDetector;

impl AntiEmulationDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for anti-emulation patterns.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EvasionMatch> {
        EvasionPatternDb::new().scan_category(data, EvasionCategory::AntiEmulation)
    }

    /// Return `true` if RDTSC or RDTSCP is present.
    #[must_use]
    pub fn has_rdtsc(&self, data: &[u8]) -> bool {
        data.windows(2).any(|w| w == [0x0F, 0x31])
            || data.windows(3).any(|w| w == [0x0F, 0x01, 0xF9])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects sandbox-environment artefact checks.
#[derive(Debug, Clone, Default)]
pub struct SandboxDetector;

impl SandboxDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for sandbox artefact patterns.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EvasionMatch> {
        EvasionPatternDb::new().scan_category(data, EvasionCategory::Sandbox)
    }

    /// Return `true` if any sandbox process-name check is found.
    #[must_use]
    pub fn has_process_check(&self, data: &[u8]) -> bool {
        let procs: &[&[u8]] = &[
            b"cuckoo",
            b"VBoxSvc",
            b"vmwaretray.exe",
            b"procmon.exe",
            b"wireshark.exe",
            b"x64dbg.exe",
            b"ollydbg.exe",
        ];
        procs.iter().any(|p| data.windows(p.len()).any(|w| w == *p))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiHookingDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects hook-detection and hook-removal techniques.
#[derive(Debug, Clone, Default)]
pub struct AntiHookingDetector;

impl AntiHookingDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for anti-hooking patterns.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EvasionMatch> {
        EvasionPatternDb::new().scan_category(data, EvasionCategory::AntiHooking)
    }

    /// Return `true` if a direct syscall (`0F 05`) is present.
    #[must_use]
    pub fn has_direct_syscall(&self, data: &[u8]) -> bool {
        data.windows(2).any(|w| w == [0x0F, 0x05])
    }

    /// Return `true` if an `INT 2E` syscall is present.
    #[must_use]
    pub fn has_int2e(&self, data: &[u8]) -> bool {
        data.windows(2).any(|w| w == [0xCD, 0x2E])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComprehensiveEvasionScanner — runs all detectors and aggregates results
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result from all evasion detectors.
#[derive(Debug, Clone, Default)]
pub struct ComprehensiveEvasionResult {
    /// All pattern matches from the database scan.
    pub matches: Vec<EvasionMatch>,
    /// Computed evasion score.
    pub score: EvasionScore,
    /// Whether any anti-dump technique was found.
    pub has_anti_dump: bool,
    /// Whether any anti-emulation technique was found.
    pub has_anti_emulation: bool,
    /// Whether any sandbox-evasion technique was found.
    pub has_sandbox: bool,
    /// Whether any anti-hooking technique was found.
    pub has_anti_hooking: bool,
    /// Overall risk assessment.
    pub risk: &'static str,
}

/// Runs all four detectors over `data` and returns a unified result.
#[must_use]
pub fn comprehensive_scan(data: &[u8]) -> ComprehensiveEvasionResult {
    let db = EvasionPatternDb::new();
    let matches = db.scan(data);
    let score = EvasionScore::from_matches(&matches);

    let has_anti_dump = matches
        .iter()
        .any(|m| m.category == EvasionCategory::AntiDump);
    let has_anti_emulation = matches
        .iter()
        .any(|m| m.category == EvasionCategory::AntiEmulation);
    let has_sandbox = matches
        .iter()
        .any(|m| m.category == EvasionCategory::Sandbox);
    let has_anti_hooking = matches
        .iter()
        .any(|m| m.category == EvasionCategory::AntiHooking);
    let risk = score.risk_level();

    ComprehensiveEvasionResult {
        matches,
        score,
        has_anti_dump,
        has_anti_emulation,
        has_sandbox,
        has_anti_hooking,
        risk,
    }
}

/// Filter a list of matches, keeping only those with confidence ≥ `min_conf`.
#[must_use]
pub fn filter_by_confidence(matches: &[EvasionMatch], min_conf: u8) -> Vec<&EvasionMatch> {
    matches
        .iter()
        .filter(|m| m.confidence >= min_conf)
        .collect()
}

/// Group matches by category and return a map of `category_label → Vec<EvasionMatch>`.
#[must_use]
pub fn group_by_category(
    matches: Vec<EvasionMatch>,
) -> std::collections::HashMap<String, Vec<EvasionMatch>> {
    let mut map: std::collections::HashMap<String, Vec<EvasionMatch>> =
        std::collections::HashMap::new();
    for m in matches {
        map.entry(m.category.label().to_owned())
            .or_default()
            .push(m);
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EvasionPatternDb ──────────────────────────────────────────────────────

    #[test]
    fn test_db_has_60_plus_patterns() {
        let db = EvasionPatternDb::new();
        assert!(
            db.count() >= 60,
            "expected ≥60 patterns, got {}",
            db.count()
        );
    }

    #[test]
    fn test_all_patterns_valid_lengths() {
        for p in EvasionPatternDb::new().patterns {
            assert!(
                p.is_valid(),
                "pattern '{}' has mismatched mask/pattern len",
                p.name
            );
        }
    }

    #[test]
    fn test_scan_rdtsc() {
        let db = EvasionPatternDb::new();
        let data = [0x90u8, 0x0F, 0x31, 0x90];
        let m = db.scan(&data);
        assert!(
            m.iter().any(|m| m.name == "rdtsc-timing"),
            "RDTSC not found"
        );
    }

    #[test]
    fn test_scan_peb() {
        let db = EvasionPatternDb::new();
        let data = [0x64u8, 0xA1, 0x30, 0x00, 0x00, 0x00];
        let m = db.scan(&data);
        assert!(m.iter().any(|m| m.name == "peb-being-debugged"));
    }

    #[test]
    fn test_scan_sorted_by_offset() {
        let db = EvasionPatternDb::new();
        let mut data = vec![0x90u8; 64];
        data[10] = 0x0F;
        data[11] = 0x31; // RDTSC at 10
        data[30] = 0x64;
        data[31] = 0xA1;
        data[32] = 0x30;
        data[33] = 0x00;
        data[34] = 0x00;
        data[35] = 0x00; // PEB at 30
        let m = db.scan(&data);
        for w in m.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    #[test]
    fn test_category_count_anti_dump() {
        let db = EvasionPatternDb::new();
        assert!(db.category_count(EvasionCategory::AntiDump) >= 8);
    }

    #[test]
    fn test_category_count_sandbox() {
        let db = EvasionPatternDb::new();
        assert!(db.category_count(EvasionCategory::Sandbox) >= 15);
    }

    #[test]
    fn test_scan_category_anti_hooking_direct_syscall() {
        let db = EvasionPatternDb::new();
        let data = [0x0Fu8, 0x05];
        let m = db.scan_category(&data, EvasionCategory::AntiHooking);
        assert!(m.iter().any(|m| m.name == "syscall-direct"));
    }

    #[test]
    fn test_scan_category_empty_data() {
        let db = EvasionPatternDb::new();
        assert!(db.scan_category(&[], EvasionCategory::Sandbox).is_empty());
    }

    #[test]
    fn test_scan_cuckoo_mutex() {
        let db = EvasionPatternDb::new();
        let data = b"CuckooMonitorMutex";
        let m = db.scan(data);
        assert!(m.iter().any(|m| m.name == "sandbox-mutex-cuckoo"));
    }

    #[test]
    fn test_scan_sleep_1min() {
        let db = EvasionPatternDb::new();
        let data = [0x68u8, 0x60, 0xEA, 0x00, 0x00];
        let m = db.scan(&data);
        assert!(m.iter().any(|m| m.name == "sleep-1min"));
    }

    // ── EvasionScore ──────────────────────────────────────────────────────────

    #[test]
    fn test_score_empty() {
        let s = EvasionScore::new();
        assert_eq!(s.total_hits, 0);
        assert_eq!(s.risk_level(), "low");
        assert_eq!(s.max_confidence(), 0);
    }

    #[test]
    fn test_score_record() {
        let mut s = EvasionScore::new();
        s.record(EvasionCategory::AntiDump, 80);
        assert_eq!(s.total_hits, 1);
        assert_eq!(s.max_confidence(), 80);
    }

    #[test]
    fn test_score_risk_levels() {
        let mut s = EvasionScore::new();
        assert_eq!(s.risk_level(), "low");
        s.record(EvasionCategory::Sandbox, 70);
        s.record(EvasionCategory::AntiDebug, 90);
        assert_eq!(s.risk_level(), "medium");
        for _ in 0..3 {
            s.record(EvasionCategory::Timing, 50);
        }
        assert_eq!(s.risk_level(), "high");
    }

    #[test]
    fn test_score_from_matches() {
        let db = EvasionPatternDb::new();
        let data = [0x0Fu8, 0x31]; // RDTSC
        let matches = db.scan(&data);
        let score = EvasionScore::from_matches(&matches);
        assert!(score.total_hits >= 1);
    }

    // ── AntiDumpDetector ──────────────────────────────────────────────────────

    #[test]
    fn test_anti_dump_mz_header() {
        let det = AntiDumpDetector::new();
        let data = [0x4Du8, 0x5A, 0x90, 0x00];
        assert!(det.is_present(&data));
    }

    #[test]
    fn test_anti_dump_ntdll_string() {
        let det = AntiDumpDetector::new();
        let data = b"NtUnmapViewOfSection";
        assert!(det.is_present(data));
    }

    #[test]
    fn test_anti_dump_empty() {
        let det = AntiDumpDetector::new();
        assert!(!det.is_present(&[]));
    }

    // ── AntiEmulationDetector ─────────────────────────────────────────────────

    #[test]
    fn test_anti_emulation_rdtsc() {
        let det = AntiEmulationDetector::new();
        let data = [0x0Fu8, 0x31];
        assert!(det.has_rdtsc(&data));
        assert!(!det.scan(&data).is_empty());
    }

    #[test]
    fn test_anti_emulation_rdtscp() {
        let det = AntiEmulationDetector::new();
        let data = [0x0Fu8, 0x01, 0xF9];
        assert!(det.has_rdtsc(&data));
    }

    #[test]
    fn test_anti_emulation_no_rdtsc() {
        let det = AntiEmulationDetector::new();
        assert!(!det.has_rdtsc(&[0x90; 16]));
    }

    // ── SandboxDetector ───────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_process_cuckoo() {
        let det = SandboxDetector::new();
        let data = b"cuckoo";
        assert!(det.has_process_check(data));
    }

    #[test]
    fn test_sandbox_vboxsvc() {
        let det = SandboxDetector::new();
        let data = b"VBoxSvc";
        assert!(det.has_process_check(data));
    }

    #[test]
    fn test_sandbox_scan_analyst_username() {
        let det = SandboxDetector::new();
        let data = b"analyst";
        let matches = det.scan(data);
        assert!(matches.iter().any(|m| m.name == "sandbox-username-analyst"));
    }

    #[test]
    fn test_sandbox_empty() {
        let det = SandboxDetector::new();
        assert!(det.scan(&[]).is_empty());
    }

    // ── AntiHookingDetector ───────────────────────────────────────────────────

    #[test]
    fn test_anti_hooking_direct_syscall() {
        let det = AntiHookingDetector::new();
        let data = [0x0Fu8, 0x05];
        assert!(det.has_direct_syscall(&data));
    }

    #[test]
    fn test_anti_hooking_int2e() {
        let det = AntiHookingDetector::new();
        let data = [0xCDu8, 0x2E];
        assert!(det.has_int2e(&data));
    }

    #[test]
    fn test_anti_hooking_ntdll_reload() {
        let det = AntiHookingDetector::new();
        let data = b"ntdll.dll";
        let m = det.scan(data);
        assert!(!m.is_empty());
    }

    #[test]
    fn test_anti_hooking_hot_patch_prefix() {
        let det = AntiHookingDetector::new();
        let data = [0x8Bu8, 0xFF, 0x55, 0x8B, 0xEC];
        let m = det.scan(&data);
        assert!(m.iter().any(|m| m.name == "detour-check-hot-patch"));
    }

    // ── EvasionCategory ───────────────────────────────────────────────────────

    #[test]
    fn test_category_labels() {
        assert_eq!(EvasionCategory::AntiDump.label(), "anti-dump");
        assert_eq!(EvasionCategory::Sandbox.label(), "sandbox");
        assert_eq!(EvasionCategory::AntiHooking.label(), "anti-hooking");
    }

    #[test]
    fn test_evasion_pattern_match_at_exact() {
        let pat = EvasionPattern {
            name: "test",
            description: "",
            category: EvasionCategory::Misc,
            pattern: &[0x0F, 0x31],
            mask: &[0xFF, 0xFF],
            confidence: 90,
        };
        assert!(pat.matches_at(&[0x90, 0x0F, 0x31, 0x90], 1));
        assert!(!pat.matches_at(&[0x90, 0x0F, 0x32, 0x90], 1));
    }

    #[test]
    fn test_evasion_pattern_match_wildcard() {
        let pat = EvasionPattern {
            name: "test",
            description: "",
            category: EvasionCategory::Misc,
            pattern: &[0x0F, 0x21, 0xC0],
            mask: &[0xFF, 0xFF, 0xF8],
            confidence: 85,
        };
        assert!(pat.matches_at(&[0x0F, 0x21, 0xC3], 0)); // lower 3 bits don't matter
        assert!(!pat.matches_at(&[0x0F, 0x22, 0xC0], 0)); // second byte differs
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_category_anti_debug_not_sensitive() {
        assert!(!EvasionCategory::AntiDebug.is_sensitive());
    }

    #[test]
    fn test_evasion_pattern_short_data() {
        let pat = EvasionPattern {
            name: "t",
            description: "",
            category: EvasionCategory::Misc,
            pattern: &[0xAA, 0xBB, 0xCC],
            mask: &[0xFF, 0xFF, 0xFF],
            confidence: 90,
        };
        // data shorter than pattern → no match
        assert!(!pat.matches_at(&[0xAA, 0xBB], 0));
    }

    #[test]
    fn test_scan_ntdll_string() {
        let det = AntiDumpDetector::new();
        let data = b"WriteProcessMemory";
        assert!(det.is_present(data));
    }

    #[test]
    fn test_scan_readprocessmemory() {
        let db = EvasionPatternDb::new();
        let data = b"ReadProcessMemory";
        let m = db.scan(data);
        assert!(m.iter().any(|m| m.name == "readprocessmemory-self"));
    }

    #[test]
    fn test_score_category_breakdown() {
        let mut s = EvasionScore::new();
        s.record(EvasionCategory::AntiDump, 80);
        s.record(EvasionCategory::AntiDump, 70);
        let (count, max_conf) = s.categories.get("anti-dump").copied().unwrap_or((0, 0));
        assert_eq!(count, 2);
        assert_eq!(max_conf, 80);
    }

    #[test]
    fn test_anti_hooking_sysenter() {
        let det = AntiHookingDetector::new();
        let data = [0x0Fu8, 0x34]; // SYSENTER
        let m = det.scan(&data);
        assert!(m.iter().any(|m| m.name == "sysenter"));
    }

    #[test]
    fn test_anti_hooking_int2e_scan() {
        let det = AntiHookingDetector::new();
        let data = [0xCDu8, 0x2E];
        let m = det.scan(&data);
        assert!(m.iter().any(|m| m.name == "int2e-syscall"));
    }

    #[test]
    fn test_sandbox_scan_wireshark_pipe() {
        let det = SandboxDetector::new();
        let data = b"\\\\.\\pipe\\wireshark";
        let m = det.scan(data);
        assert!(m.iter().any(|m| m.name == "sandbox-pipe-wireshark"));
    }

    #[test]
    fn test_scan_sleep_5min() {
        let db = EvasionPatternDb::new();
        let data = [0x68u8, 0xE0, 0x93, 0x04, 0x00];
        let m = db.scan(&data);
        assert!(m.iter().any(|m| m.name == "sleep-5min"));
    }

    #[test]
    fn test_evasion_score_from_empty_matches() {
        let score = EvasionScore::from_matches(&[]);
        assert_eq!(score.total_hits, 0);
    }

    #[test]
    fn test_anti_emulation_cpuid_leaf2() {
        let det = AntiEmulationDetector::new();
        let data = [0xB8u8, 0x02, 0x00, 0x00, 0x00, 0x0F, 0xA2];
        let m = det.scan(&data);
        assert!(m.iter().any(|m| m.name == "cpuid-leaf-2"));
    }

    #[test]
    fn test_anti_dump_scan_returns_category() {
        let det = AntiDumpDetector::new();
        let data = b"NtUnmapViewOfSection";
        let matches = det.scan(data);
        assert!(
            matches
                .iter()
                .all(|m| m.category == EvasionCategory::AntiDump)
        );
    }
}
