//! `taint_sinks_full` — Extended sink database: 200+ dangerous functions.
//!
//! Provides:
//! * [`TaintSinksFull`]    — complete sink registry and lookup
//! * [`SinkCategory`]      — functional category of a dangerous function
//! * [`SinkSeverity`]      — criticality level (Low/Medium/High/Critical)
//! * [`TaintFlowChecker`]  — checks whether a taint flow reaches a sink
//! * [`SinkEntry`]         — a single sink descriptor

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SinkSeverity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SinkSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for SinkSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── SinkCategory ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkCategory {
    MemoryWrite,
    MemoryCopy,
    StringOperation,
    FileIo,
    NetworkIo,
    ProcessExecution,
    FormatString,
    Allocation,
    Deallocation,
    Crypto,
    Authentication,
    Deserialization,
    SqlInjection,
    CommandInjection,
    XssReflection,
    PathTraversal,
    IntegerOverflow,
    UseAfterFree,
    RaceCondition,
    PrivilegeEscalation,
    Registry,
    InterProcess,
    Kernel,
    Other,
}

impl fmt::Display for SinkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ─── SinkEntry ───────────────────────────────────────────────────────────────

/// A single dangerous sink descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkEntry {
    pub name: String,
    pub category: SinkCategory,
    pub severity: SinkSeverity,
    pub tainted_arg_indices: Vec<usize>,
    pub description: String,
    pub cve_references: Vec<String>,
    pub platforms: Vec<String>,
}

impl SinkEntry {
    pub fn new(
        name: impl Into<String>,
        category: SinkCategory,
        severity: SinkSeverity,
        tainted_args: Vec<usize>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            severity,
            tainted_arg_indices: tainted_args,
            description: String::new(),
            cve_references: Vec::new(),
            platforms: vec!["all".into()],
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_platforms(mut self, plats: Vec<String>) -> Self {
        self.platforms = plats;
        self
    }

    pub fn is_critical(&self) -> bool {
        self.severity == SinkSeverity::Critical
    }

    pub fn affects_arg(&self, idx: usize) -> bool {
        self.tainted_arg_indices.contains(&idx)
    }

    pub fn is_windows_only(&self) -> bool {
        self.platforms == vec!["windows"]
    }

    pub fn is_linux_only(&self) -> bool {
        self.platforms == vec!["linux"]
    }
}

impl fmt::Display for SinkEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sink({}, {}, {})",
            self.name, self.category, self.severity
        )
    }
}

// ─── TaintFlowRecord ─────────────────────────────────────────────────────────

/// A taint flow that reached a sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlowRecord {
    pub sink_name: String,
    pub source_label: String,
    pub arg_index: usize,
    pub severity: SinkSeverity,
    pub category: SinkCategory,
    pub call_site: Option<u64>,
}

impl TaintFlowRecord {
    pub fn new(
        sink_name: impl Into<String>,
        source_label: impl Into<String>,
        arg_index: usize,
        severity: SinkSeverity,
        category: SinkCategory,
    ) -> Self {
        Self {
            sink_name: sink_name.into(),
            source_label: source_label.into(),
            arg_index,
            severity,
            category,
            call_site: None,
        }
    }

    pub fn at(mut self, addr: u64) -> Self {
        self.call_site = Some(addr);
        self
    }
}

impl fmt::Display for TaintFlowRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TaintFlow: {} -> {} (arg {}) [{}]",
            self.source_label, self.sink_name, self.arg_index, self.severity
        )
    }
}

// ─── TaintFlowChecker ────────────────────────────────────────────────────────

/// Checks whether tainted values flow into sink arguments.
pub struct TaintFlowChecker<'a> {
    sinks: &'a TaintSinksFull,
    pub flows_found: Vec<TaintFlowRecord>,
}

impl<'a> TaintFlowChecker<'a> {
    pub fn new(sinks: &'a TaintSinksFull) -> Self {
        Self {
            sinks,
            flows_found: Vec::new(),
        }
    }

    /// Check if a call to `function_name` with `tainted_args` (set of arg indices) is a sink hit.
    pub fn check_call(
        &mut self,
        function_name: &str,
        tainted_args: &HashSet<usize>,
        source_label: &str,
        call_site: Option<u64>,
    ) -> Vec<TaintFlowRecord> {
        let mut flows = Vec::new();
        if let Some(sink) = self.sinks.get(function_name) {
            for &arg_idx in &sink.tainted_arg_indices {
                if tainted_args.contains(&arg_idx) {
                    let mut flow = TaintFlowRecord::new(
                        function_name,
                        source_label,
                        arg_idx,
                        sink.severity,
                        sink.category,
                    );
                    if let Some(addr) = call_site {
                        flow = flow.at(addr);
                    }
                    flows.push(flow.clone());
                    self.flows_found.push(flow);
                }
            }
        }
        flows
    }

    /// Return only critical flows.
    pub fn critical_flows(&self) -> Vec<&TaintFlowRecord> {
        self.flows_found
            .iter()
            .filter(|f| f.severity == SinkSeverity::Critical)
            .collect()
    }

    /// Return flows of a given category.
    pub fn flows_of_category(&self, cat: SinkCategory) -> Vec<&TaintFlowRecord> {
        self.flows_found
            .iter()
            .filter(|f| f.category == cat)
            .collect()
    }

    pub fn total_flows(&self) -> usize {
        self.flows_found.len()
    }
}

// ─── TaintSinksFull ──────────────────────────────────────────────────────────

/// Complete sink registry with 200+ dangerous function entries.
pub struct TaintSinksFull {
    sinks: HashMap<String, SinkEntry>,
}

impl TaintSinksFull {
    /// Create and populate the full sink database.
    pub fn new() -> Self {
        let mut db = Self {
            sinks: HashMap::new(),
        };
        db.populate();
        db
    }

    /// Register a sink, MERGING with any entry already present for that name.
    ///
    /// `populate` registers 17 functions twice with different categories and
    /// argument lists (`WinExec`, `VirtualProtect`, `CryptEncrypt`, …). A plain
    /// `insert` let the second registration silently delete the first, so the
    /// DB lost both the original category and — worse for a taint analysis —
    /// sink argument positions it had explicitly been told about.
    ///
    /// Merge policy: keep the FIRST category (the primary classification),
    /// take the HIGHER severity, and take the UNION of the tainted argument
    /// indices. Union is the safe direction: a sink argument that is checked
    /// but harmless costs a look, one that is dropped costs a missed finding.
    fn add(&mut self, entry: SinkEntry) {
        match self.sinks.get_mut(&entry.name) {
            Some(existing) => {
                if entry.severity > existing.severity {
                    existing.severity = entry.severity;
                }
                for idx in entry.tainted_arg_indices {
                    if !existing.tainted_arg_indices.contains(&idx) {
                        existing.tainted_arg_indices.push(idx);
                    }
                }
                existing.tainted_arg_indices.sort_unstable();
            }
            None => {
                self.sinks.insert(entry.name.clone(), entry);
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<&SinkEntry> {
        self.sinks.get(name)
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    pub fn sinks_of_category(&self, cat: SinkCategory) -> Vec<&SinkEntry> {
        self.sinks.values().filter(|s| s.category == cat).collect()
    }

    pub fn critical_sinks(&self) -> Vec<&SinkEntry> {
        self.sinks.values().filter(|s| s.is_critical()).collect()
    }

    pub fn all_names(&self) -> Vec<&String> {
        self.sinks.keys().collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.sinks.contains_key(name)
    }

    // ── sink registration ─────────────────────────────────────────────────

    fn populate(&mut self) {
        use SinkCategory::*;
        use SinkSeverity::*;

        // ── C standard library ────────────────────────────────────────────
        self.add(SinkEntry::new("strcpy", MemoryCopy, Critical, vec![0]));
        self.add(SinkEntry::new("strncpy", MemoryCopy, High, vec![0, 2]));
        self.add(SinkEntry::new("strcat", MemoryCopy, Critical, vec![0, 1]));
        self.add(SinkEntry::new("strncat", MemoryCopy, High, vec![0, 1]));
        self.add(SinkEntry::new(
            "sprintf",
            FormatString,
            Critical,
            vec![0, 1],
        ));
        self.add(SinkEntry::new("snprintf", FormatString, High, vec![0, 2]));
        self.add(SinkEntry::new(
            "vsprintf",
            FormatString,
            Critical,
            vec![0, 1],
        ));
        self.add(SinkEntry::new("vsnprintf", FormatString, High, vec![0, 2]));
        self.add(SinkEntry::new("printf", FormatString, High, vec![0]));
        self.add(SinkEntry::new("fprintf", FormatString, High, vec![1]));
        self.add(SinkEntry::new("scanf", FormatString, High, vec![0]));
        self.add(SinkEntry::new("sscanf", FormatString, High, vec![1]));
        self.add(SinkEntry::new("fscanf", FormatString, High, vec![1]));
        self.add(SinkEntry::new("gets", MemoryWrite, Critical, vec![0]));
        self.add(SinkEntry::new("fgets", MemoryWrite, High, vec![0]));
        self.add(SinkEntry::new("memcpy", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("memmove", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("memset", MemoryWrite, Medium, vec![0]));
        self.add(SinkEntry::new("bcopy", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("strtol", IntegerOverflow, Medium, vec![0]));
        self.add(SinkEntry::new("atoi", IntegerOverflow, Medium, vec![0]));
        self.add(SinkEntry::new("atol", IntegerOverflow, Medium, vec![0]));
        self.add(SinkEntry::new("atof", IntegerOverflow, Low, vec![0]));

        // ── heap allocators ───────────────────────────────────────────────
        self.add(SinkEntry::new("malloc", Allocation, Medium, vec![0]));
        self.add(SinkEntry::new("calloc", Allocation, Medium, vec![0, 1]));
        self.add(SinkEntry::new("realloc", Allocation, Medium, vec![0, 1]));
        self.add(SinkEntry::new("free", Deallocation, High, vec![0]));
        self.add(SinkEntry::new("alloca", Allocation, High, vec![0]));
        self.add(SinkEntry::new("_alloca", Allocation, High, vec![0]));

        // ── file I/O ──────────────────────────────────────────────────────
        self.add(SinkEntry::new("fopen", FileIo, High, vec![0]));
        self.add(SinkEntry::new("open", FileIo, High, vec![0]));
        self.add(SinkEntry::new("fwrite", FileIo, Medium, vec![0]));
        self.add(SinkEntry::new("fread", FileIo, Medium, vec![1]));
        self.add(SinkEntry::new("write", FileIo, Medium, vec![1]));
        self.add(SinkEntry::new("read", FileIo, Medium, vec![1]));
        self.add(SinkEntry::new("unlink", FileIo, High, vec![0]));
        self.add(SinkEntry::new("rename", FileIo, High, vec![0, 1]));
        self.add(SinkEntry::new("remove", FileIo, High, vec![0]));
        self.add(SinkEntry::new("mkdir", FileIo, Medium, vec![0]));
        self.add(SinkEntry::new("chdir", PathTraversal, High, vec![0]));
        self.add(SinkEntry::new("realpath", PathTraversal, High, vec![0]));
        self.add(SinkEntry::new("access", PathTraversal, High, vec![0]));
        self.add(SinkEntry::new("stat", FileIo, Medium, vec![0]));
        self.add(SinkEntry::new("lstat", FileIo, Medium, vec![0]));

        // ── process execution ─────────────────────────────────────────────
        self.add(SinkEntry::new(
            "system",
            CommandInjection,
            Critical,
            vec![0],
        ));
        self.add(SinkEntry::new("popen", CommandInjection, Critical, vec![0]));
        self.add(SinkEntry::new(
            "execve",
            ProcessExecution,
            Critical,
            vec![0, 1, 2],
        ));
        self.add(SinkEntry::new(
            "execvp",
            ProcessExecution,
            Critical,
            vec![0, 1],
        ));
        self.add(SinkEntry::new(
            "execle",
            ProcessExecution,
            Critical,
            vec![0],
        ));
        self.add(SinkEntry::new("execl", ProcessExecution, Critical, vec![0]));
        self.add(SinkEntry::new(
            "execlp",
            ProcessExecution,
            Critical,
            vec![0],
        ));
        self.add(SinkEntry::new("fork", ProcessExecution, Medium, vec![]));
        self.add(SinkEntry::new(
            "posix_spawn",
            ProcessExecution,
            High,
            vec![2],
        ));

        // ── network I/O ───────────────────────────────────────────────────
        self.add(SinkEntry::new("send", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("sendto", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("recv", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("connect", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("bind", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("accept", NetworkIo, Medium, vec![]));
        self.add(SinkEntry::new("getaddrinfo", NetworkIo, Medium, vec![0]));

        // ── Windows API ───────────────────────────────────────────────────
        self.add(
            SinkEntry::new("CreateFileA", FileIo, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CreateFileW", FileIo, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("WriteFile", FileIo, Medium, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("ReadFile", FileIo, Medium, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("DeleteFileA", FileIo, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("DeleteFileW", FileIo, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("MoveFileA", FileIo, High, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("MoveFileW", FileIo, High, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CopyFileA", FileIo, High, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CopyFileW", FileIo, High, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("ShellExecuteA", CommandInjection, Critical, vec![2, 3])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("ShellExecuteW", CommandInjection, Critical, vec![2, 3])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CreateProcessA", ProcessExecution, Critical, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CreateProcessW", ProcessExecution, Critical, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("WinExec", CommandInjection, Critical, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("RegSetValueExA", Registry, High, vec![3])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("RegSetValueExW", Registry, High, vec![3])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("RegOpenKeyExA", Registry, Medium, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("RegOpenKeyExW", Registry, Medium, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("LoadLibraryA", ProcessExecution, Critical, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("LoadLibraryW", ProcessExecution, Critical, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("GetProcAddress", ProcessExecution, High, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("VirtualAlloc", Allocation, High, vec![0, 1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("VirtualProtect", Kernel, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("WriteProcessMemory", MemoryWrite, Critical, vec![1, 2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("ReadProcessMemory", MemoryWrite, High, vec![1, 2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("SetWindowsHookExA", Kernel, High, vec![2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("SetWindowsHookExW", Kernel, High, vec![2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CreateRemoteThread", InterProcess, Critical, vec![0, 4])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("NtWriteVirtualMemory", MemoryWrite, Critical, vec![1, 2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("NtMapViewOfSection", Kernel, High, vec![0])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("NtCreateSection", Kernel, High, vec![6])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("HttpSendRequestA", NetworkIo, High, vec![2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("HttpSendRequestW", NetworkIo, High, vec![2])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("WSASend", NetworkIo, High, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("WSARecv", NetworkIo, High, vec![1])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CryptEncrypt", Crypto, High, vec![5])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CryptDecrypt", Crypto, High, vec![5])
                .with_platforms(vec!["windows".into()]),
        );
        self.add(
            SinkEntry::new("CryptHashData", Crypto, Medium, vec![1])
                .with_platforms(vec!["windows".into()]),
        );

        // ── Linux / POSIX ─────────────────────────────────────────────────
        self.add(
            SinkEntry::new("mmap", Kernel, High, vec![0, 1]).with_platforms(vec!["linux".into()]),
        );
        self.add(
            SinkEntry::new("mprotect", Kernel, High, vec![0]).with_platforms(vec!["linux".into()]),
        );
        self.add(
            SinkEntry::new("ptrace", Kernel, Critical, vec![1, 2, 3])
                .with_platforms(vec!["linux".into()]),
        );
        self.add(
            SinkEntry::new("ioctl", Kernel, High, vec![2]).with_platforms(vec!["linux".into()]),
        );
        self.add(
            SinkEntry::new("sendmsg", NetworkIo, High, vec![1])
                .with_platforms(vec!["linux".into()]),
        );
        self.add(
            SinkEntry::new("recvmsg", NetworkIo, High, vec![1])
                .with_platforms(vec!["linux".into()]),
        );

        // ── crypto ────────────────────────────────────────────────────────
        self.add(SinkEntry::new("EVP_EncryptUpdate", Crypto, High, vec![2]));
        self.add(SinkEntry::new("EVP_DecryptUpdate", Crypto, High, vec![2]));
        self.add(SinkEntry::new("MD5_Update", Crypto, Medium, vec![1]));
        self.add(SinkEntry::new("SHA1_Update", Crypto, Medium, vec![1]));
        self.add(SinkEntry::new("SHA256_Update", Crypto, Medium, vec![1]));
        self.add(SinkEntry::new("RAND_bytes", Crypto, Medium, vec![0]));

        // ── authentication ────────────────────────────────────────────────
        self.add(
            SinkEntry::new("strcmp", Authentication, Medium, vec![0, 1])
                .with_description("Use for password comparison is insecure (timing attack)"),
        );
        self.add(SinkEntry::new("strncmp", Authentication, Low, vec![0, 1]));
        self.add(SinkEntry::new("memcmp", Authentication, Medium, vec![0, 1]));

        // ── SQL ───────────────────────────────────────────────────────────
        self.add(SinkEntry::new(
            "sqlite3_exec",
            SqlInjection,
            Critical,
            vec![1],
        ));
        self.add(SinkEntry::new(
            "mysql_query",
            SqlInjection,
            Critical,
            vec![1],
        ));
        self.add(SinkEntry::new("PQexec", SqlInjection, Critical, vec![1]));
        self.add(SinkEntry::new(
            "sqlite3_prepare",
            SqlInjection,
            High,
            vec![1],
        ));

        // ── deserialization ───────────────────────────────────────────────
        self.add(SinkEntry::new("yaml_parse", Deserialization, High, vec![0]));
        self.add(SinkEntry::new(
            "json_loads",
            Deserialization,
            Medium,
            vec![0],
        ));
        self.add(SinkEntry::new(
            "pickle_loads",
            Deserialization,
            Critical,
            vec![0],
        ));
        self.add(SinkEntry::new(
            "unserialize",
            Deserialization,
            Critical,
            vec![0],
        ));

        // ── integer overflow ──────────────────────────────────────────────
        self.add(SinkEntry::new("abs", IntegerOverflow, Low, vec![0]));
        self.add(SinkEntry::new("labs", IntegerOverflow, Low, vec![0]));
        self.add(SinkEntry::new("llabs", IntegerOverflow, Low, vec![0]));

        // ── IPC ───────────────────────────────────────────────────────────
        self.add(SinkEntry::new("shmget", InterProcess, Medium, vec![0]));
        self.add(SinkEntry::new("shmat", InterProcess, High, vec![0]));
        self.add(SinkEntry::new("msgsnd", InterProcess, High, vec![1]));
        self.add(SinkEntry::new("msgrcv", InterProcess, High, vec![1]));
        self.add(SinkEntry::new("semop", InterProcess, Medium, vec![1]));

        // ── additional platform-specific ──────────────────────────────────
        self.add(SinkEntry::new("dlopen", ProcessExecution, High, vec![0]));
        self.add(SinkEntry::new("dlsym", ProcessExecution, High, vec![1]));
        self.add(SinkEntry::new("dlerror", Other, Low, vec![]));
        self.add(SinkEntry::new("setenv", Other, Medium, vec![0, 1]));
        self.add(SinkEntry::new("putenv", Other, Medium, vec![0]));
        self.add(SinkEntry::new("getenv", Other, Low, vec![0]));
        self.add(SinkEntry::new("signal", Kernel, High, vec![1]));
        self.add(SinkEntry::new("sigaction", Kernel, High, vec![1]));
        self.add(SinkEntry::new("raise", Kernel, High, vec![0]));
        self.add(SinkEntry::new("kill", Kernel, High, vec![0, 1]));
        self.add(SinkEntry::new("prctl", Kernel, High, vec![0]));
        self.add(SinkEntry::new("seccomp", Kernel, High, vec![2]));
        self.add(SinkEntry::new("chmod", FileIo, High, vec![0]));
        self.add(SinkEntry::new("chown", FileIo, High, vec![0]));
        self.add(SinkEntry::new("lchown", FileIo, High, vec![0]));
        self.add(SinkEntry::new("symlink", PathTraversal, High, vec![0, 1]));
        self.add(SinkEntry::new("link", PathTraversal, High, vec![0, 1]));
        self.add(SinkEntry::new("readlink", PathTraversal, Medium, vec![0]));
        self.add(SinkEntry::new("truncate", FileIo, High, vec![0]));
        self.add(SinkEntry::new("ftruncate", FileIo, Medium, vec![1]));
        self.add(SinkEntry::new("pread", FileIo, High, vec![1]));
        self.add(SinkEntry::new("pwrite", FileIo, High, vec![1]));
        self.add(SinkEntry::new("writev", FileIo, High, vec![1]));
        self.add(SinkEntry::new("readv", FileIo, High, vec![1]));
        self.add(SinkEntry::new("lockf", FileIo, Medium, vec![]));
        self.add(SinkEntry::new("flock", FileIo, Medium, vec![]));
        self.add(SinkEntry::new("fcntl", FileIo, Medium, vec![2]));
        self.add(SinkEntry::new("setsockopt", NetworkIo, Medium, vec![3]));
        self.add(SinkEntry::new("getsockopt", NetworkIo, Low, vec![3]));
        self.add(SinkEntry::new("inet_aton", NetworkIo, Medium, vec![0]));
        self.add(SinkEntry::new("inet_addr", NetworkIo, Medium, vec![0]));
        self.add(SinkEntry::new("gethostbyname", NetworkIo, Medium, vec![0]));
        self.add(SinkEntry::new("sprintf_s", FormatString, High, vec![0, 2]));
        self.add(SinkEntry::new("wcscpy", StringOperation, Critical, vec![0]));
        self.add(SinkEntry::new(
            "wcscat",
            StringOperation,
            Critical,
            vec![0, 1],
        ));
        self.add(SinkEntry::new("wcsncpy", StringOperation, High, vec![0]));
        self.add(SinkEntry::new(
            "swprintf",
            FormatString,
            Critical,
            vec![0, 2],
        ));
        self.add(SinkEntry::new("_snwprintf", FormatString, High, vec![0, 3]));

        // ── Extended C/Posix string & memory ─────────────────────────────
        self.add(SinkEntry::new("stpcpy", StringOperation, High, vec![0, 1]));
        self.add(SinkEntry::new("stpncpy", StringOperation, High, vec![0, 1]));
        self.add(SinkEntry::new("strlcpy", StringOperation, Medium, vec![0, 1]));
        self.add(SinkEntry::new("strlcat", StringOperation, Medium, vec![0, 1]));
        self.add(SinkEntry::new("strdup", Allocation, Medium, vec![0]));
        self.add(SinkEntry::new("strndup", Allocation, Medium, vec![0, 1]));
        self.add(SinkEntry::new("memccpy", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("wmemcpy", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("wmemmove", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("mempcpy", MemoryCopy, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("strtoul", IntegerOverflow, Medium, vec![0]));
        self.add(SinkEntry::new("strtoll", IntegerOverflow, Medium, vec![0]));
        self.add(SinkEntry::new("strtoull", IntegerOverflow, Medium, vec![0]));

        // ── Extended Windows API ─────────────────────────────────────────
        self.add(SinkEntry::new("lstrcpyA", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("lstrcpyW", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("lstrcatA", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("lstrcatW", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("StrCpyA", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("StrCpyW", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("StrCatA", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("StrCatW", StringOperation, Critical, vec![0, 1]));
        self.add(SinkEntry::new("WinExec", ProcessExecution, Critical, vec![0]));
        self.add(SinkEntry::new("ShellExecuteW", ProcessExecution, Critical, vec![2, 3]));
        self.add(SinkEntry::new("ShellExecuteExA", ProcessExecution, Critical, vec![0]));
        self.add(SinkEntry::new("ShellExecuteExW", ProcessExecution, Critical, vec![0]));
        self.add(SinkEntry::new("CreateFileW", FileIo, High, vec![0]));
        self.add(SinkEntry::new("DeleteFileA", FileIo, High, vec![0]));
        self.add(SinkEntry::new("DeleteFileW", FileIo, High, vec![0]));
        self.add(SinkEntry::new("MoveFileA", FileIo, High, vec![0, 1]));
        self.add(SinkEntry::new("MoveFileW", FileIo, High, vec![0, 1]));
        self.add(SinkEntry::new("CopyFileA", FileIo, High, vec![0, 1]));
        self.add(SinkEntry::new("CopyFileW", FileIo, High, vec![0, 1]));
        self.add(SinkEntry::new("RegOpenKeyA", Registry, Medium, vec![1]));
        self.add(SinkEntry::new("RegOpenKeyW", Registry, Medium, vec![1]));
        self.add(SinkEntry::new("RegSetValueExA", Registry, High, vec![1, 4]));
        self.add(SinkEntry::new("RegSetValueExW", Registry, High, vec![1, 4]));
        self.add(SinkEntry::new("RegCreateKeyExA", Registry, Medium, vec![1]));
        self.add(SinkEntry::new("RegCreateKeyExW", Registry, Medium, vec![1]));
        self.add(SinkEntry::new("RegDeleteKeyA", Registry, High, vec![1]));
        self.add(SinkEntry::new("RegDeleteKeyW", Registry, High, vec![1]));
        self.add(SinkEntry::new("URLDownloadToFileA", NetworkIo, Critical, vec![1, 2]));
        self.add(SinkEntry::new("URLDownloadToFileW", NetworkIo, Critical, vec![1, 2]));
        self.add(SinkEntry::new("InternetOpenUrlA", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("InternetOpenUrlW", NetworkIo, High, vec![1]));
        self.add(SinkEntry::new("HttpOpenRequestA", NetworkIo, High, vec![1, 2]));
        self.add(SinkEntry::new("HttpOpenRequestW", NetworkIo, High, vec![1, 2]));
        self.add(SinkEntry::new("WSAStartup", NetworkIo, Low, vec![1]));
        self.add(SinkEntry::new("CreateRemoteThread", ProcessExecution, Critical, vec![0, 3, 4]));
        self.add(SinkEntry::new("NtCreateThreadEx", ProcessExecution, Critical, vec![3]));
        self.add(SinkEntry::new("VirtualAllocEx", Allocation, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("VirtualProtect", PrivilegeEscalation, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("VirtualProtectEx", PrivilegeEscalation, High, vec![0, 1, 2, 3]));
        self.add(SinkEntry::new("SetWindowsHookExA", PrivilegeEscalation, High, vec![1, 2]));
        self.add(SinkEntry::new("SetWindowsHookExW", PrivilegeEscalation, High, vec![1, 2]));
        self.add(SinkEntry::new("AdjustTokenPrivileges", PrivilegeEscalation, High, vec![0, 2]));
        self.add(SinkEntry::new("ImpersonateLoggedOnUser", PrivilegeEscalation, High, vec![0]));
        self.add(SinkEntry::new("LogonUserA", Authentication, High, vec![0, 1, 2]));
        self.add(SinkEntry::new("LogonUserW", Authentication, High, vec![0, 1, 2]));

        // ── Crypto / hashing ─────────────────────────────────────────────
        self.add(SinkEntry::new("MD5_Init", Crypto, Medium, vec![0]));
        self.add(SinkEntry::new("SHA1_Init", Crypto, Medium, vec![0]));
        self.add(SinkEntry::new("CryptAcquireContextA", Crypto, Medium, vec![1, 2]));
        self.add(SinkEntry::new("CryptAcquireContextW", Crypto, Medium, vec![1, 2]));
        self.add(SinkEntry::new("CryptEncrypt", Crypto, High, vec![3]));
        self.add(SinkEntry::new("CryptDecrypt", Crypto, High, vec![3]));

        // ── Deserialization / parsing ────────────────────────────────────
        self.add(SinkEntry::new("xmlParseDoc", Deserialization, High, vec![0]));
        self.add(SinkEntry::new("xmlReadMemory", Deserialization, High, vec![0, 1]));
        self.add(SinkEntry::new("json_loads", Deserialization, Medium, vec![0]));
        self.add(SinkEntry::new("pickle_loads", Deserialization, Critical, vec![0]));
        self.add(SinkEntry::new("yaml_load", Deserialization, Critical, vec![0]));
    }
}

impl Default for TaintSinksFull {
    fn default() -> Self {
        Self::new()
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sinks() -> TaintSinksFull {
        TaintSinksFull::new()
    }

    // ── SinkEntry ────────────────────────────────────────────────────────────

    #[test]
    fn test_sink_entry_creation() {
        let s = SinkEntry::new(
            "strcpy",
            SinkCategory::MemoryCopy,
            SinkSeverity::Critical,
            vec![0],
        );
        assert_eq!(s.name, "strcpy");
        assert!(s.is_critical());
    }

    #[test]
    fn test_sink_entry_affects_arg() {
        let s = SinkEntry::new(
            "memcpy",
            SinkCategory::MemoryCopy,
            SinkSeverity::High,
            vec![0, 1],
        );
        assert!(s.affects_arg(0));
        assert!(s.affects_arg(1));
        assert!(!s.affects_arg(2));
    }

    #[test]
    fn test_sink_entry_description() {
        let s = SinkEntry::new("x", SinkCategory::Other, SinkSeverity::Low, vec![])
            .with_description("test desc");
        assert_eq!(s.description, "test desc");
    }

    #[test]
    fn test_sink_entry_windows_only() {
        let s = SinkEntry::new("x", SinkCategory::Other, SinkSeverity::Low, vec![])
            .with_platforms(vec!["windows".into()]);
        assert!(s.is_windows_only());
        assert!(!s.is_linux_only());
    }

    // ── TaintSinksFull ───────────────────────────────────────────────────────

    #[test]
    fn test_sinks_total_count() {
        let db = sinks();
        assert!(
            db.len() >= 200,
            "Expected at least 200 sinks, got {}",
            db.len()
        );
    }

    #[test]
    fn test_sinks_contains_strcpy() {
        assert!(sinks().contains("strcpy"));
    }

    #[test]
    fn test_sinks_contains_system() {
        assert!(sinks().contains("system"));
    }

    #[test]
    fn test_sinks_contains_execve() {
        assert!(sinks().contains("execve"));
    }

    #[test]
    fn test_sinks_contains_createfilea() {
        assert!(sinks().contains("CreateFileA"));
    }

    #[test]
    fn test_sinks_contains_shellexecutea() {
        assert!(sinks().contains("ShellExecuteA"));
    }

    #[test]
    fn test_sinks_contains_sqlite3_exec() {
        assert!(sinks().contains("sqlite3_exec"));
    }

    #[test]
    fn test_sinks_strcpy_critical() {
        let db = sinks();
        assert_eq!(db.get("strcpy").unwrap().severity, SinkSeverity::Critical);
    }

    #[test]
    fn test_sinks_of_category_memory_copy() {
        let db = sinks();
        let mem_copy = db.sinks_of_category(SinkCategory::MemoryCopy);
        assert!(!mem_copy.is_empty());
    }

    #[test]
    fn test_sinks_of_category_command_injection() {
        let db = sinks();
        let ci = db.sinks_of_category(SinkCategory::CommandInjection);
        assert!(!ci.is_empty());
    }

    #[test]
    fn test_sinks_critical_count() {
        let db = sinks();
        let crits = db.critical_sinks();
        assert!(!crits.is_empty());
    }

    #[test]
    fn test_sinks_get_missing() {
        let db = sinks();
        assert!(db.get("totally_unknown_fn").is_none());
    }

    #[test]
    fn test_sinks_memory_copy_args() {
        let db = sinks();
        let memcpy = db.get("memcpy").unwrap();
        assert!(memcpy.affects_arg(0));
        assert!(memcpy.affects_arg(1));
    }

    // ── TaintFlowChecker ─────────────────────────────────────────────────────

    #[test]
    fn test_checker_hit_strcpy() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        let flows = checker.check_call("strcpy", &tainted, "user_input", None);
        assert!(!flows.is_empty());
        assert_eq!(flows[0].severity, SinkSeverity::Critical);
    }

    #[test]
    fn test_checker_no_hit_wrong_arg() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(2usize); // strcpy only cares about arg 0
        let flows = checker.check_call("strcpy", &tainted, "src", None);
        assert!(flows.is_empty());
    }

    #[test]
    fn test_checker_no_hit_unknown_fn() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        let flows = checker.check_call("__unknown_fn__", &tainted, "src", None);
        assert!(flows.is_empty());
    }

    #[test]
    fn test_checker_critical_flows() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        checker.check_call("strcpy", &tainted, "src", Some(0x1000));
        checker.check_call("fgets", &tainted, "src", Some(0x2000));
        let crits = checker.critical_flows();
        assert!(!crits.is_empty());
    }

    #[test]
    fn test_checker_flows_of_category() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        checker.check_call("system", &tainted, "user_cmd", None);
        let ci = checker.flows_of_category(SinkCategory::CommandInjection);
        assert!(!ci.is_empty());
    }

    #[test]
    fn test_checker_call_site_recorded() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        checker.check_call("strcpy", &tainted, "s", Some(0xDEAD));
        assert_eq!(checker.flows_found[0].call_site, Some(0xDEAD));
    }

    #[test]
    fn test_checker_total_flows() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        tainted.insert(1usize);
        checker.check_call("memcpy", &tainted, "s", None);
        assert_eq!(checker.total_flows(), 2);
    }

    #[test]
    fn test_taint_flow_record_at() {
        let r = TaintFlowRecord::new("fn", "src", 0, SinkSeverity::High, SinkCategory::MemoryCopy)
            .at(0x1234);
        assert_eq!(r.call_site, Some(0x1234));
    }

    #[test]
    fn test_sink_severity_ordering() {
        assert!(SinkSeverity::Critical > SinkSeverity::High);
        assert!(SinkSeverity::High > SinkSeverity::Medium);
        assert!(SinkSeverity::Medium > SinkSeverity::Low);
    }

    #[test]
    fn test_sinks_contains_loadlibrarya() {
        assert!(sinks().contains("LoadLibraryA"));
    }

    #[test]
    fn test_sinks_contains_writeprocessmemory() {
        assert!(sinks().contains("WriteProcessMemory"));
    }

    #[test]
    fn test_sinks_contains_wcscpy() {
        assert!(sinks().contains("wcscpy"));
    }

    #[test]
    fn test_sinks_contains_swprintf() {
        assert!(sinks().contains("swprintf"));
    }

    #[test]
    fn test_sinks_contains_createprocessw() {
        assert!(sinks().contains("CreateProcessW"));
    }

    #[test]
    fn test_sinks_contains_ntwritevirtualmemory() {
        assert!(sinks().contains("NtWriteVirtualMemory"));
    }

    #[test]
    fn test_sinks_contains_ptrace() {
        assert!(sinks().contains("ptrace"));
    }

    #[test]
    fn test_sinks_contains_sqlite3_prepare() {
        assert!(sinks().contains("sqlite3_prepare"));
    }

    #[test]
    fn test_sinks_of_category_format_string() {
        let db = sinks();
        let fs = db.sinks_of_category(SinkCategory::FormatString);
        assert!(!fs.is_empty());
    }

    #[test]
    fn test_sinks_of_category_kernel() {
        let db = sinks();
        let k = db.sinks_of_category(SinkCategory::Kernel);
        assert!(!k.is_empty());
    }

    #[test]
    fn test_sinks_of_category_network() {
        let db = sinks();
        let n = db.sinks_of_category(SinkCategory::NetworkIo);
        assert!(!n.is_empty());
    }

    #[test]
    fn test_sinks_of_category_process_execution() {
        let db = sinks();
        let pe = db.sinks_of_category(SinkCategory::ProcessExecution);
        assert!(!pe.is_empty());
    }

    #[test]
    fn test_checker_system_critical() {
        let db = sinks();
        let mut checker = TaintFlowChecker::new(&db);
        let mut tainted = HashSet::new();
        tainted.insert(0usize);
        let flows = checker.check_call("system", &tainted, "cmd", None);
        assert!(!flows.is_empty());
        assert_eq!(flows[0].category, SinkCategory::CommandInjection);
    }

    #[test]
    fn test_sink_entry_linux_only() {
        let db = sinks();
        let ptrace = db.get("ptrace").unwrap();
        assert!(ptrace.is_linux_only());
    }

    #[test]
    fn test_taint_flow_record_display() {
        let r = TaintFlowRecord::new(
            "strcpy",
            "input",
            0,
            SinkSeverity::Critical,
            SinkCategory::MemoryCopy,
        );
        let s = format!("{r}");
        assert!(s.contains("strcpy"));
        assert!(s.contains("CRITICAL"));
    }

    #[test]
    fn test_sink_entry_display() {
        let s = SinkEntry::new("x", SinkCategory::Other, SinkSeverity::Low, vec![]);
        let disp = format!("{s}");
        assert!(disp.contains("Sink(x"));
    }

    #[test]
    fn test_sinks_all_names_not_empty() {
        let db = sinks();
        let names = db.all_names();
        assert!(!names.is_empty());
    }
}
