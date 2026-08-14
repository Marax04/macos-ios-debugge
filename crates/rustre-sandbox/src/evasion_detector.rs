//! `evasion_detector` — Detection of anti-analysis and evasion techniques.
//!
//! Identifies common evasion patterns used by malware to detect sandboxes,
//! debuggers, virtual machines, and analysis environments. Analyses both
//! static disassembly traces and dynamic execution logs.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── Timestamp ────────────────────────────────────────────────────────────────

pub type Timestamp = u64;

fn now_ms() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

// ─── Evasion Technique ────────────────────────────────────────────────────────

/// A specific evasion technique detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvasionTechnique {
    // Sleep-based
    SleepBeforeAction,
    LongSleep,        // Sleep > 60s
    TimeAcceleration, // Queries time before and after sleep to detect time skipping
    // User-interaction checks
    ForegroundWindowCheck,
    CursorPositionDelta,
    MouseClickCount,
    KeyboardInputCheck,
    // VM detection — CPUID
    CpuidHypervisorBit,
    CpuidVendorString, // "VMwareVMware", "KVMKVMKVM", "Microsoft Hv", etc.
    CpuidBrandString,  // Checks for virtual CPU brand
    // VM detection — registry
    VmRegistryKey,    // HKLM\SOFTWARE\VMware Inc\VMware Tools, etc.
    VmRegistryValue,
    // VM detection — process names
    VmProcessCheck,   // vmtoolsd.exe, vboxservice.exe, vboxtray.exe
    // VM detection — filesystem
    VmFileCheck,      // C:\windows\system32\drivers\vmmouse.sys, etc.
    // Debugger detection
    IsDebuggerPresent,
    CheckRemoteDebugger,
    NtQueryInformationProcess, // ProcessDebugPort
    HeapFlags,        // Check PEB->NtGlobalFlag
    DebugHeap,        // HEAP_TAIL_CHECKING_ENABLED etc.
    TimingCheck,      // RDTSC delta between two points
    SoftwareBreakpoint, // INT3 (0xCC) scan
    HardwareBreakpoint, // DR0-DR3 check via GetThreadContext
    // Anti-dump
    ErasePeHeader,    // MZ/PE header zeroed after loading
    TlsCallback,      // Code executed before entry point via TLS
    // Code integrity
    SelfModifyingCode,
    IntegrityChecksum,
    // Execution environment
    SandboxArtifacts, // Checks for short uptime, few running processes, low disk space
    UptimeCheck,      // < 10 minutes = likely sandbox
    ProcessCountCheck, // < 50 processes = likely sandbox
    UserActivityCheck, // No browser history / recent files = sandbox
}

impl std::fmt::Display for EvasionTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::SleepBeforeAction => "Sleep-before-action",
            Self::LongSleep => "Long sleep (>60s)",
            Self::TimeAcceleration => "Time-acceleration detection",
            Self::ForegroundWindowCheck => "GetForegroundWindow check",
            Self::CursorPositionDelta => "GetCursorPos delta check",
            Self::MouseClickCount => "Mouse click count check",
            Self::KeyboardInputCheck => "Keyboard input check",
            Self::CpuidHypervisorBit => "CPUID hypervisor bit",
            Self::CpuidVendorString => "CPUID vendor string",
            Self::CpuidBrandString => "CPUID brand string",
            Self::VmRegistryKey => "VM registry key check",
            Self::VmRegistryValue => "VM registry value check",
            Self::VmProcessCheck => "VM process name check",
            Self::VmFileCheck => "VM file presence check",
            Self::IsDebuggerPresent => "IsDebuggerPresent",
            Self::CheckRemoteDebugger => "CheckRemoteDebuggerPresent",
            Self::NtQueryInformationProcess => "NtQueryInformationProcess (DebugPort)",
            Self::HeapFlags => "PEB heap flags check",
            Self::DebugHeap => "Debug heap check",
            Self::TimingCheck => "RDTSC timing check",
            Self::SoftwareBreakpoint => "Software breakpoint scan",
            Self::HardwareBreakpoint => "Hardware breakpoint (DR) check",
            Self::ErasePeHeader => "PE header erasure",
            Self::TlsCallback => "TLS callback",
            Self::SelfModifyingCode => "Self-modifying code",
            Self::IntegrityChecksum => "Integrity checksum",
            Self::SandboxArtifacts => "Sandbox artifact check",
            Self::UptimeCheck => "System uptime check",
            Self::ProcessCountCheck => "Running process count check",
            Self::UserActivityCheck => "User activity check",
        };
        write!(f, "{name}")
    }
}

// ─── Detection Event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionEvent {
    pub id: u64,
    pub timestamp_ms: Timestamp,
    pub technique: EvasionTechnique,
    pub confidence: Confidence,
    pub address: Option<u64>,   // instruction address where detected
    pub api_call: Option<String>, // API/syscall name if applicable
    pub parameters: HashMap<String, String>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,    // Circumstantial evidence
    Medium, // Probable
    High,   // Near-certain
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

// ─── API Call Record ──────────────────────────────────────────────────────────

/// A recorded API call from the sandbox trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    pub timestamp_ms: Timestamp,
    pub pid: u32,
    pub thread_id: u32,
    pub return_address: u64,
    pub function_name: String,
    pub module: String,
    pub args: Vec<ApiArg>,
    pub return_value: Option<u64>,
    pub call_duration_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiArg {
    pub name: String,
    pub value: ApiArgValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiArgValue {
    Integer(i64),
    Unsigned(u64),
    String(String),
    Bytes(Vec<u8>),
    Null,
}

impl ApiArgValue {
    #[must_use] 
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) => Some(*v),
            Self::Integer(v) if *v >= 0 => Some((*v).cast_unsigned()),
            _ => None,
        }
    }
    #[must_use] 
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
}

// ─── Sleep Detector ───────────────────────────────────────────────────────────

/// Detects sleep-based evasion: calling Sleep/NtDelayExecution early.
#[derive(Debug, Default)]
struct SleepDetector {
    total_sleep_ms: u64,
    sleep_calls: Vec<(Timestamp, u64)>, // (when, duration_ms)
    first_meaningful_action_ms: Option<Timestamp>,
}

impl SleepDetector {
    fn record_sleep(&mut self, at_ms: Timestamp, duration_ms: u64) {
        self.total_sleep_ms += duration_ms;
        self.sleep_calls.push((at_ms, duration_ms));
    }

    const fn record_action(&mut self, at_ms: Timestamp) {
        if self.first_meaningful_action_ms.is_none() {
            self.first_meaningful_action_ms = Some(at_ms);
        }
    }

    fn check_sleep_before_action(&self, events: &mut Vec<EvasionEvent>, next_id: &mut u64) {
        // If there is a sleep before the first meaningful non-sleep action
        if let Some(action_ts) = self.first_meaningful_action_ms {
            for &(sleep_ts, dur_ms) in &self.sleep_calls {
                if sleep_ts < action_ts {
                    let confidence = if dur_ms > 5000 { Confidence::High } else { Confidence::Medium };
                    let id = *next_id;
                    *next_id += 1;
                    events.push(EvasionEvent {
                        id,
                        timestamp_ms: sleep_ts,
                        technique: EvasionTechnique::SleepBeforeAction,
                        confidence,
                        address: None,
                        api_call: Some("Sleep / NtDelayExecution".to_owned()),
                        parameters: {
                            let mut p = HashMap::new();
                            p.insert("duration_ms".to_owned(), dur_ms.to_string());
                            p
                        },
                        description: format!(
                            "Sleep of {dur_ms}ms before first meaningful action (likely sandbox evasion)"
                        ),
                    });
                }
                if dur_ms > 60_000 {
                    let id = *next_id;
                    *next_id += 1;
                    events.push(EvasionEvent {
                        id,
                        timestamp_ms: sleep_ts,
                        technique: EvasionTechnique::LongSleep,
                        confidence: Confidence::High,
                        address: None,
                        api_call: Some("Sleep".to_owned()),
                        parameters: {
                            let mut p = HashMap::new();
                            p.insert("duration_ms".to_owned(), dur_ms.to_string());
                            p
                        },
                        description: format!(
                            "Abnormally long sleep: {}s (sandboxes often cap to short durations)",
                            dur_ms / 1000
                        ),
                    });
                }
            }
        }
    }
}

// ─── VM Detection Patterns ────────────────────────────────────────────────────

/// Known VM-related artifacts.
mod vm_artifacts {
    pub const VM_PROCESS_NAMES: &[&str] = &[
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe", "vboxguest.exe",
        "vmsrvc.exe", "vmusrvc.exe",
        "qemu-ga.exe",
        "prl_tools.exe", "prl_cc.exe",
        "xenservice.exe",
        "winaflpersist.exe", "fiddler.exe", "procmon.exe",
        "processhacker.exe", "x64dbg.exe", "ollydbg.exe",
        "windbg.exe", "ida64.exe", "ida.exe",
    ];

    pub const VM_REGISTRY_KEYS: &[&str] = &[
        r"SOFTWARE\VMware, Inc.\VMware Tools",
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"HARDWARE\ACPI\DSDT\VBOX__",
        r"HARDWARE\ACPI\FADT\VBOX__",
        r"HARDWARE\ACPI\RSDT\VBOX__",
        r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        r"SYSTEM\ControlSet001\Services\VBoxGuest",
        r"SYSTEM\ControlSet001\Services\VBoxMouse",
        r"SYSTEM\ControlSet001\Services\VBoxSF",
        r"SYSTEM\ControlSet001\Services\VBoxVideo",
    ];

    pub const VM_FILES: &[&str] = &[
        r"C:\windows\system32\drivers\vmhgfs.sys",
        r"C:\windows\system32\drivers\vmmouse.sys",
        r"C:\windows\system32\drivers\vmxnet.sys",
        r"C:\windows\system32\drivers\vboxmouse.sys",
        r"C:\windows\system32\drivers\vboxguest.sys",
        r"C:\windows\system32\drivers\vboxsf.sys",
        r"C:\windows\system32\drivers\vboxvideo.sys",
    ];

    pub const VM_CPUID_VENDORS: &[&str] = &[
        "VMwareVMware",
        "KVMKVMKVM\0\0\0",
        "Microsoft Hv",
        "XenVMMXenVMM",
        "prl hyperv  ",
        "VBoxVBoxVBox",
    ];
}

// ─── CPUID Trace ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidTrace {
    pub address: u64,
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidTrace {
    /// Returns true if the hypervisor bit is queried and set.
    #[must_use] 
    pub const fn is_hypervisor_bit_check(&self) -> bool {
        // Leaf 1, ECX bit 31 = hypervisor present
        self.leaf == 0x1 && (self.ecx & (1 << 31)) != 0
    }

    /// Returns vendor string from leaf 0.
    #[must_use] 
    pub fn vendor_string(&self) -> Option<String> {
        if self.leaf == 0x4000_0000 {
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&self.ebx.to_le_bytes());
            bytes[4..8].copy_from_slice(&self.ecx.to_le_bytes());
            bytes[8..12].copy_from_slice(&self.edx.to_le_bytes());
            Some(String::from_utf8_lossy(&bytes).to_string())
        } else {
            None
        }
    }
}

// ─── Evasion Detector ─────────────────────────────────────────────────────────

/// Main evasion detection engine.
#[derive(Debug, Default)]
pub struct EvasionDetector {
    next_id: u64,
    events: Vec<EvasionEvent>,
    api_trace: Vec<ApiCallRecord>,
    cpuid_traces: Vec<CpuidTrace>,
    sleep_detector: SleepDetector,
    // track API call counts for pattern detection
    api_call_counts: HashMap<String, usize>,
    // registry keys accessed
    registry_accesses: Vec<String>,
    // process names queried
    process_name_queries: Vec<String>,
    // file paths checked
    file_checks: Vec<String>,
    // timing queries
    timing_queries: Vec<(Timestamp, u64)>, // (when, rdtsc_value)
}

impl EvasionDetector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ── Ingestion ─────────────────────────────────────────────────────────────

    /// Feed an API call from the sandbox trace into the detector.
    fn check_debugger_apis(&mut self, call: &ApiCallRecord, fn_lower: &str) {
        if matches!(fn_lower, "isdebuggerpresent" | "checkremotedebuggerpresent") {
            let technique = if fn_lower == "isdebuggerpresent" {
                EvasionTechnique::IsDebuggerPresent
            } else {
                EvasionTechnique::CheckRemoteDebugger
            };
            let id = self.next_id();
            self.events.push(EvasionEvent {
                id,
                timestamp_ms: call.timestamp_ms,
                technique,
                confidence: Confidence::High,
                address: None,
                api_call: Some(call.function_name.clone()),
                parameters: HashMap::new(),
                description: format!("Debugger detection via {}", call.function_name),
            });
        }
        if fn_lower == "ntqueryinformationprocess" {
            let class = call.args.get(1).and_then(|a| a.value.as_u64()).unwrap_or(0);
            if class == 7 || class == 30 {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: call.timestamp_ms,
                    technique: EvasionTechnique::NtQueryInformationProcess,
                    confidence: Confidence::High,
                    address: None,
                    api_call: Some(call.function_name.clone()),
                    parameters: { let mut p = HashMap::new(); p.insert("InformationClass".to_owned(), class.to_string()); p },
                    description: "NtQueryInformationProcess with ProcessDebugPort/DebugObjectHandle".to_owned(),
                });
            }
        }
        if fn_lower == "getforegroundwindow" {
            let id = self.next_id();
            self.events.push(EvasionEvent {
                id, timestamp_ms: call.timestamp_ms,
                technique: EvasionTechnique::ForegroundWindowCheck, confidence: Confidence::Medium,
                address: None, api_call: Some(call.function_name.clone()), parameters: HashMap::new(),
                description: "GetForegroundWindow called — checking for active user desktop".to_owned(),
            });
        }
        if fn_lower == "getcursorpos" {
            let id = self.next_id();
            self.events.push(EvasionEvent {
                id, timestamp_ms: call.timestamp_ms,
                technique: EvasionTechnique::CursorPositionDelta, confidence: Confidence::Medium,
                address: None, api_call: Some(call.function_name.clone()), parameters: HashMap::new(),
                description: "GetCursorPos called — checking for mouse movement".to_owned(),
            });
        }
    }

    fn check_vm_registry(&mut self, call: &ApiCallRecord, fn_lower: &str) {
        if !matches!(fn_lower, "regopenkeya" | "regopenkeyw" | "regopenkeyexa" | "regopenkeyexw") {
            return;
        }
        let Some(key) = call.args.get(1).and_then(|a| a.value.as_str()) else { return };
        let key_owned = key.to_owned();
        self.registry_accesses.push(key_owned.clone());
        let key_lower = key_owned.to_ascii_lowercase();
        for &vm_key in vm_artifacts::VM_REGISTRY_KEYS {
            if key_lower.contains(&vm_key.to_ascii_lowercase()) {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: call.timestamp_ms,
                    technique: EvasionTechnique::VmRegistryKey,
                    confidence: Confidence::High,
                    address: None,
                    api_call: Some(call.function_name.clone()),
                    parameters: { let mut p = HashMap::new(); p.insert("key".to_owned(), key_owned.clone()); p },
                    description: format!("VM registry key check: {key_owned}"),
                });
                break;
            }
        }
    }

    fn check_vm_files(&mut self, call: &ApiCallRecord, fn_lower: &str) {
        if !matches!(fn_lower, "createfilea" | "createfilew" | "getfileattributesa" | "getfileattributesw") {
            return;
        }
        let Some(path) = call.args.first().and_then(|a| a.value.as_str()) else { return };
        let path_owned = path.to_owned();
        let path_lower = path_owned.to_ascii_lowercase();
        for &vm_file in vm_artifacts::VM_FILES {
            if path_lower.contains(&vm_file.to_ascii_lowercase()) {
                self.file_checks.push(path_owned.clone());
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: call.timestamp_ms,
                    technique: EvasionTechnique::VmFileCheck,
                    confidence: Confidence::High,
                    address: None,
                    api_call: Some(call.function_name.clone()),
                    parameters: { let mut p = HashMap::new(); p.insert("path".to_owned(), path_owned); p },
                    description: format!("VM artifact file check: {vm_file}"),
                });
                break;
            }
        }
    }

    pub fn ingest_api_call(&mut self, call: ApiCallRecord) {
        let fn_lower = call.function_name.to_ascii_lowercase();
        *self.api_call_counts.entry(fn_lower.clone()).or_default() += 1;

        // Sleep detection
        if matches!(fn_lower.as_str(), "sleep" | "sleepex" | "ntdelayexecution") {
            let dur_ms = call.args.first().and_then(|a| a.value.as_u64()).unwrap_or(0);
            self.sleep_detector.record_sleep(call.timestamp_ms, dur_ms);
        } else {
            self.sleep_detector.record_action(call.timestamp_ms);
        }

        self.check_debugger_apis(&call, &fn_lower);
        self.check_vm_registry(&call, &fn_lower);

        // Process enumeration for VM process detection
        if matches!(fn_lower.as_str(), "createtoolhelp32snapshot" | "process32first" | "process32next") {
            self.process_name_queries.push(fn_lower.clone());
        }

        self.check_vm_files(&call, &fn_lower);

        // GetSystemTime / QueryPerformanceCounter used for timing
        if matches!(fn_lower.as_str(), "gettickcount" | "gettickcount64" | "queryperformancecounter") {
            self.timing_queries.push((call.timestamp_ms, call.return_value.unwrap_or(0)));
        }

        self.api_trace.push(call);
    }

    /// Feed a CPUID instruction trace.
    pub fn ingest_cpuid(&mut self, trace: CpuidTrace) {
        // Hypervisor bit check
        if trace.leaf == 0x1 && (trace.ecx & (1 << 31)) != 0 {
            let id = self.next_id();
            self.events.push(EvasionEvent {
                id,
                timestamp_ms: now_ms(),
                technique: EvasionTechnique::CpuidHypervisorBit,
                confidence: Confidence::High,
                address: Some(trace.address),
                api_call: Some("CPUID".to_owned()),
                parameters: {
                    let mut p = HashMap::new();
                    p.insert("leaf".to_owned(), format!("0x{:x}", trace.leaf));
                    p.insert("ecx".to_owned(), format!("0x{:x}", trace.ecx));
                    p
                },
                description: "CPUID leaf 1 with hypervisor bit (ECX[31]) set".to_owned(),
            });
        }

        // Hypervisor vendor leaf
        if trace.leaf == 0x4000_0000
            && let Some(vendor) = trace.vendor_string() {
                let is_vm = vm_artifacts::VM_CPUID_VENDORS
                    .iter()
                    .any(|v| vendor.starts_with(v));
                if is_vm {
                    let id = self.next_id();
                    self.events.push(EvasionEvent {
                        id,
                        timestamp_ms: now_ms(),
                        technique: EvasionTechnique::CpuidVendorString,
                        confidence: Confidence::High,
                        address: Some(trace.address),
                        api_call: Some("CPUID".to_owned()),
                        parameters: {
                            let mut p = HashMap::new();
                            p.insert("vendor".to_owned(), vendor);
                            p
                        },
                        description: "CPUID hypervisor vendor string query".to_owned(),
                    });
                }
            }

        self.cpuid_traces.push(trace);
    }

    /// Feed a process name observed via tool-help enumeration.
    pub fn ingest_process_name(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        for &vm_proc in vm_artifacts::VM_PROCESS_NAMES {
            if lower == vm_proc.to_ascii_lowercase() {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: now_ms(),
                    technique: EvasionTechnique::VmProcessCheck,
                    confidence: Confidence::High,
                    address: None,
                    api_call: Some("Process32Next".to_owned()),
                    parameters: {
                        let mut p = HashMap::new();
                        p.insert("process_name".to_owned(), name.to_owned());
                        p
                    },
                    description: format!("VM/analysis process found in process list: {name}"),
                });
            }
        }
    }

    // ── Anti-VM patch detection ───────────────────────────────────────────────

    /// Scan a disassembly byte stream for patterns indicating anti-VM patches.
    pub fn scan_code_for_anti_vm_patches(&mut self, code: &[u8], base_address: u64) {
        // CPUID instruction: 0F A2
        let mut i = 0;
        while i + 1 < code.len() {
            if code[i] == 0x0F && code[i + 1] == 0xA2 {
                // Found CPUID
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: now_ms(),
                    technique: EvasionTechnique::CpuidVendorString,
                    confidence: Confidence::Medium,
                    address: Some(base_address + i as u64),
                    api_call: Some("CPUID".to_owned()),
                    parameters: {
                        let mut p = HashMap::new();
                        p.insert("address".to_owned(), format!("0x{:x}", base_address + i as u64));
                        p
                    },
                    description: "CPUID instruction found in code".to_owned(),
                });
            }
            // RDTSC: 0F 31
            if code[i] == 0x0F && code[i + 1] == 0x31 {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: now_ms(),
                    technique: EvasionTechnique::TimingCheck,
                    confidence: Confidence::Medium,
                    address: Some(base_address + i as u64),
                    api_call: Some("RDTSC".to_owned()),
                    parameters: HashMap::new(),
                    description: "RDTSC timing instruction found — possible timing-based VM detection".to_owned(),
                });
            }
            // INT3: CC (software breakpoint self-check)
            // Sequence: two INT3s close together suggest integrity checking
            if code[i] == 0xCC && i > 0 && code[i - 1] != 0xCC {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: now_ms(),
                    technique: EvasionTechnique::SoftwareBreakpoint,
                    confidence: Confidence::Low,
                    address: Some(base_address + i as u64),
                    api_call: None,
                    parameters: HashMap::new(),
                    description: "Unexpected INT3 in code — may be breakpoint scan residual".to_owned(),
                });
            }
            i += 1;
        }
    }

    /// Detect erased PE header (MZ at load address overwritten).
    pub fn check_pe_header_erasure(&mut self, pe_base: u64, bytes_at_base: &[u8]) {
        if bytes_at_base.len() >= 2 && &bytes_at_base[..2] != b"MZ" {
            let id = self.next_id();
            self.events.push(EvasionEvent {
                id,
                timestamp_ms: now_ms(),
                technique: EvasionTechnique::ErasePeHeader,
                confidence: Confidence::High,
                address: Some(pe_base),
                api_call: None,
                parameters: {
                    let mut p = HashMap::new();
                    p.insert("first_bytes".to_owned(),
                        bytes_at_base[..bytes_at_base.len().min(4)]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" "));
                    p
                },
                description: "PE base address does not contain MZ signature — header likely erased".to_owned(),
            });
        }
    }

    // ── Finalise ──────────────────────────────────────────────────────────────

    /// Run all deferred checks and return complete results.
    pub fn finalize(&mut self) -> EvasionReport {
        // Run sleep-before-action check
        let mut extra_events = Vec::new();
        let mut next_id = self.next_id;
        self.sleep_detector.check_sleep_before_action(&mut extra_events, &mut next_id);
        self.next_id = next_id;
        self.events.extend(extra_events);

        // Timing acceleration: multiple timing queries with very short wall-clock gaps
        if self.timing_queries.len() >= 3 {
            let spans: Vec<u64> = self.timing_queries.windows(2)
                .map(|w| w[1].0.saturating_sub(w[0].0))
                .collect();
            if spans.iter().any(|&s| s < 100) {
                let id = self.next_id();
                self.events.push(EvasionEvent {
                    id,
                    timestamp_ms: now_ms(),
                    technique: EvasionTechnique::TimeAcceleration,
                    confidence: Confidence::Medium,
                    address: None,
                    api_call: Some("QueryPerformanceCounter".to_owned()),
                    parameters: HashMap::new(),
                    description: "Repeated rapid timing queries — checking for time-acceleration sandbox countermeasure".to_owned(),
                });
            }
        }

        // Deduplicate events by technique (keep highest confidence)
        let mut best: HashMap<String, EvasionEvent> = HashMap::new();
        for ev in self.events.drain(..) {
            let key = format!("{}", ev.technique);
            let entry = best.entry(key).or_insert_with(|| ev.clone());
            if ev.confidence > entry.confidence {
                *entry = ev;
            }
        }
        self.events = best.into_values().collect();
        self.events.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        // Build technique summary
        let mut technique_counts: HashMap<String, usize> = HashMap::new();
        for ev in &self.events {
            *technique_counts.entry(format!("{}", ev.technique)).or_default() += 1;
        }

        EvasionReport {
            total_events: self.events.len(),
            events: self.events.clone(),
            techniques_detected: self.events.iter().map(|e| e.technique.clone()).collect(),
            technique_counts,
            high_confidence_count: self.events.iter().filter(|e| e.confidence == Confidence::High).count(),
            cpuid_instruction_count: self.cpuid_traces.len(),
            sleep_total_ms: self.sleep_detector.total_sleep_ms,
            registry_keys_checked: self.registry_accesses.clone(),
            files_checked: self.file_checks.clone(),
            is_vm_aware: self.events.iter().any(|e| matches!(
                e.technique,
                EvasionTechnique::CpuidHypervisorBit | EvasionTechnique::CpuidVendorString |
                EvasionTechnique::VmRegistryKey | EvasionTechnique::VmProcessCheck |
                EvasionTechnique::VmFileCheck
            )),
            is_debugger_aware: self.events.iter().any(|e| matches!(
                e.technique,
                EvasionTechnique::IsDebuggerPresent | EvasionTechnique::CheckRemoteDebugger |
                EvasionTechnique::NtQueryInformationProcess | EvasionTechnique::TimingCheck |
                EvasionTechnique::HardwareBreakpoint | EvasionTechnique::HeapFlags
            )),
            uses_sleep_evasion: self.sleep_detector.total_sleep_ms > 1000,
        }
    }

    #[must_use] 
    pub fn events(&self) -> &[EvasionEvent] {
        &self.events
    }

    #[must_use] 
    pub fn api_trace(&self) -> &[ApiCallRecord] {
        &self.api_trace
    }
}

// ─── Evasion Report ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionReport {
    pub total_events: usize,
    pub events: Vec<EvasionEvent>,
    pub techniques_detected: Vec<EvasionTechnique>,
    pub technique_counts: HashMap<String, usize>,
    pub high_confidence_count: usize,
    pub cpuid_instruction_count: usize,
    pub sleep_total_ms: u64,
    pub registry_keys_checked: Vec<String>,
    pub files_checked: Vec<String>,
    pub is_vm_aware: bool,
    pub is_debugger_aware: bool,
    pub uses_sleep_evasion: bool,
}

impl EvasionReport {
    #[must_use] 
    pub const fn severity(&self) -> EvasionSeverity {
        if self.high_confidence_count >= 5 {
            EvasionSeverity::Critical
        } else if self.high_confidence_count >= 2 {
            EvasionSeverity::High
        } else if self.total_events >= 2 {
            EvasionSeverity::Medium
        } else if self.total_events >= 1 {
            EvasionSeverity::Low
        } else {
            EvasionSeverity::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for EvasionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, ts: Timestamp, args: Vec<ApiArg>) -> ApiCallRecord {
        ApiCallRecord {
            timestamp_ms: ts,
            pid: 1234,
            thread_id: 1,
            return_address: 0x0040_0000,
            function_name: name.to_owned(),
            module: "kernel32".to_owned(),
            args,
            return_value: Some(1),
            call_duration_us: 100,
        }
    }

    #[test]
    fn test_sleep_before_action_detection() {
        let mut det = EvasionDetector::new();
        det.ingest_api_call(make_call("Sleep", 1000, vec![
            ApiArg { name: "dwMilliseconds".to_owned(), value: ApiArgValue::Unsigned(10000) }
        ]));
        det.ingest_api_call(make_call("CreateFileA", 15000, vec![
            ApiArg { name: "lpFileName".to_owned(), value: ApiArgValue::String("C:\\Temp\\file.txt".to_owned()) }
        ]));
        let report = det.finalize();
        assert!(report.uses_sleep_evasion);
        assert!(report.techniques_detected.iter().any(|t| matches!(t, EvasionTechnique::SleepBeforeAction)));
    }

    #[test]
    fn test_debugger_detection_api() {
        let mut det = EvasionDetector::new();
        det.ingest_api_call(make_call("IsDebuggerPresent", 1000, vec![]));
        det.ingest_api_call(make_call("CheckRemoteDebuggerPresent", 2000, vec![]));
        let report = det.finalize();
        assert!(report.is_debugger_aware);
        assert_eq!(report.high_confidence_count, 2);
    }

    #[test]
    fn test_cpuid_hypervisor_bit() {
        let mut det = EvasionDetector::new();
        det.ingest_cpuid(CpuidTrace {
            address: 0x0040_1000,
            leaf: 1,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 1 << 31, // hypervisor bit set
            edx: 0,
        });
        let report = det.finalize();
        assert!(report.is_vm_aware);
    }

    #[test]
    fn test_vm_registry_key_detection() {
        let mut det = EvasionDetector::new();
        det.ingest_api_call(make_call("RegOpenKeyA", 1000, vec![
            ApiArg { name: "hKey".to_owned(), value: ApiArgValue::Unsigned(0x8000_0002) },
            ApiArg { name: "lpSubKey".to_owned(), value: ApiArgValue::String(
                r"SOFTWARE\VMware, Inc.\VMware Tools".to_owned()
            ) },
        ]));
        let report = det.finalize();
        assert!(report.is_vm_aware);
    }

    #[test]
    fn test_pe_header_erasure() {
        let mut det = EvasionDetector::new();
        det.check_pe_header_erasure(0x0040_0000, &[0x00, 0x00, 0x00, 0x00]);
        let report = det.finalize();
        assert!(report.techniques_detected.iter().any(|t| matches!(t, EvasionTechnique::ErasePeHeader)));
    }

    #[test]
    fn test_code_scan_rdtsc() {
        let mut det = EvasionDetector::new();
        let code = &[0x0F, 0x31, 0x90, 0x0F, 0xA2];
        det.scan_code_for_anti_vm_patches(code, 0x0040_1000);
        let report = det.finalize();
        assert!(report.techniques_detected.iter().any(|t| matches!(t, EvasionTechnique::TimingCheck)));
    }

    #[test]
    fn test_severity_levels() {
        let report = EvasionReport {
            total_events: 6,
            events: Vec::new(),
            techniques_detected: Vec::new(),
            technique_counts: HashMap::new(),
            high_confidence_count: 6,
            cpuid_instruction_count: 2,
            sleep_total_ms: 5000,
            registry_keys_checked: Vec::new(),
            files_checked: Vec::new(),
            is_vm_aware: true,
            is_debugger_aware: true,
            uses_sleep_evasion: true,
        };
        assert_eq!(report.severity(), EvasionSeverity::Critical);
    }
}
