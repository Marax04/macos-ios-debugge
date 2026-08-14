//! Sandbox and VM evasion detection: artifact checks, CPUID analysis,
//! timing-based detection, anti-debug techniques, and process enumeration.

pub use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SandboxArtifact ─────────────────────────────────────────────────────────

/// A known sandbox-specific artifact that malware may check for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxArtifact {
    /// The artifact identifier (registry key, filename, process name, etc.).
    pub value: String,
    /// Category of artifact.
    pub category: ArtifactCategory,
    /// Which sandbox product this artifact is associated with.
    pub product: String,
    /// Whether detection of this artifact is critical.
    pub critical: bool,
}

impl SandboxArtifact {
    /// Create a new artifact entry.
    #[must_use]
    pub fn new(
        value: impl Into<String>,
        category: ArtifactCategory,
        product: impl Into<String>,
        critical: bool,
    ) -> Self {
        Self {
            value: value.into(),
            category,
            product: product.into(),
            critical,
        }
    }
}

/// Category of sandbox artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactCategory {
    RegistryKey,
    FilePath,
    ProcessName,
    MacAddress,
    CpuidString,
    Username,
    Hostname,
    ComputerName,
    DiskLabel,
    ServiceName,
    MutexName,
}

impl fmt::Display for ArtifactCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryKey => write!(f, "registry_key"),
            Self::FilePath => write!(f, "file_path"),
            Self::ProcessName => write!(f, "process_name"),
            Self::MacAddress => write!(f, "mac_address"),
            Self::CpuidString => write!(f, "cpuid_string"),
            Self::Username => write!(f, "username"),
            Self::Hostname => write!(f, "hostname"),
            Self::ComputerName => write!(f, "computer_name"),
            Self::DiskLabel => write!(f, "disk_label"),
            Self::ServiceName => write!(f, "service_name"),
            Self::MutexName => write!(f, "mutex_name"),
        }
    }
}

// ─── VmDetection ──────────────────────────────────────────────────────────────

/// Detects virtual machine and sandbox artifacts.
#[derive(Debug, Clone, Default)]
pub struct VmDetection;

/// Result of a VM detection scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetectionResult {
    pub detected: bool,
    pub matched_artifacts: Vec<SandboxArtifact>,
    pub vm_product: Option<String>,
    pub confidence: u8,
    pub cpuid_hypervisor: Option<String>,
}

impl VmDetectionResult {
    /// Returns `true` if confidence is at or above the threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}

impl VmDetection {
    fn vmware_artifacts() -> Vec<SandboxArtifact> {
        vec![
            SandboxArtifact::new(r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools", ArtifactCategory::RegistryKey, "VMware", true),
            SandboxArtifact::new("vmtoolsd.exe", ArtifactCategory::ProcessName, "VMware", true),
            SandboxArtifact::new("vmwaretray.exe", ArtifactCategory::ProcessName, "VMware", false),
            SandboxArtifact::new("00:0C:29", ArtifactCategory::MacAddress, "VMware", true),
            SandboxArtifact::new("00:50:56", ArtifactCategory::MacAddress, "VMware", true),
            SandboxArtifact::new(r"C:\Windows\System32\drivers\vmhgfs.sys", ArtifactCategory::FilePath, "VMware", false),
        ]
    }

    fn virtualbox_artifacts() -> Vec<SandboxArtifact> {
        vec![
            SandboxArtifact::new(r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", ArtifactCategory::RegistryKey, "VirtualBox", true),
            SandboxArtifact::new("vboxservice.exe", ArtifactCategory::ProcessName, "VirtualBox", true),
            SandboxArtifact::new("vboxtray.exe", ArtifactCategory::ProcessName, "VirtualBox", false),
            SandboxArtifact::new("08:00:27", ArtifactCategory::MacAddress, "VirtualBox", true),
            SandboxArtifact::new(r"C:\Windows\System32\drivers\vboxguest.sys", ArtifactCategory::FilePath, "VirtualBox", false),
            SandboxArtifact::new("VBOX HARDDISK", ArtifactCategory::DiskLabel, "VirtualBox", true),
        ]
    }

    fn qemu_hyperv_artifacts() -> Vec<SandboxArtifact> {
        vec![
            SandboxArtifact::new("qemu-ga.exe", ArtifactCategory::ProcessName, "QEMU", true),
            SandboxArtifact::new("52:54:00", ArtifactCategory::MacAddress, "QEMU/KVM", true),
            SandboxArtifact::new("QEMU HARDDISK", ArtifactCategory::DiskLabel, "QEMU", true),
            SandboxArtifact::new(r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\...\Identifier", ArtifactCategory::RegistryKey, "QEMU", false),
            SandboxArtifact::new("vmms.exe", ArtifactCategory::ProcessName, "Hyper-V", true),
            SandboxArtifact::new(r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", ArtifactCategory::RegistryKey, "Hyper-V", true),
            SandboxArtifact::new("00:15:5D", ArtifactCategory::MacAddress, "Hyper-V", true),
        ]
    }

    fn generic_sandbox_artifacts() -> Vec<SandboxArtifact> {
        vec![
            SandboxArtifact::new("analyzer.exe", ArtifactCategory::ProcessName, "Cuckoo", true),
            SandboxArtifact::new("cuckoo", ArtifactCategory::Username, "Cuckoo", true),
            SandboxArtifact::new("SANDBOX", ArtifactCategory::ComputerName, "Generic", false),
            SandboxArtifact::new("MALTEST", ArtifactCategory::ComputerName, "Generic", false),
            SandboxArtifact::new("VIRUS", ArtifactCategory::ComputerName, "Generic", false),
            SandboxArtifact::new("sample", ArtifactCategory::Username, "Generic", false),
            SandboxArtifact::new("xenservice.exe", ArtifactCategory::ProcessName, "Xen", true),
            SandboxArtifact::new(r"HKLM\SOFTWARE\Xen\Xen", ArtifactCategory::RegistryKey, "Xen", true),
            SandboxArtifact::new("prl_tools.exe", ArtifactCategory::ProcessName, "Parallels", true),
            SandboxArtifact::new(r"HKLM\SOFTWARE\Parallels\Coherence", ArtifactCategory::RegistryKey, "Parallels", true),
            SandboxArtifact::new("SbieDll.dll", ArtifactCategory::FilePath, "Sandboxie", true),
            SandboxArtifact::new(r"HKLM\SYSTEM\CurrentControlSet\Services\SandboxieAgent", ArtifactCategory::RegistryKey, "Sandboxie", true),
        ]
    }

    /// Return the built-in artifact database.
    #[must_use]
    pub fn artifact_db() -> Vec<SandboxArtifact> {
        let mut db = Self::vmware_artifacts();
        db.extend(Self::virtualbox_artifacts());
        db.extend(Self::qemu_hyperv_artifacts());
        db.extend(Self::generic_sandbox_artifacts());
        db
    }

    /// Scan a list of strings (registry keys, filenames, process names) for artifacts.
    #[must_use]
    pub fn scan(&self, items: &[&str]) -> VmDetectionResult {
        let db = Self::artifact_db();
        let mut matched = Vec::new();

        for item in items {
            let lower = item.to_ascii_lowercase();
            for artifact in &db {
                if lower.contains(&artifact.value.to_ascii_lowercase()) {
                    matched.push(artifact.clone());
                }
            }
        }

        let detected = !matched.is_empty();
        let vm_product = matched.first().map(|a| a.product.clone());
        let critical_count = matched.iter().filter(|a| a.critical).count();
        let confidence = u8::try_from((matched.len().min(10) * 8 + critical_count.min(5) * 12).min(100)).unwrap_or(u8::MAX);

        VmDetectionResult {
            detected,
            matched_artifacts: matched,
            vm_product,
            confidence,
            cpuid_hypervisor: None,
        }
    }

    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

// ─── CpuidCheck ───────────────────────────────────────────────────────────────

/// Analyzes CPUID-based VM detection patterns.
#[derive(Debug, Clone, Default)]
pub struct CpuidCheck;

/// Result of a CPUID-based hypervisor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidResult {
    /// Whether hypervisor bit (bit 31 of ECX) was set.
    pub hypervisor_present: bool,
    /// Hypervisor vendor string (if any).
    pub vendor_string: Option<String>,
    /// Detected hypervisor product.
    pub hypervisor: Option<HypervisorType>,
}

/// Known hypervisor types detectable via CPUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypervisorType {
    Vmware,
    VirtualBox,
    HyperV,
    Xen,
    Kvm,
    Parallels,
    Bhyve,
    Unknown(String),
}

impl fmt::Display for HypervisorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vmware => write!(f, "VMware"),
            Self::VirtualBox => write!(f, "VirtualBox"),
            Self::HyperV => write!(f, "Hyper-V"),
            Self::Xen => write!(f, "Xen"),
            Self::Kvm => write!(f, "KVM"),
            Self::Parallels => write!(f, "Parallels"),
            Self::Bhyve => write!(f, "bhyve"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

impl CpuidCheck {
    /// Create a new CPUID checker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse a CPUID vendor string from emulated registers.
    /// `vendor` should be the 12-byte string from EBX+EDX+ECX of CPUID leaf 0x40000000.
    #[must_use]
    pub fn analyse_vendor(&self, vendor: &str) -> CpuidResult {
        let hypervisor = match vendor {
            "VMwareVMware" => Some(HypervisorType::Vmware),
            "VBoxVBoxVBox" => Some(HypervisorType::VirtualBox),
            "Microsoft Hv" => Some(HypervisorType::HyperV),
            "XenVMMXenVMM" => Some(HypervisorType::Xen),
            "KVMKVMKVM\0\0\0" | "KVMKVMKVM" => Some(HypervisorType::Kvm),
            " lrpepyh  vr" => Some(HypervisorType::Parallels),
            "bhyve bhyve " => Some(HypervisorType::Bhyve),
            s if !s.is_empty() => Some(HypervisorType::Unknown(s.to_string())),
            _ => None,
        };
        let hypervisor_present = hypervisor.is_some();
        CpuidResult {
            hypervisor_present,
            vendor_string: if vendor.is_empty() {
                None
            } else {
                Some(vendor.to_string())
            },
            hypervisor,
        }
    }

    /// Returns `true` if a CPUID instruction was observed in the API call trace.
    #[must_use]
    pub fn cpuid_in_trace(api_calls: &[&str]) -> bool {
        api_calls
            .iter()
            .any(|c| c.to_ascii_lowercase().contains("cpuid"))
    }
}

// ─── AntiDebug ────────────────────────────────────────────────────────────────

/// Detects anti-debugging techniques in an API call trace.
#[derive(Debug, Clone, Default)]
pub struct AntiDebug;

/// An anti-debugging technique detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugEvidence {
    pub technique: AntiDebugTechnique,
    pub trigger: String,
    pub confidence: u8,
}

/// Known anti-debugging techniques.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AntiDebugTechnique {
    IsDebuggerPresent,
    CheckRemoteDebugger,
    NtQueryInformationProcess,
    DebugObjectQuery,
    CloseHandleException,
    HardwareBreakpoints,
    TimingCheck,
    OutputDebugString,
    SeDebugPrivilege,
    SelfDebugging,
    ParentProcessCheck,
    HeapFlagCheck,
    NtGlobalFlag,
    UnhandledExceptionFilter,
    Other(String),
}

impl fmt::Display for AntiDebugTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsDebuggerPresent => write!(f, "IsDebuggerPresent"),
            Self::CheckRemoteDebugger => write!(f, "CheckRemoteDebuggerPresent"),
            Self::NtQueryInformationProcess => write!(f, "NtQueryInformationProcess"),
            Self::DebugObjectQuery => write!(f, "DebugObjectQuery"),
            Self::CloseHandleException => write!(f, "CloseHandleException"),
            Self::HardwareBreakpoints => write!(f, "HardwareBreakpoints"),
            Self::TimingCheck => write!(f, "TimingCheck"),
            Self::OutputDebugString => write!(f, "OutputDebugStringW"),
            Self::SeDebugPrivilege => write!(f, "SeDebugPrivilege"),
            Self::SelfDebugging => write!(f, "SelfDebugging"),
            Self::ParentProcessCheck => write!(f, "ParentProcessCheck"),
            Self::HeapFlagCheck => write!(f, "HeapFlagCheck"),
            Self::NtGlobalFlag => write!(f, "NtGlobalFlagCheck"),
            Self::UnhandledExceptionFilter => write!(f, "UnhandledExceptionFilter"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl AntiDebug {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan API call names for anti-debug indicators.
    #[must_use]
    pub fn scan(&self, api_calls: &[&str]) -> Vec<AntiDebugEvidence> {
        let patterns: &[(&str, AntiDebugTechnique, u8)] = &[
            (
                "IsDebuggerPresent",
                AntiDebugTechnique::IsDebuggerPresent,
                95,
            ),
            (
                "CheckRemoteDebuggerPresent",
                AntiDebugTechnique::CheckRemoteDebugger,
                95,
            ),
            (
                "NtQueryInformationProcess",
                AntiDebugTechnique::NtQueryInformationProcess,
                80,
            ),
            (
                "ZwQueryInformationProcess",
                AntiDebugTechnique::NtQueryInformationProcess,
                80,
            ),
            ("DebugActiveProcess", AntiDebugTechnique::SelfDebugging, 90),
            (
                "OutputDebugString",
                AntiDebugTechnique::OutputDebugString,
                70,
            ),
            ("GetTickCount", AntiDebugTechnique::TimingCheck, 50),
            (
                "QueryPerformanceCounter",
                AntiDebugTechnique::TimingCheck,
                55,
            ),
            ("rdtsc", AntiDebugTechnique::TimingCheck, 70),
            (
                "NtSetInformationThread",
                AntiDebugTechnique::HardwareBreakpoints,
                75,
            ),
            ("GetContext", AntiDebugTechnique::HardwareBreakpoints, 65),
            (
                "NtCreateDebugObject",
                AntiDebugTechnique::DebugObjectQuery,
                85,
            ),
            ("DbgBreakPoint", AntiDebugTechnique::IsDebuggerPresent, 60),
            ("NtQueryObject", AntiDebugTechnique::DebugObjectQuery, 70),
            (
                "SetUnhandledExceptionFilter",
                AntiDebugTechnique::UnhandledExceptionFilter,
                65,
            ),
        ];

        let mut found = Vec::new();
        for call in api_calls {
            for (pat, tech, confidence) in patterns {
                if call.contains(pat) {
                    found.push(AntiDebugEvidence {
                        technique: tech.clone(),
                        trigger: call.to_string(),
                        confidence: *confidence,
                    });
                }
            }
        }
        found.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        found
    }

    /// Returns `true` if any high-confidence anti-debug technique was detected.
    #[must_use]
    pub fn has_strong_anti_debug(evidence: &[AntiDebugEvidence], threshold: u8) -> bool {
        evidence.iter().any(|e| e.confidence >= threshold)
    }

    /// Return a deduplicated list of detected technique names.
    #[must_use]
    pub fn technique_names(evidence: &[AntiDebugEvidence]) -> Vec<String> {
        let mut names: Vec<String> = evidence.iter().map(|e| e.technique.to_string()).collect();
        names.sort();
        names.dedup();
        names
    }
}

// ─── TimingCheck ──────────────────────────────────────────────────────────────

/// Timing-based sandbox evasion detector.
#[derive(Debug, Clone, Default)]
pub struct TimingCheck;

/// Evidence of timing-based evasion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingEvidence {
    pub technique: TimingTechnique,
    pub sleep_duration_ms: Option<u64>,
    pub confidence: u8,
}

/// Types of timing-based evasion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTechnique {
    LongSleep,
    SpinWait,
    RdtscDelta,
    ExternalTimeServer,
    ScheduledTask,
}

impl fmt::Display for TimingTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LongSleep => write!(f, "long_sleep"),
            Self::SpinWait => write!(f, "spin_wait"),
            Self::RdtscDelta => write!(f, "rdtsc_delta"),
            Self::ExternalTimeServer => write!(f, "external_time_server"),
            Self::ScheduledTask => write!(f, "scheduled_task"),
        }
    }
}

impl TimingCheck {
    /// Create a new checker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect timing evasion in API calls.
    #[must_use]
    pub fn detect(&self, api_calls: &[&str]) -> Vec<TimingEvidence> {
        let mut found = Vec::new();
        for call in api_calls {
            let lower = call.to_ascii_lowercase();
            if lower.contains("sleep")
                || lower.contains("ntdelayexecution")
                || lower.contains("waitforsingleobject")
            {
                found.push(TimingEvidence {
                    technique: TimingTechnique::LongSleep,
                    sleep_duration_ms: None,
                    confidence: 75,
                });
            }
            if lower.contains("rdtsc") || lower.contains("performancecounter") {
                found.push(TimingEvidence {
                    technique: TimingTechnique::RdtscDelta,
                    sleep_duration_ms: None,
                    confidence: 70,
                });
            }
            if lower.contains("timegettime") || lower.contains("gettickcount") {
                found.push(TimingEvidence {
                    technique: TimingTechnique::SpinWait,
                    sleep_duration_ms: None,
                    confidence: 55,
                });
            }
        }
        found
    }

    /// Parse sleep duration from an API call argument string (best-effort).
    #[must_use]
    pub fn parse_sleep_ms(arg: &str) -> Option<u64> {
        arg.trim().parse::<u64>().ok()
    }
}

// ─── ProcessEnumeration ───────────────────────────────────────────────────────

/// Detects sandbox-aware process enumeration.
#[derive(Debug, Clone, Default)]
pub struct ProcessEnumeration;

/// Evidence of process enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerationEvidence {
    pub method: EnumerationMethod,
    pub trigger_api: String,
    pub confidence: u8,
}

/// Method used to enumerate processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnumerationMethod {
    Toolhelp32,
    NtQuerySystemInformation,
    WmiQuery,
    EnumProcesses,
    NetUserEnum,
}

impl fmt::Display for EnumerationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toolhelp32 => write!(f, "CreateToolhelp32Snapshot"),
            Self::NtQuerySystemInformation => write!(f, "NtQuerySystemInformation"),
            Self::WmiQuery => write!(f, "WMI"),
            Self::EnumProcesses => write!(f, "EnumProcesses"),
            Self::NetUserEnum => write!(f, "NetUserEnum"),
        }
    }
}

impl ProcessEnumeration {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect process enumeration in an API call trace.
    #[must_use]
    pub fn detect(&self, api_calls: &[&str]) -> Vec<EnumerationEvidence> {
        let patterns: &[(&str, EnumerationMethod, u8)] = &[
            (
                "CreateToolhelp32Snapshot",
                EnumerationMethod::Toolhelp32,
                85,
            ),
            ("Process32First", EnumerationMethod::Toolhelp32, 85),
            ("Process32Next", EnumerationMethod::Toolhelp32, 80),
            (
                "NtQuerySystemInformation",
                EnumerationMethod::NtQuerySystemInformation,
                80,
            ),
            (
                "ZwQuerySystemInformation",
                EnumerationMethod::NtQuerySystemInformation,
                80,
            ),
            ("EnumProcesses", EnumerationMethod::EnumProcesses, 85),
            ("GetProcessList", EnumerationMethod::EnumProcesses, 75),
            ("Win32_Process", EnumerationMethod::WmiQuery, 80),
            ("NetUserEnum", EnumerationMethod::NetUserEnum, 70),
        ];

        let mut found = Vec::new();
        for call in api_calls {
            for (pat, method, confidence) in patterns {
                if call.contains(pat) {
                    found.push(EnumerationEvidence {
                        method: method.clone(),
                        trigger_api: call.to_string(),
                        confidence: *confidence,
                    });
                }
            }
        }
        found
    }
}

// ─── EvasionDetection ─────────────────────────────────────────────────────────

/// Aggregated evasion detection engine.
#[derive(Debug, Default)]
pub struct EvasionDetection {
    pub vm_detector: VmDetection,
    pub anti_debug: AntiDebug,
    pub timing: TimingCheck,
    pub cpuid: CpuidCheck,
    pub enum_detector: ProcessEnumeration,
}

/// Full evasion detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionAnalysisResult {
    pub vm_result: VmDetectionResult,
    pub anti_debug_evidence: Vec<AntiDebugEvidence>,
    pub timing_evidence: Vec<TimingEvidence>,
    pub cpuid_result: Option<CpuidResult>,
    pub enumeration_evidence: Vec<EnumerationEvidence>,
    pub overall_evasion_score: u8,
    pub techniques: Vec<String>,
}

impl EvasionAnalysisResult {
    /// Returns `true` if significant evasion was detected.
    #[must_use]
    pub const fn is_evasive(&self) -> bool {
        self.overall_evasion_score >= 40
    }
}

impl EvasionDetection {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all detectors on a set of observed artifacts.
    #[must_use]
    pub fn analyze(
        &self,
        observed_items: &[&str],
        api_calls: &[&str],
        cpuid_vendor: Option<&str>,
    ) -> EvasionAnalysisResult {
        let vm_result = self.vm_detector.scan(observed_items);
        let anti_debug_evidence = self.anti_debug.scan(api_calls);
        let timing_evidence = self.timing.detect(api_calls);
        let enumeration_evidence = self.enum_detector.detect(api_calls);
        let cpuid_result = cpuid_vendor.map(|v| self.cpuid.analyse_vendor(v));

        let mut score = 0u8;
        let mut techniques = Vec::new();

        if vm_result.detected {
            score = score.saturating_add(30);
            techniques.push(format!(
                "vm_detected:{}",
                vm_result.vm_product.as_deref().unwrap_or("unknown")
            ));
        }
        if !anti_debug_evidence.is_empty() {
            score = score.saturating_add(25);
            for name in AntiDebug::technique_names(&anti_debug_evidence) {
                techniques.push(format!("anti_debug:{name}"));
            }
        }
        if !timing_evidence.is_empty() {
            score = score.saturating_add(15);
            techniques.push("timing_evasion".to_string());
        }
        if cpuid_result.as_ref().is_some_and(|r| r.hypervisor_present) {
            score = score.saturating_add(20);
            if let Some(ref cr) = cpuid_result
                && let Some(ref hv) = cr.hypervisor
            {
                techniques.push(format!("cpuid_hypervisor:{hv}"));
            }
        }
        if !enumeration_evidence.is_empty() {
            score = score.saturating_add(10);
            techniques.push("process_enumeration".to_string());
        }

        EvasionAnalysisResult {
            vm_result,
            anti_debug_evidence,
            timing_evidence,
            cpuid_result,
            enumeration_evidence,
            overall_evasion_score: score.min(100),
            techniques,
        }
    }

    /// Build a mock result for testing.
    #[must_use]
    pub fn mock_result() -> EvasionAnalysisResult {
        let engine = Self::new();
        let items = ["vmtoolsd.exe", "00:0C:29:aa:bb:cc", "VBOX HARDDISK"];
        let apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "CreateToolhelp32Snapshot",
            "NtDelayExecution",
            "QueryPerformanceCounter",
        ];
        engine.analyze(&items, &apis, Some("VMwareVMware"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SandboxArtifact
    #[test]
    fn test_artifact_new() {
        let a = SandboxArtifact::new(
            "vmtoolsd.exe",
            ArtifactCategory::ProcessName,
            "VMware",
            true,
        );
        assert_eq!(a.product, "VMware");
        assert!(a.critical);
    }
    #[test]
    fn test_artifact_category_display() {
        assert_eq!(ArtifactCategory::ProcessName.to_string(), "process_name");
    }

    // VmDetection
    #[test]
    fn test_vm_detect_vmware() {
        let d = VmDetection::new();
        let r = d.scan(&["vmtoolsd.exe", "00:0C:29:aa:bb:cc"]);
        assert!(r.detected);
        assert!(r.confidence > 0);
    }
    #[test]
    fn test_vm_detect_vbox() {
        let d = VmDetection::new();
        let r = d.scan(&["vboxservice.exe"]);
        assert!(r.detected);
    }
    #[test]
    fn test_vm_detect_nothing() {
        let d = VmDetection::new();
        let r = d.scan(&["notepad.exe", "explorer.exe"]);
        assert!(!r.detected);
    }
    #[test]
    fn test_vm_detect_qemu() {
        let d = VmDetection::new();
        let r = d.scan(&["qemu-ga.exe"]);
        assert!(r.detected);
    }
    #[test]
    fn test_vm_artifact_db_nonempty() {
        let db = VmDetection::artifact_db();
        assert!(db.len() >= 20);
    }
    #[test]
    fn test_vm_result_confident() {
        let d = VmDetection::new();
        let r = d.scan(&["vmtoolsd.exe", "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools"]);
        assert!(r.is_confident(30));
    }
    #[test]
    fn test_vm_detect_sandboxie() {
        let d = VmDetection::new();
        let r = d.scan(&["SbieDll.dll"]);
        assert!(r.detected);
    }

    // CpuidCheck
    #[test]
    fn test_cpuid_vmware() {
        let c = CpuidCheck::new();
        let r = c.analyse_vendor("VMwareVMware");
        assert!(r.hypervisor_present);
        assert_eq!(r.hypervisor, Some(HypervisorType::Vmware));
    }
    #[test]
    fn test_cpuid_vbox() {
        let c = CpuidCheck::new();
        let r = c.analyse_vendor("VBoxVBoxVBox");
        assert_eq!(r.hypervisor, Some(HypervisorType::VirtualBox));
    }
    #[test]
    fn test_cpuid_kvm() {
        let c = CpuidCheck::new();
        let r = c.analyse_vendor("KVMKVMKVM");
        assert_eq!(r.hypervisor, Some(HypervisorType::Kvm));
    }
    #[test]
    fn test_cpuid_empty_string() {
        let c = CpuidCheck::new();
        let r = c.analyse_vendor("");
        assert!(!r.hypervisor_present);
    }
    #[test]
    fn test_cpuid_in_trace() {
        assert!(CpuidCheck::cpuid_in_trace(&["CPUID leaf 40000000"]));
    }
    #[test]
    fn test_cpuid_not_in_trace() {
        assert!(!CpuidCheck::cpuid_in_trace(&["CreateFile"]));
    }
    #[test]
    fn test_hypervisor_display() {
        assert_eq!(HypervisorType::Vmware.to_string(), "VMware");
    }

    // AntiDebug
    #[test]
    fn test_anti_debug_is_debugger_present() {
        let d = AntiDebug::new();
        let ev = d.scan(&["IsDebuggerPresent"]);
        assert!(!ev.is_empty());
        assert_eq!(ev[0].technique, AntiDebugTechnique::IsDebuggerPresent);
    }
    #[test]
    fn test_anti_debug_nt_query() {
        let d = AntiDebug::new();
        let ev = d.scan(&["NtQueryInformationProcess"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_anti_debug_none() {
        let d = AntiDebug::new();
        let ev = d.scan(&["CreateFile"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_anti_debug_has_strong() {
        let d = AntiDebug::new();
        let ev = d.scan(&["IsDebuggerPresent"]);
        assert!(AntiDebug::has_strong_anti_debug(&ev, 80));
    }
    #[test]
    fn test_anti_debug_technique_names() {
        let d = AntiDebug::new();
        let ev = d.scan(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]);
        let names = AntiDebug::technique_names(&ev);
        assert!(names.len() >= 2);
    }
    #[test]
    fn test_anti_debug_technique_display() {
        assert_eq!(
            AntiDebugTechnique::IsDebuggerPresent.to_string(),
            "IsDebuggerPresent"
        );
    }

    // TimingCheck
    #[test]
    fn test_timing_sleep() {
        let t = TimingCheck::new();
        let ev = t.detect(&["NtDelayExecution"]);
        assert!(!ev.is_empty());
        assert_eq!(ev[0].technique, TimingTechnique::LongSleep);
    }
    #[test]
    fn test_timing_rdtsc() {
        let t = TimingCheck::new();
        let ev = t.detect(&["rdtsc instruction"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_timing_none() {
        let t = TimingCheck::new();
        let ev = t.detect(&["CreateFile"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_timing_parse_sleep_ms() {
        assert_eq!(TimingCheck::parse_sleep_ms("5000"), Some(5000));
    }
    #[test]
    fn test_timing_parse_bad() {
        assert_eq!(TimingCheck::parse_sleep_ms("abc"), None);
    }
    #[test]
    fn test_timing_display() {
        assert_eq!(TimingTechnique::LongSleep.to_string(), "long_sleep");
    }

    // ProcessEnumeration
    #[test]
    fn test_enum_toolhelp32() {
        let e = ProcessEnumeration::new();
        let ev = e.detect(&["CreateToolhelp32Snapshot", "Process32First"]);
        assert!(ev.iter().any(|e| e.method == EnumerationMethod::Toolhelp32));
    }
    #[test]
    fn test_enum_nt_query_system() {
        let e = ProcessEnumeration::new();
        let ev = e.detect(&["NtQuerySystemInformation"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_enum_none() {
        let e = ProcessEnumeration::new();
        let ev = e.detect(&["ReadFile"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_enum_method_display() {
        assert_eq!(
            EnumerationMethod::Toolhelp32.to_string(),
            "CreateToolhelp32Snapshot"
        );
    }

    // EvasionDetection
    #[test]
    fn test_evasion_new() {
        let _ = EvasionDetection::new();
    }
    #[test]
    fn test_evasion_mock_is_evasive() {
        let r = EvasionDetection::mock_result();
        assert!(r.is_evasive());
    }
    #[test]
    fn test_evasion_mock_has_techniques() {
        let r = EvasionDetection::mock_result();
        assert!(!r.techniques.is_empty());
    }
    #[test]
    fn test_evasion_no_artifacts() {
        let e = EvasionDetection::new();
        let r = e.analyze(&[], &[], None);
        assert_eq!(r.overall_evasion_score, 0);
        assert!(!r.is_evasive());
    }
    #[test]
    fn test_evasion_cpuid_counted() {
        let e = EvasionDetection::new();
        let r = e.analyze(&[], &[], Some("VMwareVMware"));
        assert!(r.overall_evasion_score > 0);
    }
    #[test]
    fn test_evasion_score_capped_at_100() {
        let r = EvasionDetection::mock_result();
        assert!(r.overall_evasion_score <= 100);
    }
    #[test]
    fn test_vm_result_has_product() {
        let r = EvasionDetection::mock_result();
        assert!(r.vm_result.vm_product.is_some());
    }
}
