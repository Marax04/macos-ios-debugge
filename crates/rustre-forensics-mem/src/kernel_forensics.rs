//! Kernel-level memory forensics: driver analysis, hidden modules, malicious
//! callbacks, notify routines, filter drivers, and SSDT hook detection.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// --- DriverAnalysis -----------------------------------------------------------

/// Packed boolean flags for [`DriverAnalysis`] stored as a bitmask.
///
/// Bit layout: `0x01` = signed, `0x02` = hidden, `0x04` = suspicious path, `0x08` = known good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DriverFlags(pub u8);

impl DriverFlags {
    const SIGNED: u8 = 0x01;
    const HIDDEN: u8 = 0x02;
    const SUSPICIOUS: u8 = 0x04;
    const KNOWN_GOOD: u8 = 0x08;

    /// `true` if the driver is signed.
    #[must_use]
    pub const fn is_signed(self) -> bool { self.0 & Self::SIGNED != 0 }
    /// `true` if the driver is hidden from normal enumeration.
    #[must_use]
    pub const fn is_hidden(self) -> bool { self.0 & Self::HIDDEN != 0 }
    /// `true` if the driver loads from a suspicious path.
    #[must_use]
    pub const fn suspicious_path(self) -> bool { self.0 & Self::SUSPICIOUS != 0 }
    /// `true` if the driver is in the known-good hash database.
    #[must_use]
    pub const fn known_good(self) -> bool { self.0 & Self::KNOWN_GOOD != 0 }
    /// Mark the driver as signed.
    pub const fn set_signed(&mut self) { self.0 |= Self::SIGNED; }
    /// Mark the driver as hidden.
    pub const fn set_hidden(&mut self) { self.0 |= Self::HIDDEN; }
    /// Mark the driver as loading from a suspicious path.
    pub const fn set_suspicious_path(&mut self) { self.0 |= Self::SUSPICIOUS; }
    /// Mark the driver as known-good.
    pub const fn set_known_good(&mut self) { self.0 |= Self::KNOWN_GOOD; }
}

/// Information about a loaded kernel driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverAnalysis {
    /// Driver name (e.g. "tcpip.sys").
    pub name: String,
    /// Load address in kernel space.
    pub base_address: u64,
    /// Size of the driver in memory.
    pub size: u64,
    /// Full path on disk.
    pub image_path: String,
    /// Driver boolean flags (signed, hidden, suspicious path, known-good).
    pub flags: DriverFlags,
    /// Entropy of the driver image.
    pub entropy: f64,
    /// IRQL at which the driver operates.
    pub irql: u8,
    /// Tags for analysis notes.
    pub tags: Vec<String>,
}

impl DriverAnalysis {
    /// Create a new driver analysis entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        base_address: u64,
        size: u64,
        image_path: impl Into<String>,
    ) -> Self {
        let image_path_str: String = image_path.into();
        let mut flags = DriverFlags::default();
        if is_suspicious_driver_path(&image_path_str) {
            flags.set_suspicious_path();
        }
        Self {
            name: name.into(),
            base_address,
            size,
            image_path: image_path_str,
            flags,
            entropy: 0.0,
            irql: 0,
            tags: vec![],
        }
    }

    /// Returns `true` if this driver warrants further investigation.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.flags.is_hidden()
            || self.flags.suspicious_path()
            || (!self.flags.is_signed() && !self.flags.known_good())
            || self.entropy > 7.2
    }

    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }
}

fn is_suspicious_driver_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("\\windows\\debug\\")
}

// --- HiddenModule -------------------------------------------------------------

/// A kernel module that is hidden from standard enumeration APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenModule {
    /// Base address of the module.
    pub base_address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Detected name (may be empty if fully stealthed).
    pub name: String,
    /// Detection method.
    pub detection_method: HidingDetectionMethod,
    /// Confidence of detection (0�100).
    pub confidence: u8,
}

/// Method used to detect a hidden module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HidingDetectionMethod {
    /// Discrepancy between `PsLoadedModuleList` and physical scan.
    PsLoadedModuleListMismatch,
    /// Object type mismatch in handle table.
    HandleTableMismatch,
    /// Signature match in memory without corresponding module entry.
    MemorySignatureMatch,
    /// DKOM (Direct Kernel Object Manipulation) detected.
    DkomDetected,
    /// IDT/SSDT reference without corresponding loaded module.
    UnaccountedCodeReference,
}

impl fmt::Display for HidingDetectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PsLoadedModuleListMismatch => write!(f, "ps_loaded_module_list_mismatch"),
            Self::HandleTableMismatch => write!(f, "handle_table_mismatch"),
            Self::MemorySignatureMatch => write!(f, "memory_signature_match"),
            Self::DkomDetected => write!(f, "dkom_detected"),
            Self::UnaccountedCodeReference => write!(f, "unaccounted_code_reference"),
        }
    }
}

impl HiddenModule {
    /// Create a new hidden module record.
    #[must_use]
    pub fn new(
        base_address: u64,
        size: u64,
        name: impl Into<String>,
        method: HidingDetectionMethod,
        confidence: u8,
    ) -> Self {
        Self {
            base_address,
            size,
            name: name.into(),
            detection_method: method,
            confidence: confidence.min(100),
        }
    }
}

// --- MaliciousCallback --------------------------------------------------------

/// A malicious kernel callback registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousCallback {
    pub callback_type: CallbackType,
    pub address: u64,
    pub module_name: String,
    pub is_outside_known_module: bool,
    pub confidence: u8,
}

/// Known Windows kernel callback types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackType {
    PsSetCreateProcessNotifyRoutine,
    PsSetCreateThreadNotifyRoutine,
    PsSetLoadImageNotifyRoutine,
    CmRegisterCallback,
    ObRegisterCallbacks,
    IoRegisterFsRegistrationChange,
    KeRegisterBugCheckCallback,
    KeBugCheckEx,
    WfpCallout,
}

impl fmt::Display for CallbackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PsSetCreateProcessNotifyRoutine => write!(f, "PsSetCreateProcessNotifyRoutine"),
            Self::PsSetCreateThreadNotifyRoutine => write!(f, "PsSetCreateThreadNotifyRoutine"),
            Self::PsSetLoadImageNotifyRoutine => write!(f, "PsSetLoadImageNotifyRoutine"),
            Self::CmRegisterCallback => write!(f, "CmRegisterCallback"),
            Self::ObRegisterCallbacks => write!(f, "ObRegisterCallbacks"),
            Self::IoRegisterFsRegistrationChange => write!(f, "IoRegisterFsRegistrationChange"),
            Self::KeRegisterBugCheckCallback => write!(f, "KeRegisterBugCheckCallback"),
            Self::KeBugCheckEx => write!(f, "KeBugCheckEx"),
            Self::WfpCallout => write!(f, "WfpCallout"),
        }
    }
}

impl MaliciousCallback {
    /// Create a new malicious callback record.
    #[must_use]
    pub fn new(
        callback_type: CallbackType,
        address: u64,
        module_name: impl Into<String>,
        is_outside_known_module: bool,
    ) -> Self {
        let confidence = if is_outside_known_module { 90 } else { 60 };
        Self {
            callback_type,
            address,
            module_name: module_name.into(),
            is_outside_known_module,
            confidence,
        }
    }
}

// --- NotifyRoutine ------------------------------------------------------------

/// A kernel notify routine (process/thread/image load).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyRoutine {
    pub routine_type: NotifyType,
    pub address: u64,
    pub owning_module: String,
    pub is_legitimate: bool,
}

/// Type of notify routine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotifyType {
    ProcessCreate,
    ProcessDelete,
    ThreadCreate,
    ThreadDelete,
    ImageLoad,
    RegistryOperation,
}

impl fmt::Display for NotifyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessCreate => write!(f, "process_create"),
            Self::ProcessDelete => write!(f, "process_delete"),
            Self::ThreadCreate => write!(f, "thread_create"),
            Self::ThreadDelete => write!(f, "thread_delete"),
            Self::ImageLoad => write!(f, "image_load"),
            Self::RegistryOperation => write!(f, "registry_operation"),
        }
    }
}

impl NotifyRoutine {
    /// Create a new notify routine entry.
    #[must_use]
    pub fn new(
        routine_type: NotifyType,
        address: u64,
        owning_module: impl Into<String>,
        is_legitimate: bool,
    ) -> Self {
        Self {
            routine_type,
            address,
            owning_module: owning_module.into(),
            is_legitimate,
        }
    }

    /// Returns `true` if this routine is suspicious.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.is_legitimate
    }
}

// --- FilterDriver -------------------------------------------------------------

/// A registered file system or minifilter driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterDriver {
    pub name: String,
    pub altitude: String,
    pub frame: u32,
    pub flags: u32,
    pub is_known: bool,
    pub suspicious: bool,
}

impl FilterDriver {
    /// Create a new filter driver entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        altitude: impl Into<String>,
        frame: u32,
        is_known: bool,
    ) -> Self {
        Self {
            name: name.into(),
            altitude: altitude.into(),
            frame,
            flags: 0,
            is_known,
            suspicious: !is_known,
        }
    }

    /// Returns `true` if this filter is at an unusually low altitude (rootkit-like).
    #[must_use]
    pub fn is_low_altitude(&self) -> bool {
        self.altitude.parse::<u32>().is_ok_and(|a| a < 20000)
    }
}

// --- SsdtHook ----------------------------------------------------------------

/// A System Service Descriptor Table hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsdtHook {
    /// System call index.
    pub syscall_index: u16,
    /// Expected (original) function address.
    pub expected_address: u64,
    /// Actual (hooked) function address.
    pub actual_address: u64,
    /// The name of the hooked system call.
    pub syscall_name: String,
    /// Module containing the hook target.
    pub hook_module: String,
    /// Confidence score (0�100).
    pub confidence: u8,
}

impl SsdtHook {
    /// Create a new SSDT hook record.
    #[must_use]
    pub fn new(
        syscall_index: u16,
        expected: u64,
        actual: u64,
        syscall_name: impl Into<String>,
        hook_module: impl Into<String>,
    ) -> Self {
        let confidence = if expected == actual { 0 } else { 95 };
        Self {
            syscall_index,
            expected_address: expected,
            actual_address: actual,
            syscall_name: syscall_name.into(),
            hook_module: hook_module.into(),
            confidence,
        }
    }

    /// Returns `true` if the SSDT entry is hooked (addresses differ).
    #[must_use]
    pub const fn is_hooked(&self) -> bool {
        self.expected_address != self.actual_address
    }

    /// Returns the hook displacement (offset from expected).
    #[must_use]
    pub const fn displacement(&self) -> i64 {
        self.actual_address.cast_signed() - self.expected_address.cast_signed()
    }
}

// --- KernelForensics ----------------------------------------------------------

/// Aggregated kernel forensics analysis.
pub struct KernelForensics {
    pub drivers: Vec<DriverAnalysis>,
    pub hidden_modules: Vec<HiddenModule>,
    pub malicious_callbacks: Vec<MaliciousCallback>,
    pub notify_routines: Vec<NotifyRoutine>,
    pub filter_drivers: Vec<FilterDriver>,
    pub ssdt_hooks: Vec<SsdtHook>,
}

/// Summary of kernel forensics findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelForensicsReport {
    pub total_drivers: usize,
    pub suspicious_drivers: usize,
    pub hidden_modules: usize,
    pub malicious_callbacks: usize,
    pub suspicious_notify_routines: usize,
    pub unknown_filter_drivers: usize,
    pub ssdt_hooks: usize,
    pub overall_risk_score: u8,
    pub findings: Vec<String>,
}

impl KernelForensics {
    /// Create an empty analysis structure.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            drivers: vec![],
            hidden_modules: vec![],
            malicious_callbacks: vec![],
            notify_routines: vec![],
            filter_drivers: vec![],
            ssdt_hooks: vec![],
        }
    }

    /// Add a driver.
    pub fn add_driver(&mut self, d: DriverAnalysis) {
        self.drivers.push(d);
    }
    /// Add a hidden module.
    pub fn add_hidden_module(&mut self, m: HiddenModule) {
        self.hidden_modules.push(m);
    }
    /// Add a malicious callback.
    pub fn add_callback(&mut self, c: MaliciousCallback) {
        self.malicious_callbacks.push(c);
    }
    /// Add a notify routine.
    pub fn add_notify(&mut self, n: NotifyRoutine) {
        self.notify_routines.push(n);
    }
    /// Add a filter driver.
    pub fn add_filter(&mut self, f: FilterDriver) {
        self.filter_drivers.push(f);
    }
    /// Add an SSDT hook.
    pub fn add_ssdt_hook(&mut self, h: SsdtHook) {
        self.ssdt_hooks.push(h);
    }

    /// Compute a risk score and generate a report.
    #[must_use]
    pub fn report(&self) -> KernelForensicsReport {
        let suspicious_drivers = self.drivers.iter().filter(|d| d.is_suspicious()).count();
        let suspicious_notifies = self
            .notify_routines
            .iter()
            .filter(|n| n.is_suspicious())
            .count();
        let unknown_filters = self.filter_drivers.iter().filter(|f| f.suspicious).count();

        let mut score = 0u8;
        let mut findings = Vec::new();

        if !self.hidden_modules.is_empty() {
            score = score.saturating_add(30);
            findings.push(format!(
                "{} hidden kernel module(s) detected",
                self.hidden_modules.len()
            ));
        }
        if !self.ssdt_hooks.iter().all(|h| !h.is_hooked()) {
            let hooked = self.ssdt_hooks.iter().filter(|h| h.is_hooked()).count();
            if hooked > 0 {
                score = score.saturating_add(25);
                findings.push(format!("{hooked} SSDT hook(s) detected"));
            }
        }
        if !self.malicious_callbacks.is_empty() {
            score = score.saturating_add(20);
            findings.push(format!(
                "{} malicious callback(s)",
                self.malicious_callbacks.len()
            ));
        }
        if suspicious_drivers > 0 {
            score = score.saturating_add(15);
            findings.push(format!("{suspicious_drivers} suspicious driver(s)"));
        }
        if suspicious_notifies > 0 {
            score = score.saturating_add(10);
            findings.push(format!(
                "{suspicious_notifies} suspicious notify routine(s)"
            ));
        }
        if unknown_filters > 0 {
            findings.push(format!("{unknown_filters} unknown minifilter driver(s)"));
        }

        KernelForensicsReport {
            total_drivers: self.drivers.len(),
            suspicious_drivers,
            hidden_modules: self.hidden_modules.len(),
            malicious_callbacks: self.malicious_callbacks.len(),
            suspicious_notify_routines: suspicious_notifies,
            unknown_filter_drivers: unknown_filters,
            ssdt_hooks: self.ssdt_hooks.iter().filter(|h| h.is_hooked()).count(),
            overall_risk_score: score.min(100),
            findings,
        }
    }

    /// Build a mock instance for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut kf = Self::new();

        let mut legit_driver = DriverAnalysis::new(
            "tcpip.sys",
            0xFFFF_F803_0000_0000,
            0x8_0000,
            r"C:\Windows\System32\drivers\tcpip.sys",
        );
        legit_driver.flags.set_signed();
        legit_driver.flags.set_known_good();
        kf.add_driver(legit_driver);

        let mut rootkit = DriverAnalysis::new(
            "rootkit.sys",
            0xFFFF_F803_1000_0000,
            0x5000,
            r"C:\Windows\Temp\rootkit.sys",
        );
        rootkit.flags.set_hidden();
        rootkit.entropy = 7.5;
        kf.add_driver(rootkit);

        kf.add_hidden_module(HiddenModule::new(
            0xFFFF_F803_2000_0000,
            0x3000,
            "hidden_rootkit",
            HidingDetectionMethod::PsLoadedModuleListMismatch,
            90,
        ));

        kf.add_callback(MaliciousCallback::new(
            CallbackType::PsSetCreateProcessNotifyRoutine,
            0xFFFF_F803_1000_1000,
            "rootkit.sys",
            true,
        ));

        kf.add_notify(NotifyRoutine::new(
            NotifyType::ImageLoad,
            0xFFFF_F803_1000_2000,
            "rootkit.sys",
            false,
        ));

        kf.add_filter(FilterDriver::new("EvilFilter", "10000", 0, false));

        kf.add_ssdt_hook(SsdtHook::new(
            0x0025,
            0xFFFF_F803_0400_1000,
            0xFFFF_F803_1000_3000,
            "NtOpenProcess",
            "rootkit.sys",
        ));

        kf
    }
}

impl Default for KernelForensics {
    fn default() -> Self {
        Self::new()
    }
}

// --- SsdtAnalyzer -------------------------------------------------------------

/// Analyzes the SSDT for hooks by comparing expected and actual function addresses.
#[derive(Debug, Clone, Default)]
pub struct SsdtAnalyzer {
    /// Known syscall names indexed by syscall number.
    pub syscall_names: HashMap<u16, &'static str>,
}

impl SsdtAnalyzer {
    /// Create an analyzer with a partial list of well-known NT syscalls.
    #[must_use]
    pub fn new() -> Self {
        let mut names = HashMap::new();
        // A subset of NT x64 syscall numbers (Windows 10 20H2).
        let table: &[(u16, &str)] = &[
            (0x0000, "NtAccessCheck"),
            (0x0001, "NtWorkerFactoryWorkerReady"),
            (0x0002, "NtAcceptConnectPort"),
            (0x0004, "NtAllocateVirtualMemory"),
            (0x0005, "NtAlpcConnectPort"),
            (0x000C, "NtAssignProcessToJobObject"),
            (0x000F, "NtCallbackReturn"),
            (0x0012, "NtClose"),
            (0x0014, "NtConnectPort"),
            (0x0018, "NtCreateEvent"),
            (0x001C, "NtCreateFile"),
            (0x001D, "NtCreateIoCompletion"),
            (0x0022, "NtCreateMutant"),
            (0x0025, "NtOpenProcess"),
            (0x0026, "NtCreateProcessEx"),
            (0x0029, "NtCreateSection"),
            (0x002A, "NtCreateSemaphore"),
            (0x002B, "NtCreateSymbolicLinkObject"),
            (0x002C, "NtCreateThread"),
            (0x002D, "NtCreateThreadEx"),
            (0x002E, "NtCreateTimer"),
            (0x002F, "NtCreateToken"),
            (0x0031, "NtCreateUserProcess"),
            (0x0055, "NtLoadDriver"),
            (0x0057, "NtMakeTemporaryObject"),
            (0x005A, "NtMapViewOfSection"),
            (0x0065, "NtNotifyChangeDirectoryFile"),
            (0x0077, "NtOpenFile"),
            (0x007B, "NtOpenKey"),
            (0x0088, "NtOpenSection"),
            (0x008A, "NtOpenThread"),
            (0x00B7, "NtQueryInformationProcess"),
            (0x00C1, "NtQuerySystemInformation"),
            (0x00D5, "NtReadFile"),
            (0x00D6, "NtReadVirtualMemory"),
            (0x00D7, "NtRegisterThreadTerminatePort"),
            (0x0102, "NtSetInformationFile"),
            (0x010B, "NtSetInformationToken"),
            (0x0115, "NtSetValueKey"),
            (0x012C, "NtTerminateProcess"),
            (0x012D, "NtTerminateThread"),
            (0x0145, "NtWriteFile"),
            (0x0149, "NtWriteVirtualMemory"),
            (0x014E, "NtCreateMailslotFile"),
        ];
        for (idx, name) in table {
            names.insert(*idx, *name);
        }
        Self {
            syscall_names: names,
        }
    }

    /// Check if a given syscall index is hooked.
    #[must_use]
    pub fn check_hook(&self, index: u16, expected: u64, actual: u64) -> Option<SsdtHook> {
        if expected == actual {
            return None;
        }
        let name = self.syscall_names.get(&index).copied().unwrap_or("Unknown");
        Some(SsdtHook::new(
            index,
            expected,
            actual,
            name,
            "unknown_module",
        ))
    }

    /// Scan a set of (index, expected, actual) tuples for hooks.
    #[must_use]
    pub fn scan_entries(&self, entries: &[(u16, u64, u64)]) -> Vec<SsdtHook> {
        entries
            .iter()
            .filter_map(|(idx, exp, act)| self.check_hook(*idx, *exp, *act))
            .collect()
    }

    /// Returns a syscall name by index.
    #[must_use]
    pub fn name_for(&self, index: u16) -> &str {
        self.syscall_names.get(&index).copied().unwrap_or("Unknown")
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> KernelForensics {
        KernelForensics::mock()
    }

    // DriverAnalysis
    #[test]
    fn test_driver_new() {
        let d = DriverAnalysis::new(
            "test.sys",
            0xFFFF_F000_0000_0000,
            0x5000,
            r"C:\Windows\System32\drivers\test.sys",
        );
        assert_eq!(d.name, "test.sys");
        assert!(!d.flags.suspicious_path());
    }
    #[test]
    fn test_driver_suspicious_path() {
        let d = DriverAnalysis::new("evil.sys", 0, 0, r"C:\Windows\Temp\evil.sys");
        assert!(d.flags.suspicious_path());
    }
    #[test]
    fn test_driver_is_suspicious_hidden() {
        let mut d = DriverAnalysis::new("x.sys", 0, 0, r"C:\Windows\System32\drivers\x.sys");
        d.flags.set_hidden();
        assert!(d.is_suspicious());
    }
    #[test]
    fn test_driver_known_good_not_suspicious() {
        let mut d = DriverAnalysis::new("x.sys", 0, 0, r"C:\Windows\System32\drivers\x.sys");
        d.flags.set_signed();
        d.flags.set_known_good();
        assert!(!d.is_suspicious());
    }
    #[test]
    fn test_driver_high_entropy_suspicious() {
        let mut d = DriverAnalysis::new("x.sys", 0, 0, r"C:\Windows\System32\drivers\x.sys");
        d.flags.set_signed();
        d.flags.set_known_good();
        d.entropy = 7.5;
        assert!(d.is_suspicious());
    }
    #[test]
    fn test_driver_tag() {
        let mut d = DriverAnalysis::new("x.sys", 0, 0, "path");
        d.tag("rootkit");
        assert!(d.tags.contains(&"rootkit".to_string()));
    }

    // HiddenModule
    #[test]
    fn test_hidden_module_new() {
        let m = HiddenModule::new(
            0xFFFF_0000_0000,
            0x3000,
            "evil",
            HidingDetectionMethod::DkomDetected,
            90,
        );
        assert_eq!(m.confidence, 90);
    }
    #[test]
    fn test_hiding_method_display() {
        assert_eq!(
            HidingDetectionMethod::DkomDetected.to_string(),
            "dkom_detected"
        );
    }
    #[test]
    fn test_hidden_module_confidence_capped() {
        let m = HiddenModule::new(0, 0, "", HidingDetectionMethod::MemorySignatureMatch, 150);
        assert_eq!(m.confidence, 100);
    }

    // MaliciousCallback
    #[test]
    fn test_callback_new_outside_module() {
        let c = MaliciousCallback::new(
            CallbackType::PsSetCreateProcessNotifyRoutine,
            0x1000,
            "evil.sys",
            true,
        );
        assert_eq!(c.confidence, 90);
    }
    #[test]
    fn test_callback_new_inside_module() {
        let c = MaliciousCallback::new(
            CallbackType::PsSetLoadImageNotifyRoutine,
            0x1000,
            "some.sys",
            false,
        );
        assert_eq!(c.confidence, 60);
    }
    #[test]
    fn test_callback_type_display() {
        assert_eq!(
            CallbackType::PsSetCreateProcessNotifyRoutine.to_string(),
            "PsSetCreateProcessNotifyRoutine"
        );
    }

    // NotifyRoutine
    #[test]
    fn test_notify_legitimate() {
        let n = NotifyRoutine::new(NotifyType::ProcessCreate, 0x1000, "legit.sys", true);
        assert!(!n.is_suspicious());
    }
    #[test]
    fn test_notify_illegitimate() {
        let n = NotifyRoutine::new(NotifyType::ImageLoad, 0x1000, "evil.sys", false);
        assert!(n.is_suspicious());
    }
    #[test]
    fn test_notify_type_display() {
        assert_eq!(NotifyType::ProcessCreate.to_string(), "process_create");
    }

    // FilterDriver
    #[test]
    fn test_filter_known() {
        let f = FilterDriver::new("WdFilter", "320000", 0, true);
        assert!(!f.suspicious);
    }
    #[test]
    fn test_filter_unknown() {
        let f = FilterDriver::new("EvilFilter", "10000", 0, false);
        assert!(f.suspicious);
    }
    #[test]
    fn test_filter_low_altitude() {
        let f = FilterDriver::new("LowFilter", "10000", 0, false);
        assert!(f.is_low_altitude());
    }
    #[test]
    fn test_filter_normal_altitude() {
        let f = FilterDriver::new("NormalFilter", "320000", 0, true);
        assert!(!f.is_low_altitude());
    }

    // SsdtHook
    #[test]
    fn test_ssdt_hook_is_hooked() {
        let h = SsdtHook::new(0x25, 0x1000, 0x2000, "NtOpenProcess", "evil.sys");
        assert!(h.is_hooked());
    }
    #[test]
    fn test_ssdt_hook_not_hooked() {
        let h = SsdtHook::new(0x25, 0x1000, 0x1000, "NtOpenProcess", "ntoskrnl.exe");
        assert!(!h.is_hooked());
        assert_eq!(h.confidence, 0);
    }
    #[test]
    fn test_ssdt_hook_displacement() {
        let h = SsdtHook::new(0x25, 0x1000, 0x3000, "NtOpenProcess", "evil.sys");
        assert_eq!(h.displacement(), 0x2000);
    }
    #[test]
    fn test_ssdt_hook_high_confidence() {
        let h = SsdtHook::new(0x25, 0x1000, 0x2000, "NtOpenProcess", "evil.sys");
        assert_eq!(h.confidence, 95);
    }

    // KernelForensics
    #[test]
    fn test_kf_mock_has_drivers() {
        let kf = mock();
        assert!(kf.drivers.len() >= 2);
    }
    #[test]
    fn test_kf_mock_has_hidden() {
        let kf = mock();
        assert!(!kf.hidden_modules.is_empty());
    }
    #[test]
    fn test_kf_mock_has_ssdt_hook() {
        let kf = mock();
        assert!(kf.ssdt_hooks.iter().any(super::SsdtHook::is_hooked));
    }
    #[test]
    fn test_kf_report_risk_score_positive() {
        let kf = mock();
        let report = kf.report();
        assert!(report.overall_risk_score > 0);
    }
    #[test]
    fn test_kf_report_findings_nonempty() {
        let kf = mock();
        let report = kf.report();
        assert!(!report.findings.is_empty());
    }
    #[test]
    fn test_kf_report_suspicious_drivers_count() {
        let kf = mock();
        let report = kf.report();
        assert!(report.suspicious_drivers >= 1);
    }
    #[test]
    fn test_kf_new_empty() {
        let kf = KernelForensics::new();
        let r = kf.report();
        assert_eq!(r.overall_risk_score, 0);
        assert_eq!(r.total_drivers, 0);
    }

    // SsdtAnalyzer
    #[test]
    fn test_ssdt_analyzer_new() {
        let a = SsdtAnalyzer::new();
        assert!(!a.syscall_names.is_empty());
    }
    #[test]
    fn test_ssdt_analyzer_check_hook_hooked() {
        let a = SsdtAnalyzer::new();
        let h = a.check_hook(0x0025, 0x1000, 0x2000);
        assert!(h.is_some());
        assert_eq!(h.unwrap().syscall_name, "NtOpenProcess");
    }
    #[test]
    fn test_ssdt_analyzer_check_hook_not_hooked() {
        let a = SsdtAnalyzer::new();
        let h = a.check_hook(0x0025, 0x1000, 0x1000);
        assert!(h.is_none());
    }
    #[test]
    fn test_ssdt_analyzer_scan_entries() {
        let a = SsdtAnalyzer::new();
        let entries = vec![(0x0025u16, 0x1000u64, 0x2000u64), (0x0012, 0x3000, 0x3000)];
        let hooks = a.scan_entries(&entries);
        assert_eq!(hooks.len(), 1);
    }
    #[test]
    fn test_ssdt_analyzer_name_for_known() {
        let a = SsdtAnalyzer::new();
        assert_eq!(a.name_for(0x0025), "NtOpenProcess");
    }
    #[test]
    fn test_ssdt_analyzer_name_for_unknown() {
        let a = SsdtAnalyzer::new();
        assert_eq!(a.name_for(0xFFFF), "Unknown");
    }
    #[test]
    fn test_kf_report_score_capped() {
        let kf = mock();
        let r = kf.report();
        assert!(r.overall_risk_score <= 100);
    }
    #[test]
    fn test_kf_malicious_callbacks_count() {
        let kf = mock();
        let r = kf.report();
        assert!(r.malicious_callbacks >= 1);
    }
}
