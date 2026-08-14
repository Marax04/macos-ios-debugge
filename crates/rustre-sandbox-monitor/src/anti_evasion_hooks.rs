//! Anti-evasion hooks — normalise or spoof environment signals that malware
//! uses to detect sandbox/VM execution.
//!
//! # Components
//! * [`AntiEvasionHooks`] — top-level coordinator
//! * [`TimingNormalizer`] — corrects suspiciously short or skipped time deltas
//! * [`CpuidSpoof`] — intercepts CPUID results and returns bare-metal values
//! * [`EnvSpoofer`] — spoofs environment variables, registry keys, hardware
//! * [`ArtifactHider`] — hides sandbox-specific filesystem/process artefacts
//! * [`AntiEvasionReport`] — collects all detected evasion attempts

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AntiEvasionError {
    #[error("hook installation failed for {hook}: {reason}")]
    HookInstall { hook: String, reason: String },
    #[error("artifact path too long: {0}")]
    PathTooLong(usize),
    #[error("cpuid leaf 0x{0:08x} not in spoof table")]
    CpuidLeafMissing(u32),
    #[error("timing overflow: delta={0}")]
    TimingOverflow(u64),
    #[error("spoof conflict: key '{0}' already registered")]
    SpoofConflict(String),
}

pub type AEResult<T> = Result<T, AntiEvasionError>;

// ─── EvasionTechnique ─────────────────────────────────────────────────────────

/// Taxonomy of anti-sandbox / anti-VM / anti-analysis techniques.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionTechnique {
    // Timing-based
    SleepAcceleration,
    RdtscDelta,
    GetTickCountDelta,
    QueryPerformanceCounter,
    // CPU / hardware fingerprint
    CpuidVmBit,
    CpuidBrandString,
    CpuidHypervisorBit,
    HardwareBreakpointCheck,
    // Environment fingerprint
    UserNameCheck,
    ComputerNameCheck,
    UsernameLength,
    ProcessCount,
    MemorySizeCheck,
    DiskSizeCheck,
    ScreenResolutionCheck,
    MouseMovement,
    // Artefact checks
    SandboxFilePresence,
    SandboxRegistryKey,
    SandboxProcessPresence,
    SandboxWindowTitle,
    SandboxMacAddress,
    // Debugger checks
    IsDebuggerPresent,
    RemoteDebugger,
    NtGlobalFlag,
    HeapFlags,
    // Other
    DllLoadOrder,
    ExceptionHandling,
    Custom(String),
}

impl fmt::Display for EvasionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SleepAcceleration => "sleep-acceleration",
            Self::RdtscDelta => "rdtsc-delta",
            Self::GetTickCountDelta => "gettickcount-delta",
            Self::QueryPerformanceCounter => "query-performance-counter",
            Self::CpuidVmBit => "cpuid-vm-bit",
            Self::CpuidBrandString => "cpuid-brand-string",
            Self::CpuidHypervisorBit => "cpuid-hypervisor-bit",
            Self::HardwareBreakpointCheck => "hardware-breakpoint",
            Self::UserNameCheck => "username-check",
            Self::ComputerNameCheck => "computername-check",
            Self::UsernameLength => "username-length",
            Self::ProcessCount => "process-count",
            Self::MemorySizeCheck => "memory-size",
            Self::DiskSizeCheck => "disk-size",
            Self::ScreenResolutionCheck => "screen-resolution",
            Self::MouseMovement => "mouse-movement",
            Self::SandboxFilePresence => "sandbox-file",
            Self::SandboxRegistryKey => "sandbox-registry",
            Self::SandboxProcessPresence => "sandbox-process",
            Self::SandboxWindowTitle => "sandbox-window",
            Self::SandboxMacAddress => "sandbox-mac",
            Self::IsDebuggerPresent => "is-debugger-present",
            Self::RemoteDebugger => "remote-debugger",
            Self::NtGlobalFlag => "nt-global-flag",
            Self::HeapFlags => "heap-flags",
            Self::DllLoadOrder => "dll-load-order",
            Self::ExceptionHandling => "exception-handling",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// ─── TimingNormalizer ─────────────────────────────────────────────────────────

/// Intercepts time-related calls and normalises or fakes their results.
#[derive(Debug)]
pub struct TimingNormalizer {
    /// Virtual clock, incremented on each tick call.
    virtual_clock_ms: Arc<AtomicU64>,
    /// Minimum delta returned for RDTSC (cycles).
    min_rdtsc_delta: u64,
    /// How many calls were intercepted.
    intercept_count: u64,
    /// Detected sleep-acceleration attempts.
    sleep_accel_count: u32,
    /// When `true`, `sleep()` calls are returned immediately but the virtual
    /// clock is advanced by the requested duration.
    accelerate_sleeps: bool,
}

impl Default for TimingNormalizer {
    fn default() -> Self {
        Self {
            virtual_clock_ms: Arc::new(AtomicU64::new(0)),
            min_rdtsc_delta: 1_000_000,
            intercept_count: 0,
            sleep_accel_count: 0,
            accelerate_sleeps: true,
        }
    }
}

impl TimingNormalizer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate a `GetTickCount` call.  Returns a normalised value.
    pub fn get_tick_count(&mut self) -> u64 {
        self.intercept_count += 1;
        self.virtual_clock_ms.fetch_add(10, Ordering::Relaxed)
    }

    /// Simulate a `Sleep(ms)` call. If `accelerate_sleeps` is set, the real
    /// thread does not sleep but the virtual clock advances.
    pub fn sleep(&mut self, requested_ms: u64) {
        self.intercept_count += 1;
        if requested_ms > 5_000 {
            self.sleep_accel_count += 1;
        }
        if self.accelerate_sleeps {
            self.virtual_clock_ms.fetch_add(requested_ms, Ordering::Relaxed);
        }
    }

    /// Simulate an RDTSC call.  Returns a value that grows plausibly.
    pub fn rdtsc(&mut self) -> u64 {
        self.intercept_count += 1;
        let base = self.virtual_clock_ms.fetch_add(1, Ordering::Relaxed);
        base.wrapping_mul(3_000_000).wrapping_add(self.min_rdtsc_delta)
    }

    /// Check whether a timing delta looks anomalous (sleep-acceleration detection).
    #[must_use]
    pub const fn is_anomalous_delta(&self, delta_ms: u64, expected_min_ms: u64) -> bool {
        delta_ms < expected_min_ms / 10
    }

    #[must_use]
    pub const fn intercept_count(&self) -> u64 {
        self.intercept_count
    }

    #[must_use]
    pub const fn sleep_accel_count(&self) -> u32 {
        self.sleep_accel_count
    }

    #[must_use]
    pub fn virtual_clock_ms(&self) -> u64 {
        self.virtual_clock_ms.load(Ordering::Relaxed)
    }
}

// ─── CpuidSpoof ───────────────────────────────────────────────────────────────

/// CPUID result for one leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Intercepts CPUID instructions and returns spoofed values.
#[derive(Debug, Default)]
pub struct CpuidSpoof {
    /// Spoof table: leaf → result
    spoof_table: HashMap<u32, CpuidResult>,
    /// Number of spoofed calls
    spoof_count: u64,
    /// Leaves that were queried but not in the table
    missing_leaves: Vec<u32>,
}

impl CpuidSpoof {
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self::default();
        s.install_defaults();
        s
    }

    fn install_defaults(&mut self) {
        // Leaf 0: vendor string "GenuineIntel"
        self.spoof_table.insert(
            0x0000_0000,
            CpuidResult { eax: 0x16, ebx: 0x756e_6547, ecx: 0x6c65_746e, edx: 0x4965_6e69 },
        );
        // Leaf 1: clear hypervisor bit (bit 31 of ECX)
        self.spoof_table.insert(
            0x0000_0001,
            CpuidResult { eax: 0x0006_06a0, ebx: 0x0200_0800, ecx: 0x7ffa_3203, edx: 0xbfeb_fbff },
        );
        // Leaf 0x80000002-0x80000004: brand string "Intel(R) Core(TM) i7"
        // Each register holds 4 ASCII bytes (little-endian).
        // 0x80000002: "Inte" "l(R)" " Cor" "e(TM"
        self.spoof_table.insert(
            0x8000_0002,
            CpuidResult { eax: 0x6c65_746e, ebx: 0x436f_7265, ecx: 0x2069_3720, edx: 0x2d39_3730 },
        );
        // 0x80000003: "K0 @" "2.90" "GHz\0" "\0\0\0\0"
        self.spoof_table.insert(
            0x8000_0003,
            CpuidResult { eax: 0x4b30_2040, ebx: 0x322e_3930, ecx: 0x4748_7a00, edx: 0x0000_0000 },
        );
        // 0x80000004: all zeros (terminator)
        self.spoof_table.insert(
            0x8000_0004,
            CpuidResult { eax: 0x0000_0000, ebx: 0x0000_0000, ecx: 0x0000_0000, edx: 0x0000_0000 },
        );
        // Hypervisor leaf: return all zeros (no hypervisor)
        self.spoof_table.insert(
            0x4000_0000,
            CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 },
        );
    }

    /// Add or override a spoof entry.
    pub fn add_entry(&mut self, leaf: u32, result: CpuidResult) {
        self.spoof_table.insert(leaf, result);
    }

    /// Execute a (spoofed) CPUID query.
    ///
    /// # Errors
    ///
    /// Currently infallible but returns `AEResult` for API consistency.
    pub fn cpuid(&mut self, leaf: u32) -> AEResult<CpuidResult> {
        self.spoof_count += 1;
        if let Some(r) = self.spoof_table.get(&leaf) {
            Ok(r.clone())
        } else {
            self.missing_leaves.push(leaf);
            // Return all-zeros for unknown leaves
            Ok(CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 })
        }
    }

    /// Returns `true` if the hypervisor present bit is cleared in leaf 1.
    #[must_use]
    pub fn hypervisor_bit_cleared(&self) -> bool {
        self.spoof_table
            .get(&0x0000_0001)
            .is_some_and(|r| r.ecx & (1 << 31) == 0)
    }

    #[must_use]
    pub const fn spoof_count(&self) -> u64 {
        self.spoof_count
    }
}

// ─── EnvSpoofer ───────────────────────────────────────────────────────────────

/// Spoof environment variables, registry key values, and hardware properties.
#[derive(Debug, Default)]
pub struct EnvSpoofer {
    env_vars: HashMap<String, String>,
    registry_values: HashMap<String, String>,
    hardware_props: HashMap<String, String>,
    spoof_count: u64,
}

impl EnvSpoofer {
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self::default();
        s.install_defaults();
        s
    }

    fn install_defaults(&mut self) {
        // Common username / computername that look like a real machine
        self.env_vars.insert("USERNAME".into(), "John".into());
        self.env_vars.insert("COMPUTERNAME".into(), "DESKTOP-A1B2C3D".into());
        self.env_vars.insert("USERDOMAIN".into(), "DESKTOP-A1B2C3D".into());
        self.env_vars.insert("PROCESSOR_IDENTIFIER".into(), "Intel64 Family 6 Model 158 Stepping 10, GenuineIntel".into());
        self.env_vars.insert("NUMBER_OF_PROCESSORS".into(), "8".into());

        // Hardware
        self.hardware_props.insert("disk_size_gb".into(), "512".into());
        self.hardware_props.insert("ram_gb".into(), "16".into());
        self.hardware_props.insert("screen_width".into(), "1920".into());
        self.hardware_props.insert("screen_height".into(), "1080".into());
        self.hardware_props.insert("mac_address".into(), "AA:BB:CC:DD:EE:FF".into());

        // Registry
        self.registry_values.insert(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProductName".into(),
            "Windows 10 Pro".into(),
        );
    }

    /// Register a custom env-var spoof.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env_vars.insert(key.into(), value.into());
    }

    /// Look up a (possibly spoofed) environment variable.
    pub fn get_env(&mut self, key: &str) -> Option<String> {
        self.spoof_count += 1;
        self.env_vars.get(key).cloned()
    }

    /// Look up a hardware property.
    pub fn get_hardware(&mut self, key: &str) -> Option<String> {
        self.spoof_count += 1;
        self.hardware_props.get(key).cloned()
    }

    /// Look up a registry value.
    pub fn get_registry(&mut self, path: &str) -> Option<String> {
        self.spoof_count += 1;
        self.registry_values.get(path).cloned()
    }

    #[must_use]
    pub const fn spoof_count(&self) -> u64 {
        self.spoof_count
    }

    /// Return a convincing process count (not the sandbox-low value of ~20).
    pub const fn process_count(&mut self) -> u32 {
        self.spoof_count += 1;
        87
    }
}

// ─── ArtifactHider ────────────────────────────────────────────────────────────

/// Hides sandbox-specific filesystem paths, process names, window titles, etc.
#[derive(Debug)]
pub struct ArtifactHider {
    hidden_paths: Vec<String>,
    hidden_processes: Vec<String>,
    hidden_windows: Vec<String>,
    hide_count: u64,
}

impl Default for ArtifactHider {
    fn default() -> Self {
        let mut h = Self {
            hidden_paths: Vec::new(),
            hidden_processes: Vec::new(),
            hidden_windows: Vec::new(),
            hide_count: 0,
        };
        h.install_defaults();
        h
    }
}

impl ArtifactHider {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    fn install_defaults(&mut self) {
        // Common sandbox driver/agent paths
        for p in &[
            "C:\\agent\\",
            "C:\\cuckoo\\",
            "C:\\sandbox\\",
            "C:\\analysis\\",
            "\\\\vboxsvr\\",
            "C:\\windows\\system32\\drivers\\vboxdrv.sys",
            "C:\\windows\\system32\\drivers\\vmmemctl.sys",
        ] {
            self.hidden_paths.push(p.to_string());
        }

        // Sandbox agent processes
        for p in &[
            "agent.exe",
            "analyzer.exe",
            "cuckoo.exe",
            "procmon.exe",
            "wireshark.exe",
            "fiddler.exe",
            "sandboxie.exe",
            "sbiedll.dll",
        ] {
            self.hidden_processes.push(p.to_string());
        }

        // Window title patterns
        for w in &["Cuckoo Sandbox", "Any.Run", "Joe Sandbox", "Hybrid Analysis"] {
            self.hidden_windows.push(w.to_string());
        }
    }

    /// Add a path to hide.
    pub fn hide_path(&mut self, path: impl Into<String>) {
        self.hidden_paths.push(path.into());
    }

    /// Add a process name to hide.
    pub fn hide_process(&mut self, name: impl Into<String>) {
        self.hidden_processes.push(name.into());
    }

    /// Check whether a given filesystem path should be hidden.
    pub fn is_path_hidden(&mut self, path: &str) -> bool {
        self.hide_count += 1;
        let path_lower = path.to_lowercase();
        self.hidden_paths.iter().any(|p| path_lower.contains(&p.to_lowercase()))
    }

    /// Check whether a given process name should be hidden.
    pub fn is_process_hidden(&mut self, name: &str) -> bool {
        self.hide_count += 1;
        let name_lower = name.to_lowercase();
        self.hidden_processes
            .iter()
            .any(|p| name_lower == p.to_lowercase())
    }

    /// Check whether a window title should be hidden.
    pub fn is_window_hidden(&mut self, title: &str) -> bool {
        self.hide_count += 1;
        let title_lower = title.to_lowercase();
        self.hidden_windows
            .iter()
            .any(|w| title_lower.contains(&w.to_lowercase()))
    }

    /// Filter a list of process names, removing hidden ones.
    pub fn filter_processes(&mut self, processes: &[String]) -> Vec<String> {
        processes
            .iter()
            .filter(|n| !self.is_process_hidden(n))
            .cloned()
            .collect()
    }

    #[must_use]
    pub const fn hide_count(&self) -> u64 {
        self.hide_count
    }

    #[must_use]
    pub const fn hidden_path_count(&self) -> usize {
        self.hidden_paths.len()
    }
}

// ─── EvasionEvent ─────────────────────────────────────────────────────────────

/// A single detected evasion attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionEvent {
    pub technique: EvasionTechnique,
    pub description: String,
    pub hook_name: String,
    pub call_count: u32,
    pub mitigated: bool,
}

impl EvasionEvent {
    pub fn new(technique: EvasionTechnique, description: impl Into<String>, hook: impl Into<String>) -> Self {
        Self {
            technique,
            description: description.into(),
            hook_name: hook.into(),
            call_count: 1,
            mitigated: false,
        }
    }
}

// ─── AntiEvasionReport ────────────────────────────────────────────────────────

/// Summary of all detected (and mitigated) evasion attempts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AntiEvasionReport {
    pub events: Vec<EvasionEvent>,
    pub techniques_seen: Vec<EvasionTechnique>,
    pub mitigated_count: u32,
    pub unmitigated_count: u32,
    pub timing_normalizer_calls: u64,
    pub cpuid_spoof_calls: u64,
    pub env_spoof_calls: u64,
    pub artifact_hide_calls: u64,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl AntiEvasionReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_event(&mut self, event: EvasionEvent) {
        if event.mitigated {
            self.mitigated_count += 1;
        } else {
            self.unmitigated_count += 1;
        }
        if !self.techniques_seen.contains(&event.technique) {
            self.techniques_seen.push(event.technique.clone());
        }
        self.events.push(event);
    }

    pub const fn compute_risk(&mut self) {
        let score = self.techniques_seen.len();
        self.risk_level = match score {
            0 => RiskLevel::None,
            1..=2 => RiskLevel::Low,
            3..=5 => RiskLevel::Medium,
            6..=10 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
    }

    #[must_use]
    pub const fn unique_technique_count(&self) -> usize {
        self.techniques_seen.len()
    }

    #[must_use]
    pub const fn total_events(&self) -> usize {
        self.events.len()
    }

    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "AntiEvasionReport: {} events, {} techniques, {} mitigated, risk={:?}",
            self.events.len(),
            self.techniques_seen.len(),
            self.mitigated_count,
            self.risk_level,
        )
    }
}

impl fmt::Display for AntiEvasionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── AntiEvasionHooks ─────────────────────────────────────────────────────────

/// Top-level coordinator: holds all sub-components and builds the report.
#[derive(Debug, Default)]
pub struct AntiEvasionHooks {
    pub timing: TimingNormalizer,
    pub cpuid: CpuidSpoof,
    pub env: EnvSpoofer,
    pub hider: ArtifactHider,
    events: Vec<EvasionEvent>,
}

impl AntiEvasionHooks {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            timing: TimingNormalizer::new(),
            cpuid: CpuidSpoof::new(),
            env: EnvSpoofer::new(),
            hider: ArtifactHider::new(),
            events: Vec::new(),
        }
    }

    /// Record a detected evasion event.
    pub fn record_event(&mut self, event: EvasionEvent) {
        self.events.push(event);
    }

    /// Check for sleep-acceleration: sample calls RDTSC before and after
    /// Sleep(1000) and verifies less than 100 ms elapsed.
    pub fn check_sleep_acceleration(&mut self, sleep_ms: u64, elapsed_ms: u64) -> bool {
        if self.timing.is_anomalous_delta(elapsed_ms, sleep_ms) {
            self.events.push(EvasionEvent {
                technique: EvasionTechnique::SleepAcceleration,
                description: format!(
                    "sleep({sleep_ms}ms) but only {elapsed_ms}ms elapsed"
                ),
                hook_name: "NtDelayExecution".into(),
                call_count: 1,
                mitigated: true,
            });
            true
        } else {
            false
        }
    }

    /// Check CPUID for VM-specific bits.
    pub fn check_cpuid_vm_bit(&mut self) -> bool {
        if let Ok(r) = self.cpuid.cpuid(0x0000_0001) {
            let vm_bit = r.ecx & (1 << 31) != 0;
            if vm_bit {
                self.events.push(EvasionEvent {
                    technique: EvasionTechnique::CpuidHypervisorBit,
                    description: "CPUID leaf 1 ECX bit 31 (hypervisor) is set".into(),
                    hook_name: "CPUID".into(),
                    call_count: 1,
                    mitigated: true,
                });
            }
            vm_bit
        } else {
            false
        }
    }

    /// Check for sandbox-indicating username.
    pub fn check_username(&mut self) -> Option<String> {
        let username = self.env.get_env("USERNAME").unwrap_or_default();
        let suspicious = ["sandbox", "malware", "virus", "sample", "cuckoo", "test", "analysis"];
        let lower = username.to_lowercase();
        if suspicious.iter().any(|s| lower.contains(s)) {
            self.events.push(EvasionEvent {
                technique: EvasionTechnique::UserNameCheck,
                description: format!("suspicious username detected: '{username}'"),
                hook_name: "GetUserNameA".into(),
                call_count: 1,
                mitigated: true,
            });
            Some(username)
        } else {
            None
        }
    }

    /// Check whether process count looks like a sandbox (typically < 30).
    pub fn check_process_count(&mut self, real_count: u32) -> bool {
        if real_count < 30 {
            self.events.push(EvasionEvent {
                technique: EvasionTechnique::ProcessCount,
                description: format!("only {real_count} processes running (sandbox indicator)"),
                hook_name: "EnumProcesses".into(),
                call_count: 1,
                mitigated: true,
            });
            true
        } else {
            false
        }
    }

    /// Check for sandbox-specific files.
    pub fn check_sandbox_files(&mut self, paths_to_check: &[&str]) -> Vec<String> {
        let mut found = Vec::new();
        for &path in paths_to_check {
            if self.hider.is_path_hidden(path) {
                self.events.push(EvasionEvent {
                    technique: EvasionTechnique::SandboxFilePresence,
                    description: format!("sandbox artefact path: {path}"),
                    hook_name: "NtQueryDirectoryFile".into(),
                    call_count: 1,
                    mitigated: true,
                });
                found.push(path.to_string());
            }
        }
        found
    }

    /// Build the final `AntiEvasionReport`.
    #[must_use]
    pub fn build_report(&self) -> AntiEvasionReport {
        let mut report = AntiEvasionReport::new();
        for e in &self.events {
            report.add_event(e.clone());
        }
        report.timing_normalizer_calls = self.timing.intercept_count();
        report.cpuid_spoof_calls = self.cpuid.spoof_count();
        report.env_spoof_calls = self.env.spoof_count();
        report.artifact_hide_calls = self.hider.hide_count();
        report.compute_risk();
        report
    }

    /// Number of events recorded so far.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TimingNormalizer ───────────────────────────────────────────────────────

    #[test]
    fn test_timing_tick_count_increases() {
        let mut t = TimingNormalizer::new();
        let a = t.get_tick_count();
        let b = t.get_tick_count();
        assert!(b > a);
    }

    #[test]
    fn test_timing_sleep_advances_clock() {
        let mut t = TimingNormalizer::new();
        t.sleep(5000);
        assert!(t.virtual_clock_ms() >= 5000);
    }

    #[test]
    fn test_timing_sleep_accel_detected() {
        let mut t = TimingNormalizer::new();
        t.sleep(10_000);
        assert_eq!(t.sleep_accel_count(), 1);
    }

    #[test]
    fn test_timing_sleep_small_not_accel() {
        let mut t = TimingNormalizer::new();
        t.sleep(100);
        assert_eq!(t.sleep_accel_count(), 0);
    }

    #[test]
    fn test_timing_rdtsc_increases() {
        let mut t = TimingNormalizer::new();
        let a = t.rdtsc();
        let b = t.rdtsc();
        assert!(b >= a);
    }

    #[test]
    fn test_timing_intercept_count() {
        let mut t = TimingNormalizer::new();
        t.get_tick_count();
        t.rdtsc();
        assert_eq!(t.intercept_count(), 2);
    }

    #[test]
    fn test_timing_anomalous_delta() {
        let t = TimingNormalizer::new();
        assert!(t.is_anomalous_delta(1, 1000));
        assert!(!t.is_anomalous_delta(500, 1000));
    }

    // ── CpuidSpoof ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cpuid_default_leaf0() {
        let mut c = CpuidSpoof::new();
        let r = c.cpuid(0).unwrap();
        assert_eq!(r.ebx, 0x756e_6547); // "Genu"
    }

    #[test]
    fn test_cpuid_hypervisor_bit_cleared() {
        let c = CpuidSpoof::new();
        assert!(c.hypervisor_bit_cleared());
    }

    #[test]
    fn test_cpuid_unknown_leaf_returns_zeros() {
        let mut c = CpuidSpoof::new();
        let r = c.cpuid(0xDEAD_BEEF).unwrap();
        assert_eq!(r.eax, 0);
        assert_eq!(r.ebx, 0);
    }

    #[test]
    fn test_cpuid_add_entry() {
        let mut c = CpuidSpoof::new();
        let fake = CpuidResult { eax: 1, ebx: 2, ecx: 3, edx: 4 };
        c.add_entry(0x1234, fake.clone());
        assert_eq!(c.cpuid(0x1234).unwrap(), fake);
    }

    #[test]
    fn test_cpuid_spoof_count() {
        let mut c = CpuidSpoof::new();
        c.cpuid(0).unwrap();
        c.cpuid(1).unwrap();
        assert_eq!(c.spoof_count(), 2);
    }

    #[test]
    fn test_cpuid_hypervisor_leaf_zeros() {
        let mut c = CpuidSpoof::new();
        let r = c.cpuid(0x4000_0000).unwrap();
        assert_eq!(r.eax, 0);
    }

    // ── EnvSpoofer ─────────────────────────────────────────────────────────────

    #[test]
    fn test_env_spoofer_default_username() {
        let mut e = EnvSpoofer::new();
        assert_eq!(e.get_env("USERNAME"), Some("John".into()));
    }

    #[test]
    fn test_env_spoofer_process_count() {
        let mut e = EnvSpoofer::new();
        assert_eq!(e.process_count(), 87);
    }

    #[test]
    fn test_env_spoofer_disk_size() {
        let mut e = EnvSpoofer::new();
        assert_eq!(e.get_hardware("disk_size_gb"), Some("512".into()));
    }

    #[test]
    fn test_env_spoofer_registry() {
        let mut e = EnvSpoofer::new();
        let v = e.get_registry("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProductName");
        assert_eq!(v, Some("Windows 10 Pro".into()));
    }

    #[test]
    fn test_env_spoofer_missing_key() {
        let mut e = EnvSpoofer::new();
        assert_eq!(e.get_env("NONEXISTENT_KEY"), None);
    }

    #[test]
    fn test_env_spoofer_set_custom() {
        let mut e = EnvSpoofer::new();
        e.set_env("MY_VAR", "MY_VALUE");
        assert_eq!(e.get_env("MY_VAR"), Some("MY_VALUE".into()));
    }

    #[test]
    fn test_env_spoofer_spoof_count() {
        let mut e = EnvSpoofer::new();
        e.get_env("USERNAME");
        e.get_hardware("ram_gb");
        assert!(e.spoof_count() >= 2);
    }

    // ── ArtifactHider ──────────────────────────────────────────────────────────

    #[test]
    fn test_hider_sandbox_path_hidden() {
        let mut h = ArtifactHider::new();
        assert!(h.is_path_hidden("C:\\cuckoo\\agent\\agent.exe"));
    }

    #[test]
    fn test_hider_normal_path_not_hidden() {
        let mut h = ArtifactHider::new();
        assert!(!h.is_path_hidden("C:\\Windows\\System32\\notepad.exe"));
    }

    #[test]
    fn test_hider_process_hidden() {
        let mut h = ArtifactHider::new();
        assert!(h.is_process_hidden("agent.exe"));
    }

    #[test]
    fn test_hider_normal_process_not_hidden() {
        let mut h = ArtifactHider::new();
        assert!(!h.is_process_hidden("chrome.exe"));
    }

    #[test]
    fn test_hider_window_hidden() {
        let mut h = ArtifactHider::new();
        assert!(h.is_window_hidden("Cuckoo Sandbox - Analysis"));
    }

    #[test]
    fn test_hider_normal_window_not_hidden() {
        let mut h = ArtifactHider::new();
        assert!(!h.is_window_hidden("Notepad - document.txt"));
    }

    #[test]
    fn test_hider_filter_processes() {
        let mut h = ArtifactHider::new();
        let procs = vec!["chrome.exe".into(), "agent.exe".into(), "notepad.exe".into()];
        let filtered = h.filter_processes(&procs);
        assert!(!filtered.contains(&"agent.exe".to_string()));
        assert!(filtered.contains(&"chrome.exe".to_string()));
    }

    #[test]
    fn test_hider_custom_path() {
        let mut h = ArtifactHider::new();
        h.hide_path("C:\\mysandbox\\");
        assert!(h.is_path_hidden("C:\\mysandbox\\driver.sys"));
    }

    #[test]
    fn test_hider_hidden_path_count() {
        let h = ArtifactHider::new();
        assert!(h.hidden_path_count() > 0);
    }

    // ── EvasionEvent ──────────────────────────────────────────────────────────

    #[test]
    fn test_evasion_event_new() {
        let e = EvasionEvent::new(EvasionTechnique::RdtscDelta, "test", "RDTSC");
        assert_eq!(e.call_count, 1);
        assert!(!e.mitigated);
    }

    #[test]
    fn test_evasion_technique_display() {
        assert_eq!(EvasionTechnique::SleepAcceleration.to_string(), "sleep-acceleration");
        assert_eq!(EvasionTechnique::CpuidVmBit.to_string(), "cpuid-vm-bit");
    }

    // ── AntiEvasionReport ─────────────────────────────────────────────────────

    #[test]
    fn test_report_new_empty() {
        let r = AntiEvasionReport::new();
        assert_eq!(r.total_events(), 0);
        assert_eq!(r.unique_technique_count(), 0);
    }

    #[test]
    fn test_report_add_event() {
        let mut r = AntiEvasionReport::new();
        let e = EvasionEvent {
            technique: EvasionTechnique::ProcessCount,
            description: "test".into(),
            hook_name: "EnumProcesses".into(),
            call_count: 1,
            mitigated: true,
        };
        r.add_event(e);
        assert_eq!(r.total_events(), 1);
        assert_eq!(r.mitigated_count, 1);
    }

    #[test]
    fn test_report_risk_none() {
        let mut r = AntiEvasionReport::new();
        r.compute_risk();
        assert_eq!(r.risk_level, RiskLevel::None);
    }

    #[test]
    fn test_report_risk_critical() {
        let mut r = AntiEvasionReport::new();
        for i in 0..12 {
            r.events.push(EvasionEvent::new(
                EvasionTechnique::Custom(format!("tech{i}")),
                "t",
                "h",
            ));
            r.techniques_seen.push(EvasionTechnique::Custom(format!("tech{i}")));
        }
        r.compute_risk();
        assert_eq!(r.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_report_json() {
        let r = AntiEvasionReport::new();
        let j = r.to_json().unwrap();
        assert!(j.contains("events"));
    }

    #[test]
    fn test_report_unique_techniques_dedup() {
        let mut r = AntiEvasionReport::new();
        for _ in 0..5 {
            r.add_event(EvasionEvent::new(EvasionTechnique::RdtscDelta, "d", "h"));
        }
        assert_eq!(r.unique_technique_count(), 1);
    }

    // ── AntiEvasionHooks ──────────────────────────────────────────────────────

    #[test]
    fn test_hooks_new() {
        let h = AntiEvasionHooks::new();
        assert_eq!(h.event_count(), 0);
    }

    #[test]
    fn test_hooks_sleep_accel_detected() {
        let mut h = AntiEvasionHooks::new();
        let detected = h.check_sleep_acceleration(5000, 10);
        assert!(detected);
        assert_eq!(h.event_count(), 1);
    }

    #[test]
    fn test_hooks_sleep_accel_not_detected() {
        let mut h = AntiEvasionHooks::new();
        assert!(!h.check_sleep_acceleration(1000, 950));
    }

    #[test]
    fn test_hooks_cpuid_vm_bit() {
        let mut h = AntiEvasionHooks::new();
        // Default spoof has VM bit cleared, so should return false
        let vm_bit = h.check_cpuid_vm_bit();
        assert!(!vm_bit);
    }

    #[test]
    fn test_hooks_username_check_normal() {
        let mut h = AntiEvasionHooks::new();
        // Default is "John" — not suspicious
        let result = h.check_username();
        assert!(result.is_none());
    }

    #[test]
    fn test_hooks_username_check_suspicious() {
        let mut h = AntiEvasionHooks::new();
        h.env.set_env("USERNAME", "sandbox");
        let result = h.check_username();
        assert!(result.is_some());
    }

    #[test]
    fn test_hooks_process_count_low() {
        let mut h = AntiEvasionHooks::new();
        assert!(h.check_process_count(15));
        assert_eq!(h.event_count(), 1);
    }

    #[test]
    fn test_hooks_process_count_normal() {
        let mut h = AntiEvasionHooks::new();
        assert!(!h.check_process_count(100));
    }

    #[test]
    fn test_hooks_sandbox_files() {
        let mut h = AntiEvasionHooks::new();
        let found = h.check_sandbox_files(&["C:\\cuckoo\\agent.exe", "C:\\Windows\\notepad.exe"]);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_hooks_build_report() {
        let mut h = AntiEvasionHooks::new();
        h.check_sleep_acceleration(10000, 5);
        h.check_process_count(5);
        let report = h.build_report();
        assert_eq!(report.total_events(), 2);
    }

    #[test]
    fn test_hooks_build_report_risk_computed() {
        let mut h = AntiEvasionHooks::new();
        h.check_sleep_acceleration(10000, 1);
        let report = h.build_report();
        assert_ne!(report.risk_level, RiskLevel::None);
    }
}
