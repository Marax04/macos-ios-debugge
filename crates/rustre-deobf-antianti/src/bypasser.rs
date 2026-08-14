//! Anti-anti-analysis bypass implementations.
//!
//! The [`BypassEngine`] takes a list of [`crate::detector::DetectionSite`]
//! values and applies concrete binary patches to neutralise each detected
//! technique.  It also generates Frida hook scripts that can be used for
//! dynamic bypass when static patching is not desirable.

use serde::{Deserialize, Serialize};

use crate::{
    AntiDebugTechnique, AntiSandboxTechnique, AntiVmTechnique, PatchStrategy,
    detector::{DetectedTechnique, DetectionSite},
};

// ─────────────────────────────────────────────────────────────────────────────
// BypassPatch
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete binary patch that neutralises a single detection site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassPatch {
    /// Byte offset of the patch.
    pub offset: usize,
    /// The original bytes that were replaced.
    pub original: Vec<u8>,
    /// The replacement bytes.
    pub replacement: Vec<u8>,
    /// Technique that this patch neutralises.
    pub technique: DetectedTechnique,
    /// Human-readable description.
    pub description: String,
}

impl BypassPatch {
    /// Apply this patch to a mutable byte buffer.
    ///
    /// Returns `false` if the offset + replacement length exceeds the buffer.
    pub fn apply(&self, buf: &mut [u8]) -> bool {
        let end = self.offset + self.replacement.len();
        if end > buf.len() {
            return false;
        }
        buf[self.offset..end].copy_from_slice(&self.replacement);
        true
    }

    /// Revert this patch (restore the original bytes).
    ///
    /// Returns `false` if the offset + original length exceeds the buffer.
    pub fn revert(&self, buf: &mut [u8]) -> bool {
        let end = self.offset + self.original.len();
        if end > buf.len() {
            return false;
        }
        buf[self.offset..end].copy_from_slice(&self.original);
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FridaHookScript
// ─────────────────────────────────────────────────────────────────────────────

/// A generated Frida JavaScript hook script for dynamic bypass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FridaHookScript {
    /// Target API or function name.
    pub target: String,
    /// The generated JavaScript source.
    pub script: String,
    /// The technique this hook neutralises.
    pub technique: DetectedTechnique,
}

// ─────────────────────────────────────────────────────────────────────────────
// BypassEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Generates binary patches and Frida scripts from detection sites.
///
/// ```rust
/// use rustre_deobf_antianti::bypasser::BypassEngine;
/// use rustre_deobf_antianti::detector::StaticAntiDebugDetector;
///
/// let engine = BypassEngine::new();
/// let det = StaticAntiDebugDetector::new();
/// let data = b"\x0f\x31\x90\x90IsDebuggerPresent\x00";
/// let sites = det.scan(data);
/// let patches = engine.generate_patches(data, &sites);
/// assert!(!patches.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct BypassEngine {
    /// When `true`, the engine also generates Frida hook scripts.
    generate_frida: bool,
}

impl BypassEngine {
    /// Create a new bypass engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generate_frida: false,
        }
    }

    /// Enable Frida hook script generation.
    #[must_use]
    pub const fn with_frida(mut self) -> Self {
        self.generate_frida = true;
        self
    }

    /// Generate binary patches for all detection sites.
    ///
    /// The `data` slice provides the original bytes at each site.
    #[must_use]
    pub fn generate_patches(&self, data: &[u8], sites: &[DetectionSite]) -> Vec<BypassPatch> {
        sites
            .iter()
            .filter_map(|site| self.patch_for_site(data, site))
            .collect()
    }

    /// Generate Frida hook scripts for all API-based detection sites.
    #[must_use]
    pub fn generate_frida_hooks(&self, sites: &[DetectionSite]) -> Vec<FridaHookScript> {
        if !self.generate_frida {
            return Vec::new();
        }
        sites
            .iter()
            .filter_map(|site| self.frida_hook_for_technique(&site.technique))
            .collect::<std::collections::HashSet<String>>() // deduplicate by target
            .into_iter()
            .filter_map(|target| {
                let dummy_technique = sites
                    .iter()
                    .find(|s| s.description.contains(&target))
                    .map(|s| s.technique.clone())?;
                Some(FridaHookScript {
                    script: frida_script_for_api(&target),
                    target,
                    technique: dummy_technique,
                })
            })
            .collect()
    }

    fn patch_for_site(&self, data: &[u8], site: &DetectionSite) -> Option<BypassPatch> {
        let end = site.offset + site.length;
        if end > data.len() {
            return None;
        }
        let original = data[site.offset..end].to_vec();
        let replacement = self.build_replacement(&original, site.strategy, &site.technique);
        let description = format!("bypass {} at 0x{:08x}", site.technique, site.offset);
        Some(BypassPatch {
            offset: site.offset,
            original,
            replacement,
            technique: site.technique.clone(),
            description,
        })
    }

    fn build_replacement(
        &self,
        original: &[u8],
        strategy: PatchStrategy,
        _technique: &DetectedTechnique,
    ) -> Vec<u8> {
        let len = original.len();
        match strategy {
            PatchStrategy::Nop => vec![0x90u8; len],

            PatchStrategy::ReturnZero => {
                // xor eax, eax + ret (if space allows), else NOP
                if len >= 3 {
                    let mut b = vec![0x90u8; len];
                    b[0] = 0x31; // xor eax, eax
                    b[1] = 0xC0;
                    b[2] = 0xC3; // ret
                    b
                } else {
                    vec![0x90u8; len]
                }
            }

            PatchStrategy::ReturnOne => {
                // mov eax, 1 + ret
                if len >= 7 {
                    let mut b = vec![0x90u8; len];
                    b[0] = 0xB8; // mov eax, imm32
                    b[1] = 0x01;
                    b[2] = 0x00;
                    b[3] = 0x00;
                    b[4] = 0x00;
                    b[5] = 0xC3; // ret
                    b
                } else {
                    vec![0x90u8; len]
                }
            }

            PatchStrategy::ForceFalse => {
                // Strategy depends on technique context.
                // For most checks: xor eax, eax + NOP padding.
                let mut b = vec![0x90u8; len];
                if len >= 2 {
                    b[0] = 0x31;
                    b[1] = 0xC0;
                }
                b
            }

            PatchStrategy::ForceTrue => {
                // mov eax, 1 (5 bytes) + NOP padding
                let mut b = vec![0x90u8; len];
                if len >= 5 {
                    b[0] = 0xB8;
                    b[1] = 0x01;
                    b[2] = 0x00;
                    b[3] = 0x00;
                    b[4] = 0x00;
                }
                b
            }

            PatchStrategy::SkipBlock => {
                // jmp short +len (skip the whole site)
                let mut b = vec![0x90u8; len];
                if len >= 2 {
                    b[0] = 0xEB; // jmp short
                    b[1] = (len as u8).wrapping_sub(2); // relative offset
                }
                b
            }
        }
    }

    fn frida_hook_for_technique(&self, technique: &DetectedTechnique) -> Option<String> {
        match technique {
            DetectedTechnique::AntiDebug(t) => frida_target_for_anti_debug(t),
            DetectedTechnique::AntiVm(t) => frida_target_for_anti_vm(t),
            DetectedTechnique::AntiSandbox(t) => frida_target_for_anti_sandbox(t),
        }
    }
}

fn frida_target_for_anti_debug(t: &AntiDebugTechnique) -> Option<String> {
    match t {
        AntiDebugTechnique::IsDebuggerPresent => Some("IsDebuggerPresent".to_owned()),
        AntiDebugTechnique::CheckRemoteDebuggerPresent => {
            Some("CheckRemoteDebuggerPresent".to_owned())
        }
        AntiDebugTechnique::NtQueryInformationProcess => {
            Some("NtQueryInformationProcess".to_owned())
        }
        AntiDebugTechnique::GetTickCount => Some("GetTickCount".to_owned()),
        AntiDebugTechnique::QueryPerformanceCounter => Some("QueryPerformanceCounter".to_owned()),
        AntiDebugTechnique::TimingDelays => Some("Sleep".to_owned()),
        AntiDebugTechnique::OutputDebugString => Some("OutputDebugStringA".to_owned()),
        AntiDebugTechnique::HardwareBreakpoints => Some("GetThreadContext".to_owned()),
        AntiDebugTechnique::DrRegisterCheck => Some("NtGetContextThread".to_owned()),
        _ => None,
    }
}

fn frida_target_for_anti_vm(t: &AntiVmTechnique) -> Option<String> {
    match t {
        AntiVmTechnique::CpuCountCheck => Some("GetSystemInfo".to_owned()),
        AntiVmTechnique::DiskSizeCheck => Some("GetDiskFreeSpaceExW".to_owned()),
        AntiVmTechnique::NetworkAdapterCheck => Some("GetAdaptersAddresses".to_owned()),
        AntiVmTechnique::UptimeCheck => Some("GetTickCount".to_owned()),
        AntiVmTechnique::MouseMovementCheck => Some("GetCursorPos".to_owned()),
        _ => None,
    }
}

fn frida_target_for_anti_sandbox(t: &AntiSandboxTechnique) -> Option<String> {
    match t {
        AntiSandboxTechnique::SleepSkip => Some("Sleep".to_owned()),
        AntiSandboxTechnique::UserInteractionCheck => Some("GetCursorPos".to_owned()),
        AntiSandboxTechnique::ScreenResolution => Some("GetSystemMetrics".to_owned()),
        AntiSandboxTechnique::UsernameCheck => Some("GetUserNameW".to_owned()),
        AntiSandboxTechnique::NetworkConnectivity => Some("InternetGetConnectedState".to_owned()),
        AntiSandboxTechnique::DomainCheck => Some("NetGetJoinInformation".to_owned()),
        AntiSandboxTechnique::RecentFileCheck => Some("SHGetSpecialFolderPathW".to_owned()),
    }
}

/// Generate a Frida JavaScript hook script for a given API name.
fn frida_script_for_api(api: &str) -> String {
    match api {
        "IsDebuggerPresent" => r#"
// Bypass: IsDebuggerPresent — always return 0 (not being debugged)
const IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (IsDebuggerPresent) {
    Interceptor.replace(IsDebuggerPresent, new NativeCallback(function () {
        return 0;
    }, "uint32", []));
}
"#.trim().to_owned(),

        "CheckRemoteDebuggerPresent" => r#"
// Bypass: CheckRemoteDebuggerPresent — write 0 (FALSE) to *pbDebuggerPresent
const CheckRemoteDebuggerPresent = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
if (CheckRemoteDebuggerPresent) {
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onLeave: function(retval) {
            var pbDebuggerPresent = this.context.rdx || this.context.edx;
            if (pbDebuggerPresent) {
                Memory.writeU32(ptr(pbDebuggerPresent.toString()), 0);
            }
        }
    });
}
"#.trim().to_owned(),

        "NtQueryInformationProcess" => r#"
// Bypass: NtQueryInformationProcess — zero out ProcessDebugPort (class 7)
const NtQIP = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
if (NtQIP) {
    Interceptor.attach(NtQIP, {
        onEnter: function(args) {
            this.cls = args[1].toInt32();
            this.outPtr = args[2];
        },
        onLeave: function(retval) {
            if (this.cls === 7 && this.outPtr && !this.outPtr.isNull()) {
                this.outPtr.writeU64(0);
            }
        }
    });
}
"#.trim().to_owned(),

        "GetTickCount" => r#"
// Bypass: GetTickCount — return a plausible non-zero constant
var _tick = 600000;
const GetTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
if (GetTickCount) {
    Interceptor.replace(GetTickCount, new NativeCallback(function () {
        _tick += 15;
        return _tick;
    }, "uint32", []));
}
"#.trim().to_owned(),

        "QueryPerformanceCounter" => r#"
// Bypass: QueryPerformanceCounter — return a monotonically increasing value
var _qpc = 0x100000;
const QPC = Module.findExportByName("kernel32.dll", "QueryPerformanceCounter");
if (QPC) {
    Interceptor.attach(QPC, {
        onLeave: function(_retval) {
            _qpc += 0x10000;
            if (!this.context.rcx.isNull()) {
                this.context.rcx.writeU64(_qpc);
            }
        }
    });
}
"#.trim().to_owned(),

        "Sleep" => r#"
// Bypass: Sleep / NtDelayExecution — reduce sleep duration to 1 ms
const Sleep = Module.findExportByName("kernel32.dll", "Sleep");
if (Sleep) {
    Interceptor.attach(Sleep, {
        onEnter: function(args) {
            args[0] = ptr(1);
        }
    });
}
"#.trim().to_owned(),

        "GetSystemMetrics" => r#"
// Bypass: GetSystemMetrics SM_CXSCREEN/SM_CYSCREEN — return 1920/1080
const GSM = Module.findExportByName("user32.dll", "GetSystemMetrics");
if (GSM) {
    Interceptor.replace(GSM, new NativeCallback(function (nIndex) {
        if (nIndex === 0) return 1920;
        if (nIndex === 1) return 1080;
        return 0;
    }, "int", ["int"]));
}
"#.trim().to_owned(),

        "GetUserNameW" => r#"
// Bypass: GetUserNameW — return a realistic username
const GUN = Module.findExportByName("advapi32.dll", "GetUserNameW");
if (GUN) {
    Interceptor.attach(GUN, {
        onLeave: function(retval) {
            if (!this.context.rcx.isNull()) {
                var name = "JohnDoe";
                Memory.writeUtf16String(this.context.rcx, name);
                if (!this.context.rdx.isNull()) {
                    this.context.rdx.writeU32(name.length + 1);
                }
            }
        }
    });
}
"#.trim().to_owned(),

        "InternetGetConnectedState" => r#"
// Bypass: InternetGetConnectedState — report network as connected
const IGCS = Module.findExportByName("wininet.dll", "InternetGetConnectedState");
if (IGCS) {
    Interceptor.replace(IGCS, new NativeCallback(function (_flags, _reserved) {
        return 1; // TRUE
    }, "int", ["pointer", "uint32"]));
}
"#.trim().to_owned(),

        "GetCursorPos" => r#"
// Bypass: GetCursorPos — return a realistic, slightly changing mouse position
var _mx = 512, _my = 400;
const GCP = Module.findExportByName("user32.dll", "GetCursorPos");
if (GCP) {
    Interceptor.replace(GCP, new NativeCallback(function (lpPoint) {
        _mx = (_mx + 3) % 1920;
        _my = (_my + 2) % 1080;
        Memory.writeU32(lpPoint, _mx);
        Memory.writeU32(lpPoint.add(4), _my);
        return 1;
    }, "int", ["pointer"]));
}
"#.trim().to_owned(),

        "GetDiskFreeSpaceExW" => r#"
// Bypass: GetDiskFreeSpaceEx — report 500 GB free and total
const GDFSE = Module.findExportByName("kernel32.dll", "GetDiskFreeSpaceExW");
if (GDFSE) {
    Interceptor.attach(GDFSE, {
        onLeave: function(retval) {
            var total = ptr("0x7735940000"); // ~500 GB
            if (!this.context.rdx.isNull()) this.context.rdx.writeU64(total);
            if (!this.context.r8.isNull())  this.context.r8.writeU64(total);
            if (!this.context.r9.isNull())  this.context.r9.writeU64(total);
        }
    });
}
"#.trim().to_owned(),

        "GetAdaptersAddresses" => r#"
// Bypass: GetAdaptersAddresses — return ERROR_NO_DATA (no adapters visible to sandbox checks)
const GAA = Module.findExportByName("iphlpapi.dll", "GetAdaptersAddresses");
if (GAA) {
    Interceptor.replace(GAA, new NativeCallback(function () {
        return 0x103; // ERROR_NO_DATA
    }, "uint32", ["uint32", "uint32", "pointer", "pointer", "pointer"]));
}
"#.trim().to_owned(),

        "NetGetJoinInformation" => r#"
// Bypass: NetGetJoinInformation — report NetSetupWorkgroupName (not domain-joined)
const NGJI = Module.findExportByName("netapi32.dll", "NetGetJoinInformation");
if (NGJI) {
    Interceptor.replace(NGJI, new NativeCallback(function (_server, _name, type_ptr) {
        if (!type_ptr.isNull()) type_ptr.writeU32(2); // NetSetupWorkgroupName
        return 0; // NERR_Success
    }, "uint32", ["pointer", "pointer", "pointer"]));
}
"#.trim().to_owned(),

        "SHGetSpecialFolderPathW" => r#"
// Bypass: SHGetSpecialFolderPath — let it succeed (return TRUE) but don't flag empty dirs
const SGSFP = Module.findExportByName("shell32.dll", "SHGetSpecialFolderPathW");
// Hook is informational only; rely on static patching for this one.
if (SGSFP) {
    Interceptor.attach(SGSFP, {
        onLeave: function(retval) { /* no-op */ }
    });
}
"#.trim().to_owned(),

        "OutputDebugStringA" => r#"
// Bypass: OutputDebugStringA — no-op (suppress output)
const ODS = Module.findExportByName("kernel32.dll", "OutputDebugStringA");
if (ODS) {
    Interceptor.replace(ODS, new NativeCallback(function (_str) {}, "void", ["pointer"]));
}
"#.trim().to_owned(),

        "GetThreadContext" => r#"
// Bypass: GetThreadContext — clear DR0–DR7 (hardware breakpoint registers)
const GTC = Module.findExportByName("kernel32.dll", "GetThreadContext");
if (GTC) {
    Interceptor.attach(GTC, {
        onLeave: function(retval) {
            if (retval.toInt32() && !this.context.rdx.isNull()) {
                // Assuming CONTEXT offset of DR0 is 0x350 (x64)
                for (var i = 0; i < 8; i++) {
                    this.context.rdx.add(0x350 + i * 8).writeU64(0);
                }
            }
        }
    });
}
"#.trim().to_owned(),

        "NtGetContextThread" => r#"
// Bypass: NtGetContextThread — clear debug registers
const NGCT = Module.findExportByName("ntdll.dll", "NtGetContextThread");
if (NGCT) {
    Interceptor.attach(NGCT, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0 && !this.context.rdx.isNull()) {
                for (var i = 0; i < 8; i++) {
                    this.context.rdx.add(0x350 + i * 8).writeU64(0);
                }
            }
        }
    });
}
"#.trim().to_owned(),

        _ => format!("// No Frida hook template available for '{api}'"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{DetectedTechnique, StaticAntiDebugDetector};

    fn engine() -> BypassEngine {
        BypassEngine::new()
    }
    fn det() -> StaticAntiDebugDetector {
        StaticAntiDebugDetector::new()
    }

    #[test]
    fn test_patch_nop() {
        let data = [0x0Fu8, 0x31, 0x90, 0x90];
        let sites = det().scan(&data);
        assert!(!sites.is_empty());
        let patches = engine().generate_patches(&data, &sites);
        assert!(!patches.is_empty());
        // RDTSC patch should be NOP
        let rdtsc = patches.iter().find(|p| {
            matches!(
                &p.technique,
                DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc)
            )
        });
        if let Some(p) = rdtsc {
            assert!(p.replacement.iter().all(|&b| b == 0x90));
        }
    }

    #[test]
    fn test_apply_patch() {
        let mut buf = vec![0x0Fu8, 0x31];
        let patch = BypassPatch {
            offset: 0,
            original: vec![0x0F, 0x31],
            replacement: vec![0x90, 0x90],
            technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
            description: "test".to_owned(),
        };
        assert!(patch.apply(&mut buf));
        assert_eq!(buf, vec![0x90, 0x90]);
    }

    #[test]
    fn test_revert_patch() {
        let mut buf = vec![0x90u8, 0x90];
        let patch = BypassPatch {
            offset: 0,
            original: vec![0x0F, 0x31],
            replacement: vec![0x90, 0x90],
            technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
            description: "test".to_owned(),
        };
        assert!(patch.revert(&mut buf));
        assert_eq!(buf, vec![0x0F, 0x31]);
    }

    #[test]
    fn test_apply_patch_out_of_bounds() {
        let mut buf = vec![0x90u8];
        let patch = BypassPatch {
            offset: 0,
            original: vec![0x0F, 0x31],
            replacement: vec![0x90, 0x90],
            technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
            description: "test".to_owned(),
        };
        assert!(!patch.apply(&mut buf));
    }

    #[test]
    fn test_return_zero_strategy() {
        let engine = BypassEngine::new();
        let technique = DetectedTechnique::AntiDebug(AntiDebugTechnique::IsDebuggerPresent);
        let original = vec![0xCC; 6];
        let replacement =
            engine.build_replacement(&original, PatchStrategy::ReturnZero, &technique);
        assert_eq!(replacement.len(), 6);
        // xor eax, eax
        assert_eq!(replacement[0], 0x31);
        assert_eq!(replacement[1], 0xC0);
        // ret
        assert_eq!(replacement[2], 0xC3);
    }

    #[test]
    fn test_force_false_strategy() {
        let engine = BypassEngine::new();
        let technique = DetectedTechnique::AntiDebug(AntiDebugTechnique::IsDebuggerPresent);
        let original = vec![0xCC; 4];
        let replacement =
            engine.build_replacement(&original, PatchStrategy::ForceFalse, &technique);
        assert_eq!(replacement.len(), 4);
        assert_eq!(replacement[0], 0x31);
        assert_eq!(replacement[1], 0xC0);
    }

    #[test]
    fn test_skip_block_strategy() {
        let engine = BypassEngine::new();
        let technique = DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc);
        let original = vec![0xCC; 8];
        let replacement = engine.build_replacement(&original, PatchStrategy::SkipBlock, &technique);
        assert_eq!(replacement[0], 0xEB); // jmp short
    }

    #[test]
    fn test_frida_hooks_disabled_by_default() {
        let data = b"IsDebuggerPresent\x00";
        let sites = det().scan(data);
        let hooks = engine().generate_frida_hooks(&sites);
        assert!(hooks.is_empty());
    }

    #[test]
    fn test_frida_script_content() {
        let script = frida_script_for_api("IsDebuggerPresent");
        assert!(script.contains("IsDebuggerPresent"));
        assert!(script.contains("return 0"));
    }

    #[test]
    fn test_frida_script_sleep() {
        let script = frida_script_for_api("Sleep");
        assert!(script.contains("Sleep"));
        assert!(script.contains("ptr(1)"));
    }

    #[test]
    fn test_frida_script_unknown_api() {
        let script = frida_script_for_api("SomeObscureApi");
        assert!(script.contains("No Frida hook template"));
    }
}
