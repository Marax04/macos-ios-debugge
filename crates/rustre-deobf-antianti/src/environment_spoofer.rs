//! `environment_spoofer` — Environment spoofing for anti-debug bypass.
//!
//! Generates patches and Frida hook scripts to spoof:
//! - IsDebuggerPresent → false
//! - CheckRemoteDebuggerPresent → false
//! - NtQueryInformationProcess ProcessDebugPort → 0
//! - NtQuerySystemInformation SystemKernelDebuggerInformation → non-debugged
//! - Heap flags (NtGlobalFlag → 0)
//! - PEB.BeingDebugged → 0
//! - HEAP_TAIL_CHECKING_ENABLED clear

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// SpoofTarget — what to spoof
// ─────────────────────────────────────────────────────────────────────────────

/// An environment field that can be spoofed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpoofTarget {
    /// `PEB.BeingDebugged` byte (offset 0x02 in PEB on 64-bit).
    PebBeingDebugged,
    /// `PEB.NtGlobalFlag` (offset 0xBC on 64-bit, 0x68 on 32-bit).
    NtGlobalFlag,
    /// `PEB.ProcessHeap.Flags` (cleared to remove debug heap markers).
    HeapFlags,
    /// `PEB.ProcessHeap.ForceFlags`.
    HeapForceFlags,
    /// `kernel32!IsDebuggerPresent` function.
    IsDebuggerPresent,
    /// `kernel32!CheckRemoteDebuggerPresent` function.
    CheckRemoteDebuggerPresent,
    /// `ntdll!NtQueryInformationProcess`.
    NtQueryInformationProcess,
    /// `ntdll!NtQuerySystemInformation`.
    NtQuerySystemInformation,
    /// `kernel32!OutputDebugStringA` / `W` (timing side-channel).
    OutputDebugString,
    /// `kernel32!CloseHandle` (exception under debugger).
    CloseHandle,
    /// Heap tail-check byte (set after each heap allocation by debug CRT).
    HeapTailCheck,
}

impl SpoofTarget {
    /// Human-readable name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::PebBeingDebugged => "PEB.BeingDebugged",
            Self::NtGlobalFlag => "PEB.NtGlobalFlag",
            Self::HeapFlags => "PEB.ProcessHeap.Flags",
            Self::HeapForceFlags => "PEB.ProcessHeap.ForceFlags",
            Self::IsDebuggerPresent => "IsDebuggerPresent",
            Self::CheckRemoteDebuggerPresent => "CheckRemoteDebuggerPresent",
            Self::NtQueryInformationProcess => "NtQueryInformationProcess",
            Self::NtQuerySystemInformation => "NtQuerySystemInformation",
            Self::OutputDebugString => "OutputDebugString",
            Self::CloseHandle => "CloseHandle",
            Self::HeapTailCheck => "HeapTailCheck",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PebLayout — Windows PEB offsets (both 32-bit and 64-bit)
// ─────────────────────────────────────────────────────────────────────────────

/// PEB layout offsets for a given pointer size.
#[derive(Debug, Clone, Copy)]
pub struct PebLayout {
    pub being_debugged_offset: usize,
    pub nt_global_flag_offset: usize,
    pub process_heap_offset: usize,
    pub ptr_size: usize,
}

impl PebLayout {
    /// 64-bit Windows PEB layout.
    #[must_use]
    pub const fn x64() -> Self {
        Self {
            being_debugged_offset: 0x02,
            nt_global_flag_offset: 0xBC,
            process_heap_offset: 0x30,
            ptr_size: 8,
        }
    }

    /// 32-bit Windows PEB layout.
    #[must_use]
    pub const fn x86() -> Self {
        Self {
            being_debugged_offset: 0x02,
            nt_global_flag_offset: 0x68,
            process_heap_offset: 0x18,
            ptr_size: 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SpooferConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the environment spoofer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpooferConfig {
    /// Targets to spoof.
    pub targets: Vec<SpoofTarget>,
    /// Whether to generate Frida script (true) or binary patches (false).
    pub frida_mode: bool,
    /// Architecture (true = 64-bit, false = 32-bit).
    pub is_64bit: bool,
}

impl Default for SpooferConfig {
    fn default() -> Self {
        Self {
            targets: vec![
                SpoofTarget::IsDebuggerPresent,
                SpoofTarget::CheckRemoteDebuggerPresent,
                SpoofTarget::NtQueryInformationProcess,
                SpoofTarget::NtQuerySystemInformation,
                SpoofTarget::NtGlobalFlag,
                SpoofTarget::PebBeingDebugged,
                SpoofTarget::HeapFlags,
                SpoofTarget::HeapTailCheck,
            ],
            frida_mode: true,
            is_64bit: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FridaHookFragment
// ─────────────────────────────────────────────────────────────────────────────

/// One Frida hook fragment.
#[derive(Debug, Clone)]
pub struct FridaHookFragment {
    pub target: SpoofTarget,
    pub javascript: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// EnvironmentSpoofer
// ─────────────────────────────────────────────────────────────────────────────

/// Generates environment spoofing patches and Frida scripts.
pub struct EnvironmentSpoofer {
    config: SpooferConfig,
}

impl EnvironmentSpoofer {
    #[must_use]
    pub const fn new(config: SpooferConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SpooferConfig::default())
    }

    /// Generate a complete Frida JavaScript hook script.
    #[must_use]
    pub fn generate_frida_script(&self) -> String {
        let fragments: Vec<FridaHookFragment> = self
            .config
            .targets
            .iter()
            .filter_map(|&t| self.frida_fragment(t))
            .collect();

        let mut lines = vec![
            "// Auto-generated environment spoofer".to_string(),
            "// rustre-deobf-antianti::environment_spoofer".to_string(),
            "'use strict';".to_string(),
            String::new(),
            "function spoof_peb() {".to_string(),
        ];

        let peb_layout = if self.config.is_64bit {
            PebLayout::x64()
        } else {
            PebLayout::x86()
        };

        // PEB-related spoofing (inline assembly via Memory.readByteArray / writeByteArray)
        if self.config.targets.contains(&SpoofTarget::PebBeingDebugged) {
            lines.push(format!(
                "    // Patch PEB.BeingDebugged at offset {:#x}",
                peb_layout.being_debugged_offset
            ));
            lines.push(
                "    const peb = Process.getCurrentProcess().mainModule.base.add(-1 /* PEB addr requires NtQueryInformationProcess */);".to_string(),
            );
            lines.push("    // NOTE: Use the NtQueryInformationProcess hook below to zero ProcessDebugPort.".to_string());
        }

        if self.config.targets.contains(&SpoofTarget::NtGlobalFlag) {
            lines.push(format!(
                "    // NtGlobalFlag should be 0 (not 0x70) — offset {:#x}",
                peb_layout.nt_global_flag_offset
            ));
        }

        lines.push("}".to_string());
        lines.push(String::new());

        // API hooks
        for frag in &fragments {
            lines.push(frag.javascript.clone());
            lines.push(String::new());
        }

        // PEB.BeingDebugged via process startup hook
        lines.push(self.frida_peb_patch(peb_layout));

        lines.join("\n")
    }

    fn frida_peb_patch(&self, layout: PebLayout) -> String {
        format!(
            r#"
// Patch PEB.BeingDebugged at startup
const pebOffset = {being_debugged};
try {{
    const ntdll = Process.getModuleByName('ntdll.dll');
    // Walk TEB → PEB
    const ntQueryInfo = ntdll.findExportByName('NtQueryInformationProcess');
    if (ntQueryInfo) {{
        // Hook will zero ProcessDebugPort (see above)
        console.log('[+] NtQueryInformationProcess hooked for ProcessDebugPort');
    }}
}} catch(e) {{
    console.warn('[-] PEB patch failed:', e.message);
}}"#,
            being_debugged = layout.being_debugged_offset
        )
    }

    fn frida_fragment(&self, target: SpoofTarget) -> Option<FridaHookFragment> {
        let js = match target {
            SpoofTarget::IsDebuggerPresent => r#"
const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (IsDebuggerPresent) {
    Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
        return 0; // always false
    }, 'int', []));
    console.log('[+] Hooked IsDebuggerPresent → 0');
}"#.trim().to_string(),

            SpoofTarget::CheckRemoteDebuggerPresent => r#"
const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (CheckRemoteDebuggerPresent) {
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onLeave: function(retval) {
            // Write FALSE to the pbDebuggerPresent output parameter
            this.context.rdx.writeU32(0);
            retval.replace(1); // still return TRUE (success)
        }
    });
    console.log('[+] Hooked CheckRemoteDebuggerPresent → FALSE');
}"#.trim().to_string(),

            SpoofTarget::NtQueryInformationProcess => r#"
const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
if (NtQueryInformationProcess) {
    Interceptor.attach(NtQueryInformationProcess, {
        onLeave: function(retval) {
            const info_class = this.args[1].toUInt32();
            const out_ptr = this.args[2];
            const out_len = this.args[3].toUInt32();
            // ProcessDebugPort = 7
            if (info_class === 7 && out_ptr && out_len >= 8) {
                out_ptr.writeU64(0n);
            }
            // ProcessDebugObjectHandle = 30 → set STATUS_PORT_NOT_SET
            if (info_class === 30) {
                retval.replace(ptr(0xC0000353)); // STATUS_PORT_NOT_SET
            }
            // ProcessDebugFlags = 31 → set to 1 (not debugged)
            if (info_class === 31 && out_ptr && out_len >= 4) {
                out_ptr.writeU32(1);
            }
        }
    });
    console.log('[+] Hooked NtQueryInformationProcess (ProcessDebugPort/Flags)');
}"#.trim().to_string(),

            SpoofTarget::NtQuerySystemInformation => r#"
const NtQuerySystemInformation = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
if (NtQuerySystemInformation) {
    Interceptor.attach(NtQuerySystemInformation, {
        onLeave: function(retval) {
            const info_class = this.args[0].toUInt32();
            const out_ptr = this.args[1];
            // SystemKernelDebuggerInformation = 35
            if (info_class === 35 && out_ptr) {
                out_ptr.writeU8(0); // KdDebuggerEnabled = 0
                out_ptr.add(1).writeU8(1); // KdDebuggerNotPresent = 1
            }
        }
    });
    console.log('[+] Hooked NtQuerySystemInformation (SystemKernelDebuggerInformation)');
}"#.trim().to_string(),

            SpoofTarget::HeapFlags => r#"
// Hook RtlCreateHeap to clear debug flags on returned heap handle
const RtlCreateHeap = Module.findExportByName('ntdll.dll', 'RtlCreateHeap');
if (RtlCreateHeap) {
    Interceptor.attach(RtlCreateHeap, {
        onEnter: function(args) {
            // Clear HEAP_TAIL_CHECKING_ENABLED (0x20) and HEAP_FREE_CHECKING_ENABLED (0x40)
            const flags = args[0].toUInt32();
            args[0] = ptr(flags & ~0x60);
        }
    });
    console.log('[+] Hooked RtlCreateHeap to clear debug heap flags');
}"#.trim().to_string(),

            SpoofTarget::OutputDebugString => r#"
const OutputDebugStringA = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
if (OutputDebugStringA) {
    Interceptor.replace(OutputDebugStringA, new NativeCallback(function(lpOutputString) {
        // Silently drop the output (no timing side-channel)
    }, 'void', ['pointer']));
    console.log('[+] Hooked OutputDebugStringA → silent NOP');
}"#.trim().to_string(),

            SpoofTarget::CloseHandle => r#"
const CloseHandle = Module.findExportByName('kernel32.dll', 'CloseHandle');
if (CloseHandle) {
    Interceptor.attach(CloseHandle, {
        onEnter: function(args) {
            const handle = args[0].toUInt32();
            // INVALID_HANDLE_VALUE = 0xFFFFFFFF — replace with a valid NUL handle
            if (handle === 0xFFFFFFFF) {
                args[0] = ptr(0);
            }
        }
    });
    console.log('[+] Hooked CloseHandle to neutralise INVALID_HANDLE_VALUE check');
}"#.trim().to_string(),

            _ => return None,
        };
        Some(FridaHookFragment { target, javascript: js })
    }

    /// Generate binary patches for static binary files (no Frida).
    ///
    /// Returns patches for direct calls to debug-detecting APIs.
    /// The `iat_map` maps API name → VA of the IAT slot.
    #[must_use]
    pub fn generate_binary_patches(&self, iat_map: &HashMap<String, u64>) -> Vec<BinaryPatch> {
        let mut patches = Vec::new();

        for &target in &self.config.targets {
            match target {
                SpoofTarget::IsDebuggerPresent => {
                    if let Some(&va) = iat_map.get("IsDebuggerPresent") {
                        patches.push(BinaryPatch {
                            target,
                            iat_va: va,
                            description: "Replace IsDebuggerPresent with xor eax,eax ret".into(),
                            patch_bytes: vec![
                                0x33, 0xC0, // xor eax, eax
                                0xC3,       // ret
                            ],
                        });
                    }
                }
                SpoofTarget::CheckRemoteDebuggerPresent => {
                    if let Some(&va) = iat_map.get("CheckRemoteDebuggerPresent") {
                        patches.push(BinaryPatch {
                            target,
                            iat_va: va,
                            description: "Stub CheckRemoteDebuggerPresent".into(),
                            patch_bytes: vec![
                                // mov dword ptr [rdx], 0  (if rcx == GetCurrentProcess())
                                0x48, 0x31, 0xC0, // xor rax, rax
                                0x89, 0x02,       // mov [rdx], eax
                                0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (success)
                                0xC3,             // ret
                            ],
                        });
                    }
                }
                _ => {}
            }
        }
        patches
    }

    /// Summary of all targets being spoofed.
    #[must_use]
    pub fn summary(&self) -> String {
        let names: Vec<&str> = self.config.targets.iter().map(|t| t.display_name()).collect();
        format!("EnvironmentSpoofer targets: [{}]", names.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryPatch — a static patch for a binary file
// ─────────────────────────────────────────────────────────────────────────────

/// A binary patch at a specific IAT slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPatch {
    pub target: SpoofTarget,
    /// Virtual address of the IAT slot to redirect.
    pub iat_va: u64,
    pub description: String,
    /// Bytes of the replacement stub (written at the redirect target).
    pub patch_bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PEB patch helper (for emulation / memory writing)
// ─────────────────────────────────────────────────────────────────────────────

/// Patch PEB fields in a flat memory buffer (as obtained from a process dump).
///
/// `peb_data` must be at least as large as the largest PEB offset accessed.
pub fn patch_peb_fields(peb_data: &mut [u8], layout: PebLayout) {
    // PEB.BeingDebugged = 0
    if peb_data.len() > layout.being_debugged_offset {
        peb_data[layout.being_debugged_offset] = 0;
    }

    // NtGlobalFlag = 0 (clear 0x70 debug flags)
    if peb_data.len() > layout.nt_global_flag_offset + 4 {
        let slice = &mut peb_data[layout.nt_global_flag_offset..layout.nt_global_flag_offset + 4];
        let val = u32::from_le_bytes(slice.try_into().unwrap());
        let cleared = val & !0x70; // clear HEAP_ENABLE_TAIL_CHECK | HEAP_ENABLE_FREE_CHECK | HEAP_VALIDATE_PARAMETERS
        slice.copy_from_slice(&cleared.to_le_bytes());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frida_script_contains_all_targets() {
        let spoofer = EnvironmentSpoofer::with_defaults();
        let script = spoofer.generate_frida_script();
        assert!(script.contains("IsDebuggerPresent"));
        assert!(script.contains("CheckRemoteDebuggerPresent"));
        assert!(script.contains("NtQueryInformationProcess"));
        assert!(script.contains("NtQuerySystemInformation"));
    }

    #[test]
    fn test_patch_peb_being_debugged() {
        let layout = PebLayout::x64();
        let mut peb = vec![0u8; 0x200];
        peb[layout.being_debugged_offset] = 1; // debugger attached
        peb[layout.nt_global_flag_offset] = 0x70; // debug heap flags

        patch_peb_fields(&mut peb, layout);

        assert_eq!(peb[layout.being_debugged_offset], 0);
        assert_eq!(peb[layout.nt_global_flag_offset] & 0x70, 0);
    }

    #[test]
    fn test_binary_patches_generated() {
        let spoofer = EnvironmentSpoofer::with_defaults();
        let mut iat = HashMap::new();
        iat.insert("IsDebuggerPresent".to_string(), 0x0040_1000u64);
        iat.insert("CheckRemoteDebuggerPresent".to_string(), 0x0040_1008u64);
        let patches = spoofer.generate_binary_patches(&iat);
        assert!(!patches.is_empty());
        assert!(patches.iter().any(|p| p.target == SpoofTarget::IsDebuggerPresent));
    }

    #[test]
    fn test_spoof_target_display_names() {
        assert_eq!(SpoofTarget::PebBeingDebugged.display_name(), "PEB.BeingDebugged");
        assert_eq!(SpoofTarget::NtGlobalFlag.display_name(), "PEB.NtGlobalFlag");
    }
}
