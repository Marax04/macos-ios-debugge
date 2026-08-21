//! `rustre-deobf-antianti` — Anti-anti-analysis detection and patching.
//!
//! Detects anti-debugging, anti-VM, and anti-sandbox techniques in binary
//! data and generates patches or Frida hook scripts to neutralise them.

pub mod anti_analysis_patterns;
pub mod anti_debug_patcher;
pub mod antidbg_bypass;
pub mod bypasser;
pub mod detector;
pub mod environment_spoofer;
pub mod evasion_patterns;
pub mod timing_bypass;
pub mod timing_check_detector;
pub mod timing_patchers;
pub mod vm_check_neutralizer;
pub mod vm_detection;
pub mod vm_detection_bypass;
pub mod timing_attack_neutralizer;
pub mod exception_based_antidebug;
pub mod vm_detection_neutralizer;

use rustre_deobf::{DeobfContext, DeobfError, DeobfPass, DeobfResult, Patch, PatternMatcher};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Anti-debug technique taxonomy
// ─────────────────────────────────────────────────────────────────────────────

/// Windows, Linux, and generic anti-debugging techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiDebugTechnique {
    // ── Windows API ──────────────────────────────────────────────────────────
    /// `kernel32!IsDebuggerPresent` return value check.
    IsDebuggerPresent,
    /// `kernel32!CheckRemoteDebuggerPresent`.
    CheckRemoteDebuggerPresent,
    /// `ntdll!NtQueryInformationProcess` with `ProcessDebugPort` / flags.
    NtQueryInformationProcess,
    /// `kernel32!DebugBreak` call (causes exception when debugger attached).
    DebugBreak,
    /// `kernel32!OutputDebugStringA/W` timing side-channel.
    OutputDebugString,
    /// `CloseHandle(INVALID_HANDLE_VALUE)` — raises exception under debugger.
    CloseInvalidHandle,
    /// PEB `NtGlobalFlag` field set to 0x70 when heap is debug-allocated.
    NtGlobalFlag,
    /// PEB `ProcessHeap.Flags` / `ForceFlags` fields.
    HeapFlags,
    /// Direct `ProcessHeap` field read from PEB.
    ProcessHeap,
    /// PEB `BeingDebugged` flag (byte 2 of PEB).
    BeingDebugged,
    // ── Timing checks ────────────────────────────────────────────────────────
    /// `kernel32!GetTickCount` delta check.
    GetTickCount,
    /// `kernel32!QueryPerformanceCounter` delta check.
    QueryPerformanceCounter,
    /// `RDTSC` instruction — delta between two readings.
    Rdtsc,
    // ── Hardware breakpoints ─────────────────────────────────────────────────
    /// `GetThreadContext` + DR0–DR3 register check.
    HardwareBreakpoints,
    /// Direct DR register read via inline assembly.
    DrRegisterCheck,
    // ── Structural / exception-based ─────────────────────────────────────────
    /// SEH chain manipulation — single-stepping detection.
    SehChain,
    /// Parent process check (`ProcessInheritedFromUniqueProcessId`).
    ParentProcess,
    // ── Linux ────────────────────────────────────────────────────────────────
    /// `/proc/self/status` `TracerPid` field.
    TracerPid,
    /// `ptrace(PTRACE_TRACEME)` call — fails if already traced.
    Ptrace,
    /// `/proc/self/status` full read.
    ProcStatus,
    /// `/proc/self/maps` scan for debugger markers.
    SelfMaps,
    // ── Generic ──────────────────────────────────────────────────────────────
    /// Exception-based single-step / vectored exception handler tricks.
    ExceptionBasedChecks,
    /// Deliberate sleep / `WaitForSingleObject` timing delays.
    TimingDelays,
    // ── Generic timing ───────────────────────────────────────────────────────
    /// Generic timing check covering all timer-based approaches.
    TimingCheck,
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-VM technique taxonomy
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual-machine / hypervisor detection techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiVmTechnique {
    /// `VMware` I/O port `0x5658` ("`VMXh`") backdoor check.
    VmwarePortCheck,
    /// VMware-specific `CPUID` leaf values.
    VmwareCpuid,
    /// `VirtualBox` registry key checks (e.g. `HKLM\HARDWARE\ACPI\DSDT\VBOX__`).
    VboxRegistry,
    /// Hyper-V `CPUID` hypervisor leaf.
    HyperVCpuid,
    /// QEMU / KVM `CPUID` signature check.
    QemuCpuid,
    /// Sandbox-specific file / pipe artefact enumeration.
    SandboxArtifacts,
    /// Suspicious process list scan (e.g. `vboxservice.exe`, `vmtoolsd.exe`).
    SuspiciousProcessList,
    /// Network adapter MAC-address OUI check for VM vendors.
    NetworkAdapterCheck,
    /// `GetSystemInfo` CPU count — VMs often show 1 or 2 cores.
    CpuCountCheck,
    /// Physical disk size query — VMs often have < 100 GB.
    DiskSizeCheck,
    /// System uptime check — fresh VMs have very low uptime.
    UptimeCheck,
    /// Mouse movement / user-interaction detection.
    MouseMovementCheck,
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-sandbox technique taxonomy
// ─────────────────────────────────────────────────────────────────────────────

/// Automated-sandbox and detonation-environment evasion techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiSandboxTechnique {
    /// `Sleep` / `NtDelayExecution` with a large value to outlast analysis.
    SleepSkip,
    /// Click / keyboard-input detection before executing payload.
    UserInteractionCheck,
    /// Recent document / MRU file enumeration to detect fresh VMs.
    RecentFileCheck,
    /// DNS / HTTP connectivity check to determine if network is available.
    NetworkConnectivity,
    /// `GetSystemMetrics` screen-resolution check (sandboxes use small displays).
    ScreenResolution,
    /// Username / computer name check against known sandbox accounts.
    UsernameCheck,
    /// Domain / workgroup check.
    DomainCheck,
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy to use when neutralising a detected check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchStrategy {
    /// Overwrite bytes with `0x90` NOP instructions.
    Nop,
    /// Patch the check so it always evaluates to `false` (not being debugged).
    ForceFalse,
    /// Patch the check so it always evaluates to `true`.
    ForceTrue,
    /// Make the function / inline code return `0`.
    ReturnZero,
    /// Make the function / inline code return `1`.
    ReturnOne,
    /// Skip the entire conditional block (unconditional jump over it).
    SkipBlock,
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature database
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-pattern signature for a known anti-analysis technique.
#[derive(Debug, Clone)]
pub struct TechniqueSignature {
    /// Short identifier.
    pub name: &'static str,
    /// Pattern bytes to match.
    pub pattern: &'static [u8],
    /// Per-byte mask (`0xFF` = exact match, `0x00` = wildcard).
    pub mask: &'static [u8],
    /// Recommended neutralisation strategy.
    pub strategy: PatchStrategy,
    /// Replacement bytes corresponding to the chosen strategy.
    pub patch_bytes: &'static [u8],
}

/// Build the static signature database.
#[must_use]
pub fn signature_database() -> Vec<TechniqueSignature> {
    vec![
        // ── RDTSC ─────────────────────────────────────────────────────────
        TechniqueSignature {
            name: "rdtsc",
            pattern: &[0x0F, 0x31],
            mask: &[0xFF, 0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90],
        },
        // ── PEB BeingDebugged x86 ─────────────────────────────────────────
        // mov eax, fs:[0x30]
        TechniqueSignature {
            name: "peb-being-debugged-x86",
            pattern: &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ForceFalse,
            patch_bytes: &[0x31, 0xC0, 0x90, 0x90, 0x90, 0x90],
        },
        // ── PEB BeingDebugged x64 ─────────────────────────────────────────
        // mov rax, gs:[0x60]
        TechniqueSignature {
            name: "peb-being-debugged-x64",
            pattern: &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ForceFalse,
            patch_bytes: &[0x48, 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // ── NtGlobalFlag x86 ─────────────────────────────────────────────
        // mov eax, fs:[0x68]   (PEB +0x68 = NtGlobalFlag)
        TechniqueSignature {
            name: "nt-global-flag-x86",
            pattern: &[0x64, 0xA1, 0x68, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: &[0x31, 0xC0, 0x90, 0x90, 0x90, 0x90],
        },
        // ── ProcessHeap flags x86 ────────────────────────────────────────
        // mov eax, fs:[0x18]; mov eax,[eax+0x44]  — partial pattern
        TechniqueSignature {
            name: "heap-flags-x86",
            pattern: &[0x64, 0xA1, 0x18, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // ── DebugBreak INT3 ───────────────────────────────────────────────
        TechniqueSignature {
            name: "debug-break-int3",
            pattern: &[0xCC],
            mask: &[0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90],
        },
        // ── CloseHandle(INVALID_HANDLE_VALUE) ────────────────────────────
        // push -1; call [CloseHandle_iat]  (FF 15 ?? ?? ?? ??)
        // Using wildcard mask on the IAT address to avoid false positives
        // from bare `push -1` instructions used in other contexts.
        TechniqueSignature {
            name: "close-invalid-handle",
            pattern: &[0x6A, 0xFF, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // ── VMware I/O port backdoor ──────────────────────────────────────
        // in eax, dx  (0xED) after loading 0x5658 into ebx
        TechniqueSignature {
            name: "vmware-port-backdoor",
            pattern: &[0xB8, 0x58, 0x56, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // ── CPUID hypervisor leaf (leaf 0x40000000) ───────────────────────
        TechniqueSignature {
            name: "cpuid-hypervisor-leaf",
            pattern: &[0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // ── Sleep(large_value) anti-sandbox ──────────────────────────────
        // push 0xEA60 (60 000 ms = 1 minute)
        TechniqueSignature {
            name: "sleep-large-value",
            pattern: &[0x68, 0x60, 0xEA, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: &[0x6A, 0x00, 0x90, 0x90, 0x90],
        },
        // ── SEH-based single-step detection ──────────────────────────────
        // pushf; pop eax; test eax, 0x100 (trap flag)
        TechniqueSignature {
            name: "seh-trap-flag",
            pattern: &[0x9C, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ForceFalse,
            patch_bytes: &[0x90, 0x90, 0x31, 0xC0, 0x90, 0x90, 0x90],
        },
        // ── ptrace(PTRACE_TRACEME) — Linux ────────────────────────────────
        // mov eax, 0x65 (ptrace syscall on x86) or mov rax, 0x65
        TechniqueSignature {
            name: "ptrace-traceme-x86",
            pattern: &[0xB8, 0x65, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: &[0xB8, 0x00, 0x00, 0x00, 0x00],
        },
        // ── GetTickCount timing check pattern ────────────────────────────
        // call GetTickCount; mov edi, eax; call GetTickCount; sub eax, edi
        TechniqueSignature {
            name: "gettickcount-timing",
            pattern: &[0xFF, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            strategy: PatchStrategy::Nop,
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0],
        },
        // ── DR register check via PUSHFD + CONTEXT ────────────────────────
        // DR check signature: cmp dr7/dr0 presence
        TechniqueSignature {
            name: "dr-register-check",
            pattern: &[0x0F, 0x21, 0xC0], // mov eax, dr0
            mask: &[0xFF, 0xFF, 0xF8],    // wildcard lower 3 bits (any DR reg)
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: &[0x31, 0xC0, 0x90],
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection context
// ─────────────────────────────────────────────────────────────────────────────

/// A detected anti-analysis technique with its location and recommended patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisHit {
    /// Name taken from the matching signature.
    pub name: String,
    /// Byte offset in the binary.
    pub offset: usize,
    /// Bytes found at the match site.
    pub found_bytes: Vec<u8>,
    /// Recommended patch strategy.
    pub strategy: PatchStrategy,
    /// Replacement bytes for byte-patch strategies.
    pub patch_bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiAntiPass
// ─────────────────────────────────────────────────────────────────────────────

/// A [`DeobfPass`] that detects and patches anti-analysis mechanisms.
pub struct AntiAntiPass {
    /// Compiled pattern matcher built from the signature database.
    matcher: PatternMatcher,
    /// The raw signatures (kept for patch-byte lookup).
    signatures: Vec<TechniqueSignature>,
    /// Minimum binary size before the pass is considered applicable.
    min_size: usize,
    /// Also scan for string-literal import references (API names in binary).
    scan_strings: bool,
}

impl AntiAntiPass {
    /// Create an [`AntiAntiPass`] loaded with the default signature database.
    #[must_use]
    pub fn new() -> Self {
        let signatures = signature_database();
        let mut matcher = PatternMatcher::new();
        for sig in &signatures {
            matcher.add_masked_pattern(sig.name, sig.pattern.to_vec(), sig.mask.to_vec());
        }
        Self {
            matcher,
            signatures,
            min_size: 4,
            scan_strings: true,
        }
    }

    /// Configure whether to scan for import-name string literals.
    #[must_use]
    pub const fn with_string_scan(mut self, enabled: bool) -> Self {
        self.scan_strings = enabled;
        self
    }

    /// Scan `data` and return all hits.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<AntiAnalysisHit> {
        let mut hits: Vec<AntiAnalysisHit> = Vec::new();

        // Pattern-match hits.
        for m in self.matcher.scan(data) {
            if let Some(sig) = self.signatures.iter().find(|s| s.name == m.name) {
                hits.push(AntiAnalysisHit {
                    name: m.name.clone(),
                    offset: m.offset,
                    found_bytes: m.bytes.clone(),
                    strategy: sig.strategy,
                    patch_bytes: sig.patch_bytes.to_vec(),
                });
            }
        }

        // String-literal API name scan (import table / data sections).
        if self.scan_strings {
            hits.extend(self.scan_api_strings(data));
        }

        hits
    }

    fn scan_api_strings(&self, data: &[u8]) -> Vec<AntiAnalysisHit> {
        let apis: &[(&[u8], &str, PatchStrategy)] = &[
            (
                b"IsDebuggerPresent",
                "api-IsDebuggerPresent",
                PatchStrategy::ReturnZero,
            ),
            (
                b"CheckRemoteDebuggerPresent",
                "api-CheckRemoteDebuggerPresent",
                PatchStrategy::ReturnZero,
            ),
            (
                b"NtQueryInformationProcess",
                "api-NtQueryInformationProcess",
                PatchStrategy::ReturnZero,
            ),
            (
                b"OutputDebugStringA",
                "api-OutputDebugStringA",
                PatchStrategy::Nop,
            ),
            (
                b"OutputDebugStringW",
                "api-OutputDebugStringW",
                PatchStrategy::Nop,
            ),
            (
                b"VirtualBoxService",
                "api-VboxService",
                PatchStrategy::ForceFalse,
            ),
            (b"VBoxHook.dll", "api-VBoxHook", PatchStrategy::ForceFalse),
            (b"vmtoolsd.exe", "api-vmtoolsd", PatchStrategy::ForceFalse),
            (b"sbiedll.dll", "api-sbiedll", PatchStrategy::ForceFalse),
            (b"TracerPid", "api-TracerPid", PatchStrategy::ForceFalse),
            (b"VBoxMouse.sys", "api-VBoxMouse", PatchStrategy::ForceFalse),
        ];
        let mut hits = Vec::new();
        for (sig, name, strategy) in apis {
            let mut pos = 0;
            while pos + sig.len() <= data.len() {
                if &data[pos..pos + sig.len()] == *sig {
                    hits.push(AntiAnalysisHit {
                        name: (*name).to_owned(),
                        offset: pos,
                        found_bytes: sig.to_vec(),
                        strategy: *strategy,
                        patch_bytes: vec![],
                    });
                    pos += sig.len();
                } else {
                    pos += 1;
                }
            }
        }
        hits
    }
}

impl Default for AntiAntiPass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeobfPass for AntiAntiPass {
    fn name(&self) -> &'static str {
        "anti-anti-analysis"
    }

    fn description(&self) -> &'static str {
        "Detects and patches anti-debugging, anti-VM, and anti-sandbox techniques"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= self.min_size
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let hits = self.scan(&ctx.binary);
        let mut patches_applied = 0usize;
        let mut modified_bytes = 0usize;
        let mut transformations = Vec::new();

        for hit in &hits {
            if hit.patch_bytes.is_empty() {
                // String-literal hit — no binary patch, but record transformation.
                transformations.push(format!("detected {} at offset {:#x}", hit.name, hit.offset));
                continue;
            }
            let end = hit.offset + hit.patch_bytes.len();
            if end > ctx.binary.len() {
                continue;
            }
            let original = ctx.binary[hit.offset..end].to_vec();
            let patch = Patch::new(
                hit.offset,
                original,
                hit.patch_bytes.clone(),
                format!("neutralised {} ({:?})", hit.name, hit.strategy),
            );
            modified_bytes += hit.patch_bytes.len();
            ctx.patches.push(patch);
            patches_applied += 1;
            transformations.push(format!("patched {} at offset {:#x}", hit.name, hit.offset));
        }

        let confidence = if hits.is_empty() {
            0.0
        } else {
            0.85
        };
        Ok(DeobfResult::new(
            patches_applied,
            transformations,
            modified_bytes,
            confidence,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Frida script generator (kept for compatibility / tooling integration)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a Frida hook script targeting the detected anti-analysis techniques.
#[must_use]
pub fn generate_frida_script(hits: &[AntiAnalysisHit]) -> String {
    let mut script = String::from(
        "// Frida hook script — generated by rustre-deobf-antianti\n\
         // Automatically neutralises detected anti-analysis checks.\n\n",
    );

    let has = |name: &str| hits.iter().any(|h| h.name.contains(name));

    if has("IsDebuggerPresent") {
        script.push_str(
            "Interceptor.attach(Module.findExportByName(null, 'IsDebuggerPresent'), {\n\
             \tonLeave(retval) { retval.replace(ptr(0)); }\n\
             });\n\n",
        );
    }
    if has("CheckRemoteDebuggerPresent") {
        script.push_str(
            "Interceptor.attach(Module.findExportByName(null, 'CheckRemoteDebuggerPresent'), {\n\
             \tonLeave(retval) { retval.replace(ptr(0)); }\n\
             });\n\n",
        );
    }
    if has("NtQueryInformationProcess") {
        script.push_str(
            "Interceptor.attach(Module.findExportByName(null, 'NtQueryInformationProcess'), {\n\
             \tonEnter(args) {\n\
             \t\tthis.cls = args[1].toInt32();\n\
             \t\tthis.buf = args[2];\n\
             \t},\n\
             \tonLeave(retval) {\n\
             \t\tif (retval.toInt32() === 0 && this.buf) {\n\
             \t\t\tif (this.cls === 7 || this.cls === 30) this.buf.writePointer(ptr(0));\n\
             \t\t\tif (this.cls === 31) this.buf.writeU32(1);\n\
             \t\t}\n\
             \t}\n\
             });\n\n",
        );
    }
    if has("rdtsc") || has("Rdtsc") {
        script.push_str(
            "// RDTSC timing: consider using Frida Stalker to replace RDTSC with constant.\n\n",
        );
    }
    if has("peb") || has("BeingDebugged") {
        script.push_str(
            "// Clear PEB.BeingDebugged at process startup.\n\
             const teb = NativeFunction(Module.findExportByName('ntdll', 'NtCurrentTeb'), 'pointer', [])();
\n             const peb = teb.add(Process.pointerSize === 8 ? 0x60 : 0x30).readPointer();
\n             Memory.writeU8(peb.add(2), 0); // clear BeingDebugged

",
        );
    }
    script
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugDetector — higher-level detector for anti-debug techniques
// ─────────────────────────────────────────────────────────────────────────────

/// A detection result for a specific anti-debug technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugDetection {
    /// The detected technique.
    pub technique: AntiDebugTechnique,
    /// File offset of the detection.
    pub offset: usize,
    /// Confidence in [0, 100].
    pub confidence: u32,
    /// Description of what was found.
    pub description: String,
}

impl AntiDebugDetection {
    /// Create a new [`AntiDebugDetection`].
    #[must_use]
    pub fn new(
        technique: AntiDebugTechnique,
        offset: usize,
        confidence: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            offset,
            confidence: confidence.min(100),
            description: description.into(),
        }
    }

    /// Return `true` if confidence is high.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

/// Detects anti-debug techniques in binary data.
#[derive(Debug, Clone, Default)]
pub struct AntiDebugDetector;

impl AntiDebugDetector {
    /// Create a new [`AntiDebugDetector`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for anti-debug techniques and return all detections.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<AntiDebugDetection> {
        let mut detections = Vec::new();

        // RDTSC (0F 31)
        self.scan_pattern(
            data,
            &[0x0F, 0x31],
            &[0xFF, 0xFF],
            AntiDebugTechnique::Rdtsc,
            "RDTSC instruction",
            90,
            &mut detections,
        );

        // PEB BeingDebugged (x86)
        self.scan_pattern(
            data,
            &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            AntiDebugTechnique::BeingDebugged,
            "PEB BeingDebugged x86",
            95,
            &mut detections,
        );

        // PEB BeingDebugged (x64)
        self.scan_pattern(
            data,
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            AntiDebugTechnique::BeingDebugged,
            "PEB BeingDebugged x64",
            95,
            &mut detections,
        );

        // INT3 (0xCC) — debug break
        self.scan_pattern(
            data,
            &[0xCC],
            &[0xFF],
            AntiDebugTechnique::DebugBreak,
            "INT3 breakpoint",
            70,
            &mut detections,
        );

        // ptrace(PTRACE_TRACEME) syscall on x86 Linux
        self.scan_pattern(
            data,
            &[0xB8, 0x65, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            AntiDebugTechnique::Ptrace,
            "ptrace(PTRACE_TRACEME) x86",
            85,
            &mut detections,
        );

        // NtGlobalFlag
        self.scan_pattern(
            data,
            &[0x64, 0xA1, 0x68, 0x00, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            AntiDebugTechnique::NtGlobalFlag,
            "PEB NtGlobalFlag",
            90,
            &mut detections,
        );

        // DR register read (mov eax, dr0–7)
        self.scan_pattern(
            data,
            &[0x0F, 0x21, 0xC0],
            &[0xFF, 0xFF, 0xF8],
            AntiDebugTechnique::DrRegisterCheck,
            "DR register read",
            85,
            &mut detections,
        );

        // PUSHFD + test trap flag
        self.scan_pattern(
            data,
            &[0x9C, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            AntiDebugTechnique::SehChain,
            "SEH trap-flag check",
            80,
            &mut detections,
        );

        // IsDebuggerPresent string
        self.scan_string(
            data,
            b"IsDebuggerPresent",
            AntiDebugTechnique::IsDebuggerPresent,
            "IsDebuggerPresent import",
            75,
            &mut detections,
        );

        // NtQueryInformationProcess string
        self.scan_string(
            data,
            b"NtQueryInformationProcess",
            AntiDebugTechnique::NtQueryInformationProcess,
            "NtQueryInformationProcess import",
            80,
            &mut detections,
        );

        // TracerPid (Linux)
        self.scan_string(
            data,
            b"TracerPid",
            AntiDebugTechnique::TracerPid,
            "TracerPid string",
            85,
            &mut detections,
        );

        detections
    }

    fn scan_pattern(
        &self,
        data: &[u8],
        pattern: &[u8],
        mask: &[u8],
        technique: AntiDebugTechnique,
        desc: &str,
        confidence: u32,
        out: &mut Vec<AntiDebugDetection>,
    ) {
        let mut pos = 0;
        while pos + pattern.len() <= data.len() {
            let matches = pattern
                .iter()
                .enumerate()
                .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
            if matches {
                out.push(AntiDebugDetection::new(technique, pos, confidence, desc));
                pos += pattern.len();
            } else {
                pos += 1;
            }
        }
    }

    fn scan_string(
        &self,
        data: &[u8],
        needle: &[u8],
        technique: AntiDebugTechnique,
        desc: &str,
        confidence: u32,
        out: &mut Vec<AntiDebugDetection>,
    ) {
        let mut pos = 0;
        while pos + needle.len() <= data.len() {
            if &data[pos..pos + needle.len()] == needle {
                out.push(AntiDebugDetection::new(technique, pos, confidence, desc));
                pos += needle.len();
            } else {
                pos += 1;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiVmDetector — detects VM/hypervisor evasion techniques
// ─────────────────────────────────────────────────────────────────────────────

/// A detection result for a VM-evasion technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiVmDetection {
    /// The detected technique.
    pub technique: AntiVmTechnique,
    /// File offset.
    pub offset: usize,
    /// Confidence in [0, 100].
    pub confidence: u32,
    /// Description.
    pub description: String,
}

impl AntiVmDetection {
    /// Create a new [`AntiVmDetection`].
    #[must_use]
    pub fn new(
        technique: AntiVmTechnique,
        offset: usize,
        confidence: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            offset,
            confidence: confidence.min(100),
            description: description.into(),
        }
    }

    /// Return `true` if confidence ≥ 75.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

/// Detects VM / hypervisor evasion techniques.
#[derive(Debug, Clone, Default)]
pub struct AntiVmDetector;

impl AntiVmDetector {
    /// Create a new [`AntiVmDetector`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for VM-evasion techniques.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<AntiVmDetection> {
        let mut detections = Vec::new();

        // VMware port backdoor: mov eax, "VMXh" = 0x564D5868
        for pos in find_all_bytes(data, &[0xB8, 0x58, 0x56, 0x00, 0x00]) {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::VmwarePortCheck,
                pos,
                90,
                "VMware port backdoor",
            ));
        }

        // CPUID hypervisor leaf 0x40000000
        for pos in find_all_bytes(data, &[0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2]) {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::VmwareCpuid,
                pos,
                85,
                "CPUID hypervisor leaf 0x40000000",
            ));
        }

        // VirtualBox registry key string
        for pos in find_all_bytes(data, b"VBoxHook.dll") {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::VboxRegistry,
                pos,
                90,
                "VirtualBox hook DLL string",
            ));
        }
        for pos in find_all_bytes(data, b"VBoxMouse.sys") {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::VboxRegistry,
                pos,
                90,
                "VirtualBox mouse driver string",
            ));
        }

        // VMware tools strings
        for pos in find_all_bytes(data, b"vmtoolsd.exe") {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::VmwarePortCheck,
                pos,
                80,
                "VMware tools process name",
            ));
        }

        // Sandboxie DLL
        for pos in find_all_bytes(data, b"sbiedll.dll") {
            detections.push(AntiVmDetection::new(
                AntiVmTechnique::SandboxArtifacts,
                pos,
                90,
                "Sandboxie DLL string",
            ));
        }

        detections
    }
}

fn find_all_bytes(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut pos = 0usize;
    while pos + needle.len() <= haystack.len() {
        if &haystack[pos..pos + needle.len()] == needle {
            results.push(pos);
            pos += needle.len();
        } else {
            pos += 1;
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Bypass — describes a bypass action for an anti-analysis check
// ─────────────────────────────────────────────────────────────────────────────

/// A single bypass action to neutralise a detected check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bypass {
    /// Human-readable name.
    pub name: String,
    /// Target binary offset.
    pub offset: usize,
    /// Patch bytes to apply.
    pub patch_bytes: Vec<u8>,
    /// Strategy employed.
    pub strategy: PatchStrategy,
    /// Estimated effectiveness in [0, 100].
    pub effectiveness: u32,
}

impl Bypass {
    /// Create a new [`Bypass`].
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        offset: usize,
        patch_bytes: Vec<u8>,
        strategy: PatchStrategy,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            patch_bytes,
            strategy,
            effectiveness: 80,
        }
    }

    /// Set effectiveness and return `self`.
    #[must_use]
    pub fn with_effectiveness(mut self, eff: u32) -> Self {
        self.effectiveness = eff.min(100);
        self
    }

    /// Return `true` if this bypass is highly effective.
    #[must_use]
    pub const fn is_effective(&self) -> bool {
        self.effectiveness >= 70
    }

    /// Convert this bypass into a [`Patch`].
    #[must_use]
    pub fn to_patch(&self, original: Vec<u8>) -> Patch {
        Patch::new(
            self.offset,
            original,
            self.patch_bytes.clone(),
            self.name.clone(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiAnalysisTechnique — unified enum over all technique kinds
// ─────────────────────────────────────────────────────────────────────────────

/// A unified view of any anti-analysis technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiAnalysisTechnique {
    /// An anti-debug technique.
    Debug(AntiDebugTechnique),
    /// A VM-evasion technique.
    Vm(AntiVmTechnique),
    /// A sandbox-evasion technique.
    Sandbox(AntiSandboxTechnique),
}

impl AntiAnalysisTechnique {
    /// Return a human-readable category label.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Debug(_) => "anti-debug",
            Self::Vm(_) => "anti-vm",
            Self::Sandbox(_) => "anti-sandbox",
        }
    }

    /// Return `true` if this is an anti-debug technique.
    #[must_use]
    pub const fn is_anti_debug(self) -> bool {
        matches!(self, Self::Debug(_))
    }

    /// Return `true` if this is a VM-evasion technique.
    #[must_use]
    pub const fn is_anti_vm(self) -> bool {
        matches!(self, Self::Vm(_))
    }

    /// Return `true` if this is a sandbox-evasion technique.
    #[must_use]
    pub const fn is_anti_sandbox(self) -> bool {
        matches!(self, Self::Sandbox(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingBypassSimulator
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates timing-based bypass strategies.
#[derive(Debug, Clone)]
pub struct TimingBypassSimulator {
    /// Constant value to return from timing APIs (e.g., `GetTickCount`).
    pub constant_tick: u32,
    /// Constant `RDTSC` value pair `(low, high)`.
    pub constant_rdtsc: (u32, u32),
}

impl Default for TimingBypassSimulator {
    fn default() -> Self {
        Self {
            constant_tick: 0x1234,
            constant_rdtsc: (0x1234_5678, 0),
        }
    }
}

impl TimingBypassSimulator {
    /// Create a new [`TimingBypassSimulator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a Frida hook snippet that replaces `GetTickCount` with a constant.
    #[must_use]
    pub fn frida_gettickcount_hook(&self) -> String {
        format!(
            "Interceptor.attach(Module.findExportByName(null, 'GetTickCount'), {{\n\
             \tonLeave(retval) {{ retval.replace({:#x}); }}\n\
             }});\n",
            self.constant_tick
        )
    }

    /// Generate a Frida Stalker-based hook to replace RDTSC with a constant.
    #[must_use]
    pub fn frida_rdtsc_stalker_snippet(&self) -> String {
        let (lo, hi) = self.constant_rdtsc;
        format!(
            "// Stalker RDTSC replacement — insert into Stalker.follow transform.\n\
             // Replace 0F 31 with: mov eax, {lo:#x}; mov edx, {hi:#x}\n\
             const rdtscBytes = [0x0F, 0x31];\n\
             if (instr.mnemonic === 'rdtsc') {{\n\
             \twriter.putMovRegU32('eax', {lo:#x});\n\
             \twriter.putMovRegU32('edx', {hi:#x});\n\
             }}\n"
        )
    }

    /// Compute how many bytes a RDTSC + delta check typically spans.
    #[must_use]
    pub const fn estimated_rdtsc_check_bytes() -> usize {
        // 2 (rdtsc) + 2 (mov edi,eax) + 2 (rdtsc) + 2 (sub eax,edi) + some compare
        12
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BypassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry of known bypasses keyed by technique signature name.
#[derive(Debug, Clone, Default)]
pub struct BypassRegistry {
    bypasses: std::collections::HashMap<String, Vec<Bypass>>,
}

impl BypassRegistry {
    /// Create an empty [`BypassRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a bypass for a technique name.
    pub fn register(&mut self, technique: impl Into<String>, bypass: Bypass) {
        self.bypasses
            .entry(technique.into())
            .or_default()
            .push(bypass);
    }

    /// Retrieve all bypasses for a given technique name.
    #[must_use]
    pub fn get(&self, technique: &str) -> &[Bypass] {
        self.bypasses
            .get(technique)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Total number of registered bypasses.
    #[must_use]
    pub fn total(&self) -> usize {
        self.bypasses.values().map(std::vec::Vec::len).sum()
    }

    /// Return `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bypasses.is_empty()
    }

    /// Return all technique names that have at least one bypass.
    #[must_use]
    pub fn techniques(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.bypasses.keys().map(std::string::String::as_str).collect();
        names.sort_unstable();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SleepPatcher — patches Sleep-based sandbox evasion
// ─────────────────────────────────────────────────────────────────────────────

/// Patches `Sleep` calls with large arguments to use zero delay.
#[derive(Debug, Clone, Default)]
pub struct SleepPatcher {
    /// Minimum sleep duration (ms) to consider suspicious.
    pub threshold_ms: u32,
}

impl SleepPatcher {
    /// Create a new [`SleepPatcher`] with the given threshold.
    #[must_use]
    pub const fn new(threshold_ms: u32) -> Self {
        Self { threshold_ms }
    }

    /// Scan `data` for `push <large_dword>; call Sleep` patterns.
    ///
    /// Returns `(offset, pushed_value)` pairs for suspicious pushes.
    #[must_use]
    pub fn scan_large_sleeps(&self, data: &[u8]) -> Vec<(usize, u32)> {
        let mut results = Vec::new();
        let mut i = 0;
        while i + 5 <= data.len() {
            // push imm32 = 0x68 ++ 4 bytes
            if data[i] == 0x68 {
                let val = u32::from_le_bytes(data[i + 1..i + 5].try_into().unwrap());
                if val >= self.threshold_ms {
                    results.push((i, val));
                }
            }
            i += 1;
        }
        results
    }

    /// Generate NOP-patch bypasses for large Sleep calls.
    #[must_use]
    pub fn generate_bypasses(&self, data: &[u8]) -> Vec<Bypass> {
        self.scan_large_sleeps(data)
            .into_iter()
            .map(|(offset, val)| {
                // Replace `push <large_val>` with `push 0` (6A 00) + 3 NOPs.
                Bypass::new(
                    format!("sleep-patch-{val}ms"),
                    offset,
                    vec![0x6A, 0x00, 0x90, 0x90, 0x90],
                    PatchStrategy::ReturnZero,
                )
                .with_effectiveness(95)
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisReport — comprehensive report from all detectors
// ─────────────────────────────────────────────────────────────────────────────

/// Comprehensive anti-analysis report produced by running all detectors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Anti-debug detections.
    pub anti_debug: Vec<AntiDebugDetection>,
    /// Anti-VM detections.
    pub anti_vm: Vec<AntiVmDetection>,
    /// Total detections.
    pub total_detections: usize,
    /// Summary string.
    pub summary: String,
}

impl AnalysisReport {
    /// Create a new empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all detectors on `data` and populate the report.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let anti_debug = AntiDebugDetector::new().scan(data);
        let anti_vm = AntiVmDetector::new().scan(data);
        let total = anti_debug.len() + anti_vm.len();
        let summary = format!(
            "{} anti-debug + {} anti-VM detections ({} total)",
            anti_debug.len(),
            anti_vm.len(),
            total
        );
        Self {
            anti_debug,
            anti_vm,
            total_detections: total,
            summary,
        }
    }

    /// Return `true` if any technique was detected.
    #[must_use]
    pub const fn has_detections(&self) -> bool {
        self.total_detections > 0
    }

    /// Return only high-confidence anti-debug detections.
    #[must_use]
    pub fn high_confidence_debug(&self) -> Vec<&AntiDebugDetection> {
        self.anti_debug
            .iter()
            .filter(|d| d.is_high_confidence())
            .collect()
    }

    /// Return only high-confidence anti-VM detections.
    #[must_use]
    pub fn high_confidence_vm(&self) -> Vec<&AntiVmDetection> {
        self.anti_vm
            .iter()
            .filter(|d| d.is_high_confidence())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugSignatureDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the anti-debug signature database.
#[derive(Debug, Clone)]
pub struct AntiDebugSig {
    /// Short human-readable name (e.g. `"IsDebuggerPresent"`).
    pub name: &'static str,
    /// Raw byte pattern to match (exact bytes, not masked).
    pub bytes_pattern: Vec<u8>,
    /// Per-byte mask: `0xFF` = exact match, `0x00` = any byte, other = bitmask.
    pub mask: Vec<u8>,
    /// Human-readable description of the technique.
    pub description: &'static str,
}

impl AntiDebugSig {
    /// Create a new signature with equal-length pattern and mask.
    ///
    /// # Panics
    /// Panics in debug mode if `bytes_pattern.len() != mask.len()`.
    #[must_use]
    pub fn new(
        name: &'static str,
        bytes_pattern: Vec<u8>,
        mask: Vec<u8>,
        description: &'static str,
    ) -> Self {
        assert_eq!(
            bytes_pattern.len(),
            mask.len(),
            "pattern and mask must have equal length for signature '{name}'"
        );
        Self {
            name,
            bytes_pattern,
            mask,
            description,
        }
    }
}

/// A hit produced by [`AntiDebugSignatureDatabase::scan_for_anti_debug`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugMatch {
    /// Signature name.
    pub sig_name: String,
    /// Byte offset of the match in the input buffer.
    pub offset: usize,
    /// Confidence score in `[0, 100]`.
    pub confidence: u32,
}

/// A database of 15+ binary patterns for known anti-debug / anti-analysis
/// tricks, covering both Windows and Linux techniques.
///
/// Usage:
/// ```rust,no_run
/// use rustre_deobf_antianti::AntiDebugSignatureDatabase;
/// let db = AntiDebugSignatureDatabase::new();
/// let code = &[0x0F, 0x31_u8]; // RDTSC
/// let matches = db.scan_for_anti_debug(code);
/// assert!(!matches.is_empty());
/// ```
pub struct AntiDebugSignatureDatabase {
    sigs: Vec<AntiDebugSig>,
}

impl AntiDebugSignatureDatabase {
    /// Create a new database pre-populated with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sigs: Self::build(),
        }
    }

    /// Return a reference to all signatures in the database.
    #[must_use]
    pub fn signatures(&self) -> &[AntiDebugSig] {
        &self.sigs
    }

    /// Scan `bytes` for all known anti-debug patterns.
    ///
    /// Returns a [`AntiDebugMatch`] for every hit, sorted by offset.
    #[must_use]
    pub fn scan_for_anti_debug(&self, bytes: &[u8]) -> Vec<AntiDebugMatch> {
        let mut matches = Vec::new();
        for sig in &self.sigs {
            let pat = &sig.bytes_pattern;
            let msk = &sig.mask;
            let plen = pat.len();
            if plen == 0 {
                continue;
            }
            let mut pos = 0usize;
            while pos + plen <= bytes.len() {
                let hit = pat
                    .iter()
                    .enumerate()
                    .all(|(i, &p)| msk[i] == 0x00 || (bytes[pos + i] & msk[i]) == (p & msk[i]));
                if hit {
                    matches.push(AntiDebugMatch {
                        sig_name: sig.name.to_string(),
                        offset: pos,
                        confidence: self.confidence_for(sig),
                    });
                    pos += plen;
                } else {
                    pos += 1;
                }
            }
        }
        matches.sort_by_key(|m| m.offset);
        matches
    }

    /// Return a confidence score in `[0, 100]` for `sig`.
    ///
    /// Longer, more specific patterns get higher scores.
    fn confidence_for(&self, sig: &AntiDebugSig) -> u32 {
        let specificity = sig
            .bytes_pattern
            .iter()
            .zip(&sig.mask)
            .filter(|&(_, m)| *m == 0xFF)
            .count();
        // Base: 60 + 3 per exact byte, capped at 97.
        (60 + specificity * 3).min(97) as u32
    }

    /// Build the complete signature list.
    fn build() -> Vec<AntiDebugSig> {
        vec![
            // 1. IsDebuggerPresent — indirect call via import table (x86)
            //    FF 15 xx xx xx xx  = CALL DWORD PTR [imm32]
            AntiDebugSig::new(
                "IsDebuggerPresent-call",
                vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                "Indirect call via import table (CALL [addr]); typical IsDebuggerPresent call site",
            ),
            // 2. CheckRemoteDebuggerPresent — same indirect-call pattern but
            //    followed by test al,al (84 C0)
            AntiDebugSig::new(
                "CheckRemoteDebuggerPresent-testresult",
                vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0],
                vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
                "Indirect call + TEST AL,AL; matches CheckRemoteDebuggerPresent result check",
            ),
            // 3. NtQueryInformationProcess with ProcessDebugPort (class=7)
            //    push 0 (result len ptr); push 4; push 7; ...
            AntiDebugSig::new(
                "NtQueryInfoProcess-ProcessDebugPort",
                vec![0x6A, 0x00, 0x6A, 0x04, 0x6A, 0x07],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "push 0; push 4; push 7 (ProcessDebugPort=7) before NtQueryInformationProcess",
            ),
            // 4. CloseHandle with INVALID_HANDLE_VALUE (-1) — raises exception under debugger
            //    push 0xFFFFFFFF
            AntiDebugSig::new(
                "CloseInvalidHandle",
                vec![0x6A, 0xFF],
                vec![0xFF, 0xFF],
                "push -1 (INVALID_HANDLE_VALUE) before CloseHandle call",
            ),
            // 5. PEB BeingDebugged x86 — mov eax, fs:[30h]
            AntiDebugSig::new(
                "PEB-BeingDebugged-x86",
                vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov eax, fs:[0x30] — read PEB pointer (x86); check BeingDebugged at PEB+2",
            ),
            // 6. PEB BeingDebugged x64 — mov rax, gs:[60h]
            AntiDebugSig::new(
                "PEB-BeingDebugged-x64",
                vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov rax, gs:[0x60] — read PEB pointer (x64)",
            ),
            // 7. NtGlobalFlag x86 — mov eax, fs:[68h] (PEB+0x68)
            AntiDebugSig::new(
                "NtGlobalFlag-x86",
                vec![0x64, 0xA1, 0x68, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov eax, fs:[0x68] — read NtGlobalFlag from PEB; 0x70 when heap-debug",
            ),
            // 8. Heap flags check — mov eax, fs:[18h] (TEB.ProcessEnvironmentBlock
            //    → TEB+0x18 on x86 is the PEB pointer via NtCurrentTeb approach)
            AntiDebugSig::new(
                "HeapFlags-x86",
                vec![0x64, 0xA1, 0x18, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov eax, fs:[0x18] — TEB access; followed by heap Flags check",
            ),
            // 9. TLS callback detection — test for non-zero in TLS directory
            //    mov ecx, [something]; test ecx, ecx pattern near TLS
            AntiDebugSig::new(
                "TLS-callback-check",
                vec![0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC9],
                vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
                "mov ecx, [addr]; test ecx,ecx — TLS callback null-check pattern",
            ),
            // 10. RDTSC timing attack — 0F 31
            AntiDebugSig::new(
                "RDTSC-timing",
                vec![0x0F, 0x31],
                vec![0xFF, 0xFF],
                "RDTSC instruction — read TSC for timing delta between two readings",
            ),
            // 11. INT 3 timing attack — single-step detection via CC CC
            AntiDebugSig::new(
                "INT3-timing",
                vec![0xCC, 0xCC],
                vec![0xFF, 0xFF],
                "Two consecutive INT3 (0xCC) — double breakpoint / timing trick",
            ),
            // 12. OutputDebugString error trick
            //    After OutputDebugStringA, GetLastError should be 0 under debugger
            //    call OutputDebugStringA (E8/FF), then call GetLastError
            AntiDebugSig::new(
                "OutputDebugString-error-trick",
                vec![0xFF, 0xD0, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                "call eax (OutputDebugString stub); indirect call [addr] (GetLastError pattern)",
            ),
            // 13. DR register read — mov eax/ecx/edx/ebx, DRn (MOV Rd, Dn)
            //    Opcode: 0F 21 /r   (ModRM bits 5:3 = DR index)
            AntiDebugSig::new(
                "DR-register-read",
                vec![0x0F, 0x21, 0xC0],
                vec![0xFF, 0xFF, 0xF8], // lower 3 bits = general reg, don't care
                "mov reg, dr0-7 — hardware breakpoint register read",
            ),
            // 14. SEH trap-flag check — pushfd; pop eax; test eax, 100h
            AntiDebugSig::new(
                "SEH-trap-flag",
                vec![0x9C, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "pushfd; pop eax; test eax, 0x100 — trap flag (single-step) check",
            ),
            // 15. ptrace(PTRACE_TRACEME) Linux x86 — mov eax, 0x65
            AntiDebugSig::new(
                "ptrace-TRACEME-x86",
                vec![0xB8, 0x65, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov eax, 0x65 — syscall number for ptrace on Linux x86",
            ),
            // 16. GetTickCount timing — call via eax; save; call again; subtract
            //    call eax (FF D0); mov edi, eax (8B F8); call eax (FF D0); sub eax, edi (2B C7)
            AntiDebugSig::new(
                "GetTickCount-timing",
                vec![0xFF, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "call eax; mov edi,eax; call eax; sub eax,edi — GetTickCount delta timing check",
            ),
            // 17. QueryPerformanceCounter — CALL [imm32]; compare result
            //    lea ecx, [esp+local]; push ecx; FF 15 xx xx xx xx
            AntiDebugSig::new(
                "QueryPerformanceCounter-call",
                vec![0x51, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                "push ecx; CALL [addr] — QueryPerformanceCounter call site pattern",
            ),
            // 18. VMware port backdoor — mov eax, 0x564D5868 ("VMXh")
            AntiDebugSig::new(
                "VMware-port-magic",
                vec![0xB8, 0x68, 0x58, 0x4D, 0x56],
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                "mov eax, 0x564D5868 ('VMXh') — VMware I/O port backdoor magic value",
            ),
        ]
    }
}

impl Default for AntiDebugSignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_deobf::DeobfContext;

    // ── Signature database ───────────────────────────────────────────────────

    #[test]
    fn test_signature_database_non_empty() {
        assert!(!signature_database().is_empty());
    }

    #[test]
    fn test_signature_pattern_mask_lengths_match() {
        for sig in signature_database() {
            assert_eq!(
                sig.pattern.len(),
                sig.mask.len(),
                "signature '{}': pattern/mask length mismatch",
                sig.name
            );
            assert_eq!(
                sig.pattern.len(),
                sig.patch_bytes.len(),
                "signature '{}': pattern/patch_bytes length mismatch",
                sig.name
            );
        }
    }

    // ── Pattern detection ────────────────────────────────────────────────────

    #[test]
    fn test_detect_rdtsc() {
        let data = vec![0x90, 0x0F, 0x31, 0x90];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(
            hits.iter().any(|h| h.name == "rdtsc"),
            "should detect RDTSC"
        );
    }

    #[test]
    fn test_detect_peb_x86() {
        let data = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("peb")));
    }

    #[test]
    fn test_detect_peb_x64() {
        let data = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("peb")));
    }

    #[test]
    fn test_detect_api_string_idp() {
        let data = b"IsDebuggerPresent";
        let pass = AntiAntiPass::new();
        let hits = pass.scan(data);
        assert!(hits.iter().any(|h| h.name.contains("IsDebuggerPresent")));
    }

    #[test]
    fn test_detect_api_string_nqip() {
        let data = b"NtQueryInformationProcess";
        let pass = AntiAntiPass::new();
        let hits = pass.scan(data);
        assert!(
            hits.iter()
                .any(|h| h.name.contains("NtQueryInformationProcess"))
        );
    }

    #[test]
    fn test_detect_vmware_port() {
        let data = vec![0x90, 0xB8, 0x58, 0x56, 0x00, 0x00, 0x90];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("vmware")));
    }

    #[test]
    fn test_detect_cpuid_hypervisor() {
        let data = vec![0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("cpuid")));
    }

    #[test]
    fn test_detect_sbiedll() {
        let data = b"sbiedll.dll";
        let pass = AntiAntiPass::new();
        let hits = pass.scan(data);
        assert!(hits.iter().any(|h| h.name.contains("sbiedll")));
    }

    #[test]
    fn test_detect_nt_global_flag() {
        let data = vec![0x64, 0xA1, 0x68, 0x00, 0x00, 0x00];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("nt-global")));
    }

    #[test]
    fn test_detect_close_invalid_handle() {
        // Extended pattern: push -1; call [CloseHandle_iat] (FF 15 xx xx xx xx)
        let data = vec![0x6A, 0xFF, 0xFF, 0x15, 0x10, 0x20, 0x30, 0x40];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("close-invalid")));
    }

    #[test]
    fn test_detect_ptrace_traceme() {
        let data = vec![0xB8, 0x65, 0x00, 0x00, 0x00];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.iter().any(|h| h.name.contains("ptrace")));
    }

    // ── DeobfPass integration ────────────────────────────────────────────────

    #[test]
    fn test_pass_is_applicable() {
        let pass = AntiAntiPass::new();
        assert!(pass.is_applicable(&DeobfContext::new(vec![0x90, 0x90, 0x90, 0x90])));
        assert!(!pass.is_applicable(&DeobfContext::new(vec![])));
    }

    #[test]
    fn test_pass_run_patches_rdtsc() {
        let mut ctx = DeobfContext::new(vec![0x90, 0x0F, 0x31, 0x90]);
        let pass = AntiAntiPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert!(result.patches_applied > 0);
        let patched = ctx.apply_patches().unwrap();
        // RDTSC should now be NOP'd.
        assert_eq!(patched[1], 0x90);
        assert_eq!(patched[2], 0x90);
    }

    #[test]
    fn test_pass_run_empty_binary() {
        let mut ctx = DeobfContext::new(vec![]);
        let pass = AntiAntiPass::new();
        // is_applicable returns false, but calling run directly should still work.
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(result.patches_applied, 0);
    }

    #[test]
    fn test_pass_run_peb_x64_patched() {
        let data = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let mut ctx = DeobfContext::new(data);
        let pass = AntiAntiPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert!(result.patches_applied > 0);
        let patched = ctx.apply_patches().unwrap();
        // First two bytes become 0x48 0x31 (xor rax, rax).
        assert_eq!(patched[0], 0x48);
        assert_eq!(patched[1], 0x31);
    }

    // ── Frida script generation ──────────────────────────────────────────────

    #[test]
    fn test_frida_script_contains_idp() {
        let hits = vec![AntiAnalysisHit {
            name: "api-IsDebuggerPresent".to_owned(),
            offset: 0,
            found_bytes: b"IsDebuggerPresent".to_vec(),
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: vec![],
        }];
        let script = generate_frida_script(&hits);
        assert!(script.contains("IsDebuggerPresent"));
        assert!(script.contains("retval.replace"));
    }

    #[test]
    fn test_frida_script_contains_nqip() {
        let hits = vec![AntiAnalysisHit {
            name: "api-NtQueryInformationProcess".to_owned(),
            offset: 0,
            found_bytes: b"NtQueryInformationProcess".to_vec(),
            strategy: PatchStrategy::ReturnZero,
            patch_bytes: vec![],
        }];
        let script = generate_frida_script(&hits);
        assert!(script.contains("NtQueryInformationProcess"));
    }

    #[test]
    fn test_frida_script_empty_hits() {
        let script = generate_frida_script(&[]);
        assert!(script.contains("generated by rustre-deobf-antianti"));
    }

    // ── Enum coverage ────────────────────────────────────────────────────────

    #[test]
    fn test_anti_debug_technique_variants() {
        // Ensure all variants are constructible (no missing arms in matches above).
        let _ = AntiDebugTechnique::IsDebuggerPresent;
        let _ = AntiDebugTechnique::CheckRemoteDebuggerPresent;
        let _ = AntiDebugTechnique::NtQueryInformationProcess;
        let _ = AntiDebugTechnique::DebugBreak;
        let _ = AntiDebugTechnique::OutputDebugString;
        let _ = AntiDebugTechnique::CloseInvalidHandle;
        let _ = AntiDebugTechnique::NtGlobalFlag;
        let _ = AntiDebugTechnique::HeapFlags;
        let _ = AntiDebugTechnique::ProcessHeap;
        let _ = AntiDebugTechnique::BeingDebugged;
        let _ = AntiDebugTechnique::GetTickCount;
        let _ = AntiDebugTechnique::QueryPerformanceCounter;
        let _ = AntiDebugTechnique::Rdtsc;
        let _ = AntiDebugTechnique::HardwareBreakpoints;
        let _ = AntiDebugTechnique::DrRegisterCheck;
        let _ = AntiDebugTechnique::SehChain;
        let _ = AntiDebugTechnique::ParentProcess;
        let _ = AntiDebugTechnique::TracerPid;
        let _ = AntiDebugTechnique::Ptrace;
        let _ = AntiDebugTechnique::ProcStatus;
        let _ = AntiDebugTechnique::SelfMaps;
        let _ = AntiDebugTechnique::ExceptionBasedChecks;
        let _ = AntiDebugTechnique::TimingDelays;
        let _ = AntiDebugTechnique::TimingCheck;
    }

    #[test]
    fn test_anti_vm_technique_variants() {
        let _ = AntiVmTechnique::VmwarePortCheck;
        let _ = AntiVmTechnique::VmwareCpuid;
        let _ = AntiVmTechnique::VboxRegistry;
        let _ = AntiVmTechnique::HyperVCpuid;
        let _ = AntiVmTechnique::QemuCpuid;
        let _ = AntiVmTechnique::SandboxArtifacts;
        let _ = AntiVmTechnique::SuspiciousProcessList;
        let _ = AntiVmTechnique::NetworkAdapterCheck;
        let _ = AntiVmTechnique::CpuCountCheck;
        let _ = AntiVmTechnique::DiskSizeCheck;
        let _ = AntiVmTechnique::UptimeCheck;
        let _ = AntiVmTechnique::MouseMovementCheck;
    }

    #[test]
    fn test_anti_sandbox_technique_variants() {
        let _ = AntiSandboxTechnique::SleepSkip;
        let _ = AntiSandboxTechnique::UserInteractionCheck;
        let _ = AntiSandboxTechnique::RecentFileCheck;
        let _ = AntiSandboxTechnique::NetworkConnectivity;
        let _ = AntiSandboxTechnique::ScreenResolution;
        let _ = AntiSandboxTechnique::UsernameCheck;
        let _ = AntiSandboxTechnique::DomainCheck;
    }

    #[test]
    fn test_scan_multiple_techniques_in_one_binary() {
        let mut data = Vec::new();
        // PEB x86
        data.extend_from_slice(&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]);
        // RDTSC
        data.extend_from_slice(&[0x0F, 0x31]);
        // NtQueryInformationProcess string
        data.extend_from_slice(b"NtQueryInformationProcess");

        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_no_false_positives_on_nop_sled() {
        // Pure NOP sled should not trigger most anti-debug patterns.
        let data = vec![0x90u8; 64];
        let pass = AntiAntiPass::new();
        let hits = pass.scan(&data);
        // debug-break-int3 won't match (0xCC != 0x90). No other pattern matches all-0x90.
        assert!(hits.iter().all(|h| !h.name.contains("rdtsc")));
    }

    #[test]
    fn test_patch_strategy_serialization() {
        let s = serde_json::to_string(&PatchStrategy::Nop).unwrap();
        let s2: PatchStrategy = serde_json::from_str(&s).unwrap();
        assert_eq!(PatchStrategy::Nop, s2);
    }

    // ── AntiDebugSignatureDatabase ───────────────────────────────────────────

    #[test]
    fn test_sig_db_has_15_plus_entries() {
        let db = AntiDebugSignatureDatabase::new();
        assert!(
            db.signatures().len() >= 15,
            "expected ≥15 signatures, got {}",
            db.signatures().len()
        );
    }

    #[test]
    fn test_sig_db_pattern_mask_lengths_match() {
        for sig in AntiDebugSignatureDatabase::new().signatures() {
            assert_eq!(
                sig.bytes_pattern.len(),
                sig.mask.len(),
                "signature '{}' has mismatched pattern/mask lengths",
                sig.name
            );
        }
    }

    #[test]
    fn test_sig_db_scan_rdtsc() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x90u8, 0x0F, 0x31, 0x90];
        let matches = db.scan_for_anti_debug(&data);
        assert!(
            matches.iter().any(|m| m.sig_name.contains("RDTSC")),
            "RDTSC not detected; matches: {matches:?}"
        );
    }

    #[test]
    fn test_sig_db_scan_peb_x86() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x64u8, 0xA1, 0x30, 0x00, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("PEB")));
    }

    #[test]
    fn test_sig_db_scan_peb_x64() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x65u8, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("PEB")));
    }

    #[test]
    fn test_sig_db_scan_dr_register() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x0Fu8, 0x21, 0xC3]; // mov ebx, dr0
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("DR")));
    }

    #[test]
    fn test_sig_db_scan_nt_global_flag() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x64u8, 0xA1, 0x68, 0x00, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("NtGlobalFlag")));
    }

    #[test]
    fn test_sig_db_scan_close_invalid_handle() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x6Au8, 0xFF, 0x90];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("CloseInvalid")));
    }

    #[test]
    fn test_sig_db_scan_seh_trap_flag() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x9Cu8, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("SEH")));
    }

    #[test]
    fn test_sig_db_scan_ptrace() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0xB8u8, 0x65, 0x00, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("ptrace")));
    }

    #[test]
    fn test_sig_db_scan_heap_flags() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x64u8, 0xA1, 0x18, 0x00, 0x00, 0x00];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("Heap")));
    }

    #[test]
    fn test_sig_db_scan_vmware_magic() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0xB8u8, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("VMware")));
    }

    #[test]
    fn test_sig_db_scan_int3_timing() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0xCCu8, 0xCC, 0x90];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("INT3")));
    }

    #[test]
    fn test_sig_db_matches_sorted_by_offset() {
        let db = AntiDebugSignatureDatabase::new();
        let mut data = vec![0x90u8; 32];
        // RDTSC at offset 4, INT3*2 at offset 10.
        data[4] = 0x0F;
        data[5] = 0x31;
        data[10] = 0xCC;
        data[11] = 0xCC;
        let matches = db.scan_for_anti_debug(&data);
        for w in matches.windows(2) {
            assert!(w[0].offset <= w[1].offset, "matches not sorted by offset");
        }
    }

    #[test]
    fn test_sig_db_confidence_in_range() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0x0Fu8, 0x31]; // RDTSC
        let matches = db.scan_for_anti_debug(&data);
        for m in &matches {
            assert!(m.confidence <= 100, "confidence > 100: {}", m.confidence);
        }
    }

    #[test]
    fn test_sig_db_empty_data_no_matches() {
        let db = AntiDebugSignatureDatabase::new();
        let matches = db.scan_for_anti_debug(&[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sig_db_gettickcount_timing() {
        let db = AntiDebugSignatureDatabase::new();
        let data = [0xFFu8, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7];
        let matches = db.scan_for_anti_debug(&data);
        assert!(matches.iter().any(|m| m.sig_name.contains("GetTickCount")));
    }
}
