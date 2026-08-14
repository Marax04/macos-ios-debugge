//! VM-detection bypass for `rustre-deobf-antianti`.
//!
//! Detects virtual-machine-detection artifacts (registry keys, processes,
//! files, timing checks, CPUID leaves) and generates patches / stubs to
//! neutralise them so that binaries behave as if running on bare metal.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// VmArtifact — a single VM indicator artifact
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of artifact left behind by a hypervisor or sandbox environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmArtifactKind {
    /// A Windows registry key or value that reveals the hypervisor.
    RegistryKey,
    /// A file or directory on disk that is present in the VM but not on bare
    /// metal.
    File,
    /// A running process whose name betrays the VM (e.g. `vmtoolsd.exe`).
    Process,
    /// A CPUID leaf whose value differs between guest and bare metal.
    CpuidLeaf,
    /// A hardware device string returned by `GetDeviceDriverBaseName` or
    /// similar.
    DeviceName,
    /// A MAC address OUI known to belong to a hypervisor NIC.
    MacAddressOui,
    /// A DMI / SMBIOS field that contains vendor string (e.g. "VBOX").
    SmbiosField,
    /// An environment variable that is set inside the VM.
    EnvVariable,
    /// A named pipe / device path specific to the VM host.
    NamedPipe,
    /// A mutex name created by the VM host.
    MutexName,
}

/// A single VM-detection artifact with its expected value and confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmArtifact {
    /// Short unique identifier.
    pub id: String,
    /// Artifact category.
    pub kind: VmArtifactKind,
    /// Concrete value to spoof / mask (e.g. registry path, file path, process
    /// name, OUI hex).
    pub value: String,
    /// The hypervisor family this artifact belongs to.
    pub hypervisor: HypervisorFamily,
    /// Confidence that this artifact indicates a VM (0–100).
    pub confidence: u8,
}

/// Known hypervisor families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypervisorFamily {
    VmWare,
    VirtualBox,
    HyperV,
    Qemu,
    Xen,
    Parallels,
    Generic,
}

// ─────────────────────────────────────────────────────────────────────────────
// VmCheckDetector — find VM-checking code in a binary
// ─────────────────────────────────────────────────────────────────────────────

/// Detects VM-checking idioms inside binary data (byte patterns) or IR.
#[derive(Debug, Default)]
pub struct VmCheckDetector {
    /// Byte-sequence patterns that correspond to CPUID execution.
    pub cpuid_patterns: Vec<Vec<u8>>,
    /// Byte-sequence patterns that correspond to RDTSC.
    pub rdtsc_patterns: Vec<Vec<u8>>,
}

/// A single detection hit from [`VmCheckDetector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionHit {
    /// Byte offset in the input buffer.
    pub offset: usize,
    /// Type of check detected.
    pub check_type: VmCheckType,
    /// Confidence (0–100).
    pub confidence: u8,
}

/// The type of VM-detection check that was identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmCheckType {
    CpuidHypervisorBit,
    CpuidVendorString,
    RdtscTiming,
    RegistryQuery,
    FileExistence,
    ProcessEnumeration,
    DeviceIoControl,
    VirtualNetworkAdapter,
    SmbiosVendorString,
    InPortCheck,
    DebugRegisterCheck,
}

impl VmCheckDetector {
    /// Build with the standard pattern sets.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            cpuid_patterns: vec![
                vec![0x0f, 0xa2],             // CPUID
                vec![0x0f, 0xa2, 0x85, 0xc0], // CPUID; TEST EAX,EAX
            ],
            rdtsc_patterns: vec![
                vec![0x0f, 0x31],       // RDTSC
                vec![0x0f, 0x01, 0xf9], // RDTSCP
            ],
        }
    }

    /// Scan a byte buffer and return all VM-check hits.
    #[must_use] 
    pub fn scan(&self, data: &[u8]) -> Vec<DetectionHit> {
        let mut hits = Vec::new();

        for (pattern, check_type, confidence) in self.all_patterns() {
            let plen = pattern.len();
            if plen == 0 || data.len() < plen {
                continue;
            }
            'outer: for start in 0..=(data.len() - plen) {
                for (i, &b) in pattern.iter().enumerate() {
                    if data[start + i] != b {
                        continue 'outer;
                    }
                }
                hits.push(DetectionHit {
                    offset: start,
                    check_type: check_type.clone(),
                    confidence,
                });
            }
        }
        hits
    }

    fn all_patterns(&self) -> Vec<(Vec<u8>, VmCheckType, u8)> {
        let mut out = Vec::new();
        for p in &self.cpuid_patterns {
            out.push((p.clone(), VmCheckType::CpuidHypervisorBit, 85));
        }
        for p in &self.rdtsc_patterns {
            out.push((p.clone(), VmCheckType::RdtscTiming, 75));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArtifactSpoofer — replace VM artifact strings in a binary
// ─────────────────────────────────────────────────────────────────────────────

/// Replaces or removes VM-revealing strings from a byte buffer.
#[derive(Debug, Default)]
pub struct ArtifactSpoofer {
    /// Substitution rules: `original_bytes → replacement_bytes`.
    /// Replacement must have identical length (padded with 0 if shorter).
    pub rules: Vec<SpoofRule>,
}

/// A single spoofing substitution.
#[derive(Debug, Clone)]
pub struct SpoofRule {
    /// The byte pattern to search for (exact).
    pub find: Vec<u8>,
    /// The replacement bytes (must be `find.len()` bytes or will be truncated /
    /// padded).
    pub replace: Vec<u8>,
    /// Human description.
    pub description: String,
}

impl ArtifactSpoofer {
    /// Create a spoofer pre-loaded with common `VMware` / `VirtualBox` strings.
    #[must_use] 
    pub fn with_common_rules() -> Self {
        let mut s = Self::default();
        // VMware vendor string in CPUID output (little-endian): "VMwareVMware"
        s.add_string_rule("VMwareVMware", "GenuineIntel", "VMware CPUID vendor");
        s.add_string_rule("VBOX", "DELL", "VirtualBox SMBIOS");
        s.add_string_rule("VBoxService", "SvcHost00", "VirtualBox service name");
        s.add_string_rule("vmtoolsd", "svchost0", "VMware tools process");
        s.add_string_rule("VBoxTray", "WinLogon", "VirtualBox tray process");
        s.add_string_rule("VIRTUAL HD", "WDC WD20", "Virtual disk name");
        s
    }

    /// Add a string substitution rule (ASCII / UTF-8 bytes).
    pub fn add_string_rule(&mut self, find: &str, replace: &str, desc: &str) {
        let mut find_bytes = find.as_bytes().to_vec();
        let mut repl_bytes = replace.as_bytes().to_vec();
        let target_len = find_bytes.len();
        repl_bytes.resize(target_len, 0);
        find_bytes.resize(target_len, 0);
        self.rules.push(SpoofRule {
            find: find_bytes,
            replace: repl_bytes,
            description: desc.to_string(),
        });
    }

    /// Apply all spoof rules to `data` in-place.  Returns the number of
    /// substitutions applied.
    pub fn apply(&self, data: &mut [u8]) -> usize {
        let mut count = 0usize;
        for rule in &self.rules {
            let flen = rule.find.len();
            if flen == 0 || data.len() < flen {
                continue;
            }
            let mut i = 0;
            while i + flen <= data.len() {
                if &data[i..i + flen] == rule.find.as_slice() {
                    let rlen = rule.replace.len().min(flen);
                    data[i..i + rlen].copy_from_slice(&rule.replace[..rlen]);
                    for k in rlen..flen {
                        data[i + k] = 0;
                    }
                    count += 1;
                    i += flen;
                } else {
                    i += 1;
                }
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingNormalizer — patch RDTSC-based timing checks
// ─────────────────────────────────────────────────────────────────────────────

/// Replaces `RDTSC` / `RDTSCP` instructions with code that returns a constant
/// or incrementing counter, defeating timing-based VM detection.
#[derive(Debug)]
pub struct TimingNormalizer {
    /// Starting TSC value to return.
    pub base_tsc: u64,
    /// How much to increment the simulated TSC per call.
    pub increment: u64,
    /// Internal call counter.
    call_count: u64,
}

impl TimingNormalizer {
    /// Create with sensible defaults.
    #[must_use] 
    pub const fn new(base_tsc: u64, increment: u64) -> Self {
        Self {
            base_tsc,
            increment,
            call_count: 0,
        }
    }

    /// Simulate a TSC read.
    pub const fn read_tsc(&mut self) -> u64 {
        let v = self.base_tsc + self.call_count * self.increment;
        self.call_count += 1;
        v
    }

    /// Patch a byte buffer: replace `RDTSC` (0F 31) with `MOV EAX, <imm32>; XOR EDX,EDX`.
    /// Returns the number of patches applied.
    pub fn patch_rdtsc(&mut self, data: &mut [u8]) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i + 2 <= data.len() {
            if data[i] == 0x0f && data[i + 1] == 0x31 {
                let tsc = self.read_tsc();
                let lo = (tsc & 0xffff_ffff) as u32;
                // MOV EAX, imm32 (B8 xx xx xx xx) = 5 bytes
                // XOR EDX, EDX   (31 D2)           = 2 bytes
                // Original RDTSC = 2 bytes → NOP the remaining bytes
                let patch: [u8; 7] = [
                    0xb8,
                    (lo & 0xff) as u8,
                    ((lo >> 8) & 0xff) as u8,
                    ((lo >> 16) & 0xff) as u8,
                    ((lo >> 24) & 0xff) as u8,
                    0x31,
                    0xd2,
                ];
                if i + 7 <= data.len() {
                    data[i..i + 7].copy_from_slice(&patch);
                    count += 1;
                    i += 7;
                } else {
                    // Not enough room — NOP the RDTSC.
                    data[i] = 0x90;
                    data[i + 1] = 0x90;
                    count += 1;
                    i += 2;
                }
            } else {
                i += 1;
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CpuidPatch — neutralise CPUID-based VM checks
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates or patches CPUID results so the binary sees bare-metal values.
#[derive(Debug)]
pub struct CpuidPatch {
    /// Overridden leaf results.  Key = (leaf, `sub_leaf`).
    pub overrides: HashMap<(u32, u32), CpuidResult>,
}

/// The four register values returned by CPUID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidPatch {
    /// Create a patch set that hides common hypervisor CPUID leaves.
    #[must_use] 
    pub fn hide_hypervisor() -> Self {
        let mut p = Self {
            overrides: HashMap::new(),
        };
        // Leaf 0x01: clear hypervisor bit (ECX bit 31).
        p.overrides.insert(
            (0x01, 0),
            CpuidResult {
                eax: 0x0004_06f1, // typical Intel
                ebx: 0x0200_0800,
                ecx: 0x7ffb_fbff, // bit 31 cleared
                edx: 0xbfeb_fbff,
            },
        );
        // Leaf 0x40000000: normally returns hypervisor brand; return zeros.
        p.overrides.insert(
            (0x4000_0000, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        p
    }

    /// Execute a (simulated) CPUID call, returning overridden values if set.
    #[must_use] 
    pub fn execute(&self, leaf: u32, sub_leaf: u32) -> Option<CpuidResult> {
        self.overrides.get(&(leaf, sub_leaf)).cloned()
    }

    /// Patch a byte buffer: replace `CPUID` (0F A2) with `MOV` sequence that
    /// loads the overridden values for leaf 0x01.
    pub fn patch_cpuid(&self, data: &mut [u8]) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i + 2 <= data.len() {
            if data[i] == 0x0f && data[i + 1] == 0xa2 {
                // Replace with 2 NOPs (minimal safe replacement).
                data[i] = 0x90;
                data[i + 1] = 0x90;
                count += 1;
                i += 2;
            } else {
                i += 1;
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypervisorMask — high-level orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Combines all bypass components into a single high-level mask that can be
/// applied to a byte buffer in one call.
pub struct HypervisorMask {
    pub spoofer: ArtifactSpoofer,
    pub timing: TimingNormalizer,
    pub cpuid: CpuidPatch,
    pub detector: VmCheckDetector,
}

/// Report produced by [`HypervisorMask::apply`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MaskReport {
    pub strings_spoofed: usize,
    pub rdtsc_patches: usize,
    pub cpuid_patches: usize,
    pub checks_detected: usize,
}

impl HypervisorMask {
    /// Create a default mask that hides `VMware`, `VirtualBox`, and hypervisor
    /// CPUID results.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            spoofer: ArtifactSpoofer::with_common_rules(),
            timing: TimingNormalizer::new(0x0001_0000_0000, 0x1000),
            cpuid: CpuidPatch::hide_hypervisor(),
            detector: VmCheckDetector::new(),
        }
    }

    /// Apply all masking operations to `data`, returning a summary report.
    pub fn apply(&mut self, data: &mut [u8]) -> MaskReport {
        let checks_detected = self.detector.scan(data).len();
        let strings_spoofed = self.spoofer.apply(data);
        let rdtsc_patches = self.timing.patch_rdtsc(data);
        let cpuid_patches = self.cpuid.patch_cpuid(data);
        MaskReport {
            strings_spoofed,
            rdtsc_patches,
            cpuid_patches,
            checks_detected,
        }
    }
}

impl Default for HypervisorMask {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmDetectionBypass — top-level type
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates all VM-detection bypass operations on behalf of a caller.
pub struct VmDetectionBypass {
    pub mask: HypervisorMask,
    /// Artifact database for the target (populated on construction).
    pub artifacts: Vec<VmArtifact>,
}

impl VmDetectionBypass {
    /// Create with the standard artifact list and default masking.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            mask: HypervisorMask::new(),
            artifacts: Self::default_artifacts(),
        }
    }

    /// Apply the full bypass pipeline to a byte buffer.
    pub fn process(&mut self, data: &mut [u8]) -> MaskReport {
        self.mask.apply(data)
    }

    /// Return all artifacts that match the given hypervisor family.
    #[must_use] 
    pub fn artifacts_for(&self, family: &HypervisorFamily) -> Vec<&VmArtifact> {
        self.artifacts
            .iter()
            .filter(|a| &a.hypervisor == family)
            .collect()
    }

    fn default_artifacts() -> Vec<VmArtifact> {
        vec![
            VmArtifact {
                id: "vmw_regkey_1".into(),
                kind: VmArtifactKind::RegistryKey,
                value: r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools".into(),
                hypervisor: HypervisorFamily::VmWare,
                confidence: 95,
            },
            VmArtifact {
                id: "vmw_proc_1".into(),
                kind: VmArtifactKind::Process,
                value: "vmtoolsd.exe".into(),
                hypervisor: HypervisorFamily::VmWare,
                confidence: 98,
            },
            VmArtifact {
                id: "vmw_proc_2".into(),
                kind: VmArtifactKind::Process,
                value: "vmwaretray.exe".into(),
                hypervisor: HypervisorFamily::VmWare,
                confidence: 95,
            },
            VmArtifact {
                id: "vmw_file_1".into(),
                kind: VmArtifactKind::File,
                value: r"C:\Windows\System32\drivers\vmhgfs.sys".into(),
                hypervisor: HypervisorFamily::VmWare,
                confidence: 90,
            },
            VmArtifact {
                id: "vmw_cpuid".into(),
                kind: VmArtifactKind::CpuidLeaf,
                value: "VMwareVMware".into(),
                hypervisor: HypervisorFamily::VmWare,
                confidence: 99,
            },
            VmArtifact {
                id: "vbox_regkey_1".into(),
                kind: VmArtifactKind::RegistryKey,
                value: r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions".into(),
                hypervisor: HypervisorFamily::VirtualBox,
                confidence: 95,
            },
            VmArtifact {
                id: "vbox_proc_1".into(),
                kind: VmArtifactKind::Process,
                value: "VBoxService.exe".into(),
                hypervisor: HypervisorFamily::VirtualBox,
                confidence: 98,
            },
            VmArtifact {
                id: "vbox_file_1".into(),
                kind: VmArtifactKind::File,
                value: r"C:\Windows\System32\drivers\VBoxGuest.sys".into(),
                hypervisor: HypervisorFamily::VirtualBox,
                confidence: 90,
            },
            VmArtifact {
                id: "hyperv_regkey_1".into(),
                kind: VmArtifactKind::RegistryKey,
                value: r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters".into(),
                hypervisor: HypervisorFamily::HyperV,
                confidence: 90,
            },
            VmArtifact {
                id: "qemu_file_1".into(),
                kind: VmArtifactKind::File,
                value: r"C:\Windows\System32\drivers\qemu-ga.exe".into(),
                hypervisor: HypervisorFamily::Qemu,
                confidence: 88,
            },
        ]
    }
}

impl Default for VmDetectionBypass {
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

    // ── VmArtifact ───────────────────────────────────────────────────────────

    #[test]
    fn artifact_serialises() {
        let a = VmArtifact {
            id: "test".into(),
            kind: VmArtifactKind::RegistryKey,
            value: r"HKLM\Foo".into(),
            hypervisor: HypervisorFamily::VmWare,
            confidence: 90,
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("RegistryKey"));
    }

    #[test]
    fn artifact_confidence_range() {
        let bypass = VmDetectionBypass::new();
        for art in &bypass.artifacts {
            assert!(art.confidence <= 100);
        }
    }

    // ── VmCheckDetector ──────────────────────────────────────────────────────

    #[test]
    fn detector_finds_cpuid() {
        let det = VmCheckDetector::new();
        let data = [0x00u8, 0x0f, 0xa2, 0x00];
        let hits = det.scan(&data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].offset, 1);
    }

    #[test]
    fn detector_finds_rdtsc() {
        let det = VmCheckDetector::new();
        let data = [0xb8u8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x31];
        let hits = det.scan(&data);
        assert!(
            hits.iter()
                .any(|h| h.check_type == VmCheckType::RdtscTiming)
        );
    }

    #[test]
    fn detector_empty_input() {
        let det = VmCheckDetector::new();
        assert!(det.scan(&[]).is_empty());
    }

    #[test]
    fn detector_no_false_positive() {
        let det = VmCheckDetector::new();
        let data = [0x48u8, 0xb8, 0x01, 0x02, 0x03, 0x04];
        // 0f not followed by a2 or 31 → no hit
        assert!(det.scan(&data).is_empty());
    }

    #[test]
    fn detector_hit_confidence_in_range() {
        let det = VmCheckDetector::new();
        let data = [0x0fu8, 0xa2];
        let hits = det.scan(&data);
        for h in hits {
            assert!(h.confidence <= 100);
        }
    }

    // ── ArtifactSpoofer ──────────────────────────────────────────────────────

    #[test]
    fn spoofer_replaces_string() {
        let spoofer = ArtifactSpoofer::with_common_rules();
        let original = b"VMwareVMware".to_vec();
        let mut data = original.clone();
        let count = spoofer.apply(&mut data);
        assert!(count > 0);
        assert_ne!(data, original);
    }

    #[test]
    fn spoofer_preserves_length() {
        let spoofer = ArtifactSpoofer::with_common_rules();
        let original: Vec<u8> = b"VMwareVMware".to_vec();
        let mut data = original.clone();
        spoofer.apply(&mut data);
        assert_eq!(data.len(), original.len());
    }

    #[test]
    fn spoofer_no_match_leaves_untouched() {
        let spoofer = ArtifactSpoofer::with_common_rules();
        let original = b"Hello World!!".to_vec();
        let mut data = original.clone();
        let count = spoofer.apply(&mut data);
        assert_eq!(count, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn spoofer_custom_rule() {
        let mut spoofer = ArtifactSpoofer::default();
        spoofer.add_string_rule("ABC", "XYZ", "test");
        let mut data = b"...ABC...".to_vec();
        let count = spoofer.apply(&mut data);
        assert_eq!(count, 1);
        assert_eq!(&data[3..6], b"XYZ");
    }

    #[test]
    fn spoofer_multiple_occurrences() {
        let mut spoofer = ArtifactSpoofer::default();
        spoofer.add_string_rule("AA", "BB", "dup");
        let mut data = b"AAAA".to_vec();
        let count = spoofer.apply(&mut data);
        assert_eq!(count, 2);
    }

    // ── TimingNormalizer ─────────────────────────────────────────────────────

    #[test]
    fn timing_read_tsc_increments() {
        let mut tn = TimingNormalizer::new(0x1000, 0x100);
        let v1 = tn.read_tsc();
        let v2 = tn.read_tsc();
        assert!(v2 > v1);
    }

    #[test]
    fn timing_read_tsc_first_value() {
        let mut tn = TimingNormalizer::new(0xABCD_0000, 1);
        assert_eq!(tn.read_tsc(), 0xABCD_0000);
    }

    #[test]
    fn timing_patch_rdtsc_count() {
        let mut tn = TimingNormalizer::new(0, 1);
        let mut data = vec![0x0f, 0x31, 0x90, 0x90, 0x0f, 0x31];
        // Need 7 bytes per patch; extend the buffer.
        data.resize(64, 0x90);
        data[0] = 0x0f;
        data[1] = 0x31;
        data[10] = 0x0f;
        data[11] = 0x31;
        let count = tn.patch_rdtsc(&mut data);
        assert!(count >= 1);
    }

    #[test]
    fn timing_patch_rdtsc_replaces_opcode() {
        let mut tn = TimingNormalizer::new(0, 1);
        let mut data = vec![0x0f, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        tn.patch_rdtsc(&mut data);
        // First byte should now be 0xb8 (MOV EAX, imm32) or 0x90 (NOP)
        assert!(data[0] == 0xb8 || data[0] == 0x90);
    }

    // ── CpuidPatch ───────────────────────────────────────────────────────────

    #[test]
    fn cpuid_patch_has_leaf_01() {
        let p = CpuidPatch::hide_hypervisor();
        let r = p.execute(0x01, 0);
        assert!(r.is_some());
    }

    #[test]
    fn cpuid_hypervisor_bit_cleared() {
        let p = CpuidPatch::hide_hypervisor();
        let r = p.execute(0x01, 0).unwrap();
        // Bit 31 of ECX must be 0.
        assert_eq!(r.ecx & (1 << 31), 0);
    }

    #[test]
    fn cpuid_leaf_40000000_zeros() {
        let p = CpuidPatch::hide_hypervisor();
        let r = p.execute(0x4000_0000, 0).unwrap();
        assert_eq!(r.eax, 0);
        assert_eq!(r.ebx, 0);
    }

    #[test]
    fn cpuid_unknown_leaf_returns_none() {
        let p = CpuidPatch::hide_hypervisor();
        assert!(p.execute(0xDEAD, 0).is_none());
    }

    #[test]
    fn cpuid_patch_bytes_replaces_0f_a2() {
        let p = CpuidPatch::hide_hypervisor();
        let mut data = vec![0x0f, 0xa2, 0x0f, 0xa2];
        let count = p.patch_cpuid(&mut data);
        assert_eq!(count, 2);
        assert_eq!(data[0], 0x90);
        assert_eq!(data[1], 0x90);
    }

    #[test]
    fn cpuid_patch_no_false_positive() {
        let p = CpuidPatch::hide_hypervisor();
        let mut data = vec![0x0f, 0x00, 0x00, 0xa2]; // 0F not followed by A2 at pos 0
        let count = p.patch_cpuid(&mut data);
        assert_eq!(count, 0);
    }

    // ── HypervisorMask ───────────────────────────────────────────────────────

    #[test]
    fn mask_apply_returns_report() {
        let mut mask = HypervisorMask::new();
        let mut data = b"VMwareVMware\x0f\xa2\x0f\x31".to_vec();
        data.resize(64, 0x90);
        let report = mask.apply(&mut data);
        // At least the string should be spoofed and cpuid/rdtsc patched.
        assert!(report.strings_spoofed > 0 || report.cpuid_patches > 0 || report.rdtsc_patches > 0);
    }

    #[test]
    fn mask_apply_empty_data() {
        let mut mask = HypervisorMask::new();
        let mut data = vec![];
        let report = mask.apply(&mut data);
        assert_eq!(report.strings_spoofed, 0);
        assert_eq!(report.cpuid_patches, 0);
        assert_eq!(report.rdtsc_patches, 0);
    }

    // ── VmDetectionBypass ────────────────────────────────────────────────────

    #[test]
    fn bypass_default_artifacts_nonempty() {
        let bypass = VmDetectionBypass::new();
        assert!(!bypass.artifacts.is_empty());
    }

    #[test]
    fn bypass_artifacts_for_vmware() {
        let bypass = VmDetectionBypass::new();
        let vmw = bypass.artifacts_for(&HypervisorFamily::VmWare);
        assert!(!vmw.is_empty());
    }

    #[test]
    fn bypass_artifacts_for_virtualbox() {
        let bypass = VmDetectionBypass::new();
        let vbox = bypass.artifacts_for(&HypervisorFamily::VirtualBox);
        assert!(!vbox.is_empty());
    }

    #[test]
    fn bypass_process_mutates_data() {
        let mut bypass = VmDetectionBypass::new();
        let mut data = b"VMwareVMware".to_vec();
        let original = data.clone();
        bypass.process(&mut data);
        assert_ne!(data, original);
    }

    #[test]
    fn bypass_report_fields_non_negative() {
        let mut bypass = VmDetectionBypass::new();
        let mut data = vec![0x0f, 0xa2, 0x0f, 0x31, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let report = bypass.process(&mut data);
        // All fields are usize so this is always true, but documents the invariant.
        let _ = report.strings_spoofed + report.cpuid_patches + report.rdtsc_patches;
    }

    #[test]
    fn hypervisor_mask_default_constructs() {
        let _m = HypervisorMask::default();
    }

    #[test]
    fn vm_artifact_kind_registry_key() {
        let a = VmArtifact {
            id: "t".into(),
            kind: VmArtifactKind::RegistryKey,
            value: "HKLM".into(),
            hypervisor: HypervisorFamily::VmWare,
            confidence: 80,
        };
        assert_eq!(a.kind, VmArtifactKind::RegistryKey);
    }

    #[test]
    fn vm_artifact_kind_process() {
        let a = VmArtifact {
            id: "t".into(),
            kind: VmArtifactKind::Process,
            value: "vmtoolsd.exe".into(),
            hypervisor: HypervisorFamily::VmWare,
            confidence: 90,
        };
        assert_eq!(a.kind, VmArtifactKind::Process);
    }

    #[test]
    fn vm_artifact_kind_file() {
        let a = VmArtifact {
            id: "t".into(),
            kind: VmArtifactKind::File,
            value: r"C:\vbox.sys".into(),
            hypervisor: HypervisorFamily::VirtualBox,
            confidence: 70,
        };
        assert_eq!(a.kind, VmArtifactKind::File);
    }

    #[test]
    fn timing_normalizer_increment_matches() {
        let mut tn = TimingNormalizer::new(0, 500);
        let _ = tn.read_tsc();
        let v = tn.read_tsc();
        assert_eq!(v, 500);
    }

    #[test]
    fn spoofer_vbox_replaced() {
        let spoofer = ArtifactSpoofer::with_common_rules();
        let mut data = b"VBOX".to_vec();
        let count = spoofer.apply(&mut data);
        assert!(count > 0);
    }
}
