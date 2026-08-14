//! Anti-VM bypass: patch registry checks, process-name checks, and CPUID checks.
//!
//! The [`AntiVmBypass`] struct provides methods that generate binary patches
//! targeting the specific byte patterns and API call sequences used for
//! virtual-machine detection.

use serde::{Deserialize, Serialize};

use crate::bypasser::BypassPatch;
use crate::detector::{DetectedTechnique, DetectionSite, StaticAntiDebugDetector};
use crate::{AntiVmTechnique, PatchStrategy};

// ─────────────────────────────────────────────────────────────────────────────
// VmCheckType
// ─────────────────────────────────────────────────────────────────────────────

/// The category of VM detection check that was identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmCheckType {
    /// Registry key access to VM-specific keys (`VirtualBox`, `VMware`).
    RegistryCheck,
    /// Process name comparison against known VM tool processes.
    ProcessNameCheck,
    /// CPUID instruction with a VM-identifying leaf value.
    CpuidCheck,
    /// I/O port backdoor (`VMware` `0x5658`).
    IoPortCheck,
    /// NIC MAC address OUI comparison.
    MacAddressCheck,
    /// Disk size comparison.
    DiskSizeCheck,
    /// CPU count comparison.
    CpuCountCheck,
    /// VM-related file / pipe path scan.
    FileArtifactCheck,
    /// Uptime check (fresh VM has low uptime).
    UptimeCheck,
}

// ─────────────────────────────────────────────────────────────────────────────
// VmDetectionSite
// ─────────────────────────────────────────────────────────────────────────────

/// A single site where VM-detection code was found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetectionSite {
    /// Byte offset in the binary.
    pub offset: usize,
    /// Number of bytes covered by this site.
    pub length: usize,
    /// What kind of check this is.
    pub check_type: VmCheckType,
    /// The VM product / hypervisor this check targets.
    pub target_vm: String,
    /// Human-readable description.
    pub description: String,
    /// Recommended bypass patch strategy.
    pub strategy: PatchStrategy,
    /// Confidence (0–100).
    pub confidence: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiVmBypass
// ─────────────────────────────────────────────────────────────────────────────

/// Generates patches for VM detection checks in binary data.
///
/// ```rust
/// use rustre_deobf_antianti::vm_detection::AntiVmBypass;
///
/// let bypass = AntiVmBypass::new();
/// let data = b"VBOX__registry check here\x00vboxservice.exe\x00";
/// let sites = bypass.scan(data);
/// assert!(!sites.is_empty());
/// let patches = bypass.generate_patches(data, &sites);
/// assert!(!patches.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct AntiVmBypass;

impl AntiVmBypass {
    /// Create a new bypass helper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan binary data and return all VM detection sites.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<VmDetectionSite> {
        let det = StaticAntiDebugDetector::new();
        let generic_sites = det.scan(data);
        let vm_sites: Vec<VmDetectionSite> = generic_sites
            .into_iter()
            .filter_map(convert_to_vm_site)
            .collect();

        // Also scan additional VM-specific patterns not in the generic detector
        let mut extra = Vec::new();
        self.scan_registry_patterns(data, &mut extra);
        self.scan_process_patterns(data, &mut extra);
        self.scan_cpuid_patterns(data, &mut extra);
        self.scan_file_artifact_patterns(data, &mut extra);

        let mut all = vm_sites;
        all.extend(extra);
        all.sort_by_key(|s| s.offset);
        all
    }

    /// Generate bypass patches for the provided VM detection sites.
    ///
    /// `data` is the full binary buffer.
    #[must_use]
    pub fn generate_patches(&self, data: &[u8], sites: &[VmDetectionSite]) -> Vec<BypassPatch> {
        sites
            .iter()
            .filter_map(|site| {
                let end = site.offset + site.length;
                if end > data.len() {
                    return None;
                }
                let original = data[site.offset..end].to_vec();
                let replacement = build_vm_replacement(&original, site.strategy, &site.check_type);
                Some(BypassPatch {
                    offset: site.offset,
                    original,
                    replacement,
                    technique: DetectedTechnique::AntiVm(technique_for_check(&site.check_type)),
                    description: format!(
                        "vm-bypass {} at 0x{:08x}: {}",
                        site.target_vm, site.offset, site.description
                    ),
                })
            })
            .collect()
    }

    /// Patch all detected registry checks in `data`.
    ///
    /// Returns the number of patches applied.
    pub fn patch_registry_checks(&self, data: &mut [u8]) -> usize {
        let sites = self.scan(data);
        let registry_sites: Vec<VmDetectionSite> = sites
            .into_iter()
            .filter(|s| s.check_type == VmCheckType::RegistryCheck)
            .collect();
        let patches = self.generate_patches(data, &registry_sites);
        let count = patches.len();
        for p in patches {
            p.apply(data);
        }
        count
    }

    /// Patch all detected process-name checks in `data`.
    ///
    /// Returns the number of patches applied.
    pub fn patch_process_name_checks(&self, data: &mut [u8]) -> usize {
        let sites = self.scan(data);
        let process_sites: Vec<VmDetectionSite> = sites
            .into_iter()
            .filter(|s| s.check_type == VmCheckType::ProcessNameCheck)
            .collect();
        let patches = self.generate_patches(data, &process_sites);
        let count = patches.len();
        for p in patches {
            p.apply(data);
        }
        count
    }

    /// Patch all detected CPUID checks in `data`.
    ///
    /// Returns the number of patches applied.
    pub fn patch_cpuid_checks(&self, data: &mut [u8]) -> usize {
        let sites = self.scan(data);
        let cpuid_sites: Vec<VmDetectionSite> = sites
            .into_iter()
            .filter(|s| s.check_type == VmCheckType::CpuidCheck)
            .collect();
        let patches = self.generate_patches(data, &cpuid_sites);
        let count = patches.len();
        for p in patches {
            p.apply(data);
        }
        count
    }

    fn scan_registry_patterns(&self, data: &[u8], out: &mut Vec<VmDetectionSite>) {
        let registry_keys: &[(&[u8], &str, &str)] = &[
            (
                b"HARDWARE\\ACPI\\DSDT\\VBOX__",
                "VirtualBox",
                "ACPI DSDT VBOX__ registry key",
            ),
            (
                b"HARDWARE\\ACPI\\FADT\\VBOX__",
                "VirtualBox",
                "ACPI FADT VBOX__ registry key",
            ),
            (
                b"HARDWARE\\ACPI\\RSDT\\VBOX__",
                "VirtualBox",
                "ACPI RSDT VBOX__ registry key",
            ),
            (
                b"SOFTWARE\\Oracle\\VirtualBox",
                "VirtualBox",
                "VirtualBox software registry key",
            ),
            (
                b"SOFTWARE\\VMware, Inc.\\VMware Tools",
                "VMware",
                "VMware Tools software registry key",
            ),
            (
                b"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                "VirtualBox",
                "VBoxGuest service registry key",
            ),
            (
                b"SYSTEM\\ControlSet001\\Services\\VMwareMouseSynchronizationDriver",
                "VMware",
                "VMware mouse driver registry key",
            ),
            (
                b"SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVBOX_HARDDISK",
                "VirtualBox",
                "VirtualBox IDE disk registry key",
            ),
            (
                b"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
                "VMware",
                "VMware SCSI disk registry key",
            ),
            (
                b"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers",
                "Hyper-V",
                "Hyper-V virtual device drivers key",
            ),
            (
                b"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                "Hyper-V",
                "Hyper-V guest parameters key",
            ),
            (
                b"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString",
                "QEMU",
                "CPU name string check",
            ),
        ];

        for (pattern, vm, desc) in registry_keys {
            let plen = pattern.len();
            if plen > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - plen) {
                let window = &data[offset..offset + plen];
                // Case-insensitive comparison
                if window.eq_ignore_ascii_case(pattern) {
                    out.push(VmDetectionSite {
                        offset,
                        length: plen,
                        check_type: VmCheckType::RegistryCheck,
                        target_vm: vm.to_string(),
                        description: desc.to_string(),
                        strategy: PatchStrategy::ForceFalse,
                        confidence: 85,
                    });
                }
            }
        }
    }

    fn scan_process_patterns(&self, data: &[u8], out: &mut Vec<VmDetectionSite>) {
        let processes: &[(&[u8], &str)] = &[
            (b"vboxservice.exe", "VirtualBox"),
            (b"vboxtray.exe", "VirtualBox"),
            (b"vboxcontrol.exe", "VirtualBox"),
            (b"vmtoolsd.exe", "VMware"),
            (b"vmwaretray.exe", "VMware"),
            (b"vmwareuser.exe", "VMware"),
            (b"vmacthlp.exe", "VMware"),
            (b"qemu-ga.exe", "QEMU"),
            (b"qga.exe", "QEMU"),
            (b"prl_tools.exe", "Parallels"),
            (b"prl_cc.exe", "Parallels"),
            (b"xenservice.exe", "Xen"),
            (b"xenupdatersvc.exe", "Xen"),
            (b"vmcompute.exe", "Hyper-V"),
            (b"vmsrvc.exe", "Virtual PC"),
        ];

        for (needle, vm) in processes {
            let nlen = needle.len();
            if nlen > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - nlen) {
                if data[offset..offset + nlen].eq_ignore_ascii_case(needle) {
                    out.push(VmDetectionSite {
                        offset,
                        length: nlen,
                        check_type: VmCheckType::ProcessNameCheck,
                        target_vm: vm.to_string(),
                        description: format!(
                            "process name check: {}",
                            String::from_utf8_lossy(needle)
                        ),
                        strategy: PatchStrategy::ForceFalse,
                        confidence: 80,
                    });
                }
            }
        }
    }

    fn scan_cpuid_patterns(&self, data: &[u8], out: &mut Vec<VmDetectionSite>) {
        // Look for CPUID instruction (0F A2) preceded by common setup patterns
        let cpuid = &[0x0F_u8, 0xA2];
        if cpuid.len() > data.len() {
            return;
        }
        for offset in 0..=(data.len() - 2) {
            if &data[offset..offset + 2] == cpuid {
                // Check context: was EAX loaded with a hypervisor leaf?
                let vm_leaf_patterns: &[(&[u8], &str)] = &[
                    (
                        &[0xB8, 0x00, 0x00, 0x00, 0x40],
                        "hypervisor vendor string leaf",
                    ),
                    (&[0xB8, 0x01, 0x00, 0x00, 0x40], "VMware backdoor leaf"),
                    (
                        &[0xB8, 0x01, 0x00, 0x00, 0x00],
                        "standard feature leaf (ecx bit31 check)",
                    ),
                ];
                let has_context = if offset >= 5 {
                    vm_leaf_patterns
                        .iter()
                        .any(|(pat, _)| data[offset - 5..offset] == **pat)
                } else {
                    false
                };

                if has_context {
                    out.push(VmDetectionSite {
                        offset,
                        length: 2,
                        check_type: VmCheckType::CpuidCheck,
                        target_vm: "generic-hypervisor".to_owned(),
                        description: "CPUID hypervisor leaf".to_owned(),
                        strategy: PatchStrategy::Nop,
                        confidence: 85,
                    });
                }
            }
        }
    }

    fn scan_file_artifact_patterns(&self, data: &[u8], out: &mut Vec<VmDetectionSite>) {
        let artifacts: &[(&[u8], &str, &str)] = &[
            (
                b"\\\\.\\VBoxMiniRdrDN",
                "VirtualBox",
                "VirtualBox redirector named pipe",
            ),
            (b"\\\\.\\VBoxTrayIPC", "VirtualBox", "VirtualBox tray IPC"),
            (b"\\\\.\\HGFS", "VMware", "VMware HGFS named pipe"),
            (b"\\\\.\\vmci", "VMware", "VMware VMCI device"),
            (
                b"C:\\windows\\system32\\drivers\\vmmouse.sys",
                "VMware",
                "VMware mouse driver file",
            ),
            (
                b"C:\\windows\\system32\\drivers\\vmhgfs.sys",
                "VMware",
                "VMware HGFS driver file",
            ),
            (
                b"C:\\program files\\oracle\\virtualbox guest additions",
                "VirtualBox",
                "VirtualBox guest additions directory",
            ),
        ];

        for (needle, vm, desc) in artifacts {
            let nlen = needle.len();
            if nlen > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - nlen) {
                if data[offset..offset + nlen].eq_ignore_ascii_case(needle) {
                    out.push(VmDetectionSite {
                        offset,
                        length: nlen,
                        check_type: VmCheckType::FileArtifactCheck,
                        target_vm: vm.to_string(),
                        description: desc.to_string(),
                        strategy: PatchStrategy::ForceFalse,
                        confidence: 88,
                    });
                }
            }
        }
    }
}

fn convert_to_vm_site(site: DetectionSite) -> Option<VmDetectionSite> {
    let (check_type, target_vm) = match &site.technique {
        DetectedTechnique::AntiVm(t) => {
            let check_type = match t {
                AntiVmTechnique::VmwarePortCheck | AntiVmTechnique::VmwareCpuid => {
                    VmCheckType::IoPortCheck
                }
                AntiVmTechnique::VboxRegistry => VmCheckType::RegistryCheck,
                AntiVmTechnique::HyperVCpuid | AntiVmTechnique::QemuCpuid => {
                    VmCheckType::CpuidCheck
                }
                AntiVmTechnique::SandboxArtifacts => VmCheckType::FileArtifactCheck,
                AntiVmTechnique::SuspiciousProcessList => VmCheckType::ProcessNameCheck,
                AntiVmTechnique::NetworkAdapterCheck => VmCheckType::MacAddressCheck,
                AntiVmTechnique::CpuCountCheck => VmCheckType::CpuCountCheck,
                AntiVmTechnique::DiskSizeCheck => VmCheckType::DiskSizeCheck,
                AntiVmTechnique::UptimeCheck => VmCheckType::UptimeCheck,
                AntiVmTechnique::MouseMovementCheck => VmCheckType::FileArtifactCheck,
            };
            let target = match t {
                AntiVmTechnique::VmwarePortCheck | AntiVmTechnique::VmwareCpuid => "VMware",
                AntiVmTechnique::VboxRegistry => "VirtualBox",
                AntiVmTechnique::HyperVCpuid => "Hyper-V",
                AntiVmTechnique::QemuCpuid => "QEMU",
                _ => "generic-vm",
            };
            (check_type, target.to_owned())
        }
        _ => return None,
    };
    Some(VmDetectionSite {
        offset: site.offset,
        length: site.length,
        check_type,
        target_vm,
        description: site.description,
        strategy: site.strategy,
        confidence: site.confidence,
    })
}

const fn technique_for_check(check_type: &VmCheckType) -> AntiVmTechnique {
    match check_type {
        VmCheckType::RegistryCheck => AntiVmTechnique::VboxRegistry,
        VmCheckType::ProcessNameCheck => AntiVmTechnique::SuspiciousProcessList,
        VmCheckType::CpuidCheck => AntiVmTechnique::VmwareCpuid,
        VmCheckType::IoPortCheck => AntiVmTechnique::VmwarePortCheck,
        VmCheckType::MacAddressCheck => AntiVmTechnique::NetworkAdapterCheck,
        VmCheckType::DiskSizeCheck => AntiVmTechnique::DiskSizeCheck,
        VmCheckType::CpuCountCheck => AntiVmTechnique::CpuCountCheck,
        VmCheckType::FileArtifactCheck => AntiVmTechnique::SandboxArtifacts,
        VmCheckType::UptimeCheck => AntiVmTechnique::UptimeCheck,
    }
}

fn build_vm_replacement(
    original: &[u8],
    strategy: PatchStrategy,
    check_type: &VmCheckType,
) -> Vec<u8> {
    let len = original.len();
    match strategy {
        PatchStrategy::Nop => vec![0x90u8; len],
        PatchStrategy::ForceFalse => {
            // For string-based VM artifact checks, overwrite with null bytes
            // (so the string comparison will fail)
            match check_type {
                VmCheckType::RegistryCheck
                | VmCheckType::ProcessNameCheck
                | VmCheckType::FileArtifactCheck => vec![0x00u8; len],
                _ => {
                    let mut b = vec![0x90u8; len];
                    if len >= 2 {
                        b[0] = 0x31;
                        b[1] = 0xC0;
                    }
                    b
                }
            }
        }
        PatchStrategy::ReturnZero => {
            let mut b = vec![0x90u8; len];
            if len >= 3 {
                b[0] = 0x31;
                b[1] = 0xC0;
                b[2] = 0xC3;
            }
            b
        }
        PatchStrategy::ReturnOne => {
            let mut b = vec![0x90u8; len];
            if len >= 6 {
                b[0] = 0xB8;
                b[1] = 0x01;
                b[2] = 0x00;
                b[3] = 0x00;
                b[4] = 0x00;
                b[5] = 0xC3;
            }
            b
        }
        PatchStrategy::ForceTrue | PatchStrategy::SkipBlock => {
            vec![0x90u8; len]
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass() -> AntiVmBypass {
        AntiVmBypass::new()
    }

    #[test]
    fn test_scan_vbox_registry() {
        let data = b"HARDWARE\\ACPI\\DSDT\\VBOX__ is present";
        let sites = bypass().scan(data);
        assert!(
            sites
                .iter()
                .any(|s| s.check_type == VmCheckType::RegistryCheck)
        );
    }

    #[test]
    fn test_scan_vmtoolsd_process() {
        let data = b"process found: vmtoolsd.exe";
        let sites = bypass().scan(data);
        assert!(
            sites
                .iter()
                .any(|s| s.check_type == VmCheckType::ProcessNameCheck && s.target_vm == "VMware")
        );
    }

    #[test]
    fn test_scan_cpuid_with_context() {
        // mov eax, 0x40000000 + cpuid
        let data = [0xB8u8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2];
        let sites = bypass().scan(&data);
        assert!(
            sites
                .iter()
                .any(|s| s.check_type == VmCheckType::CpuidCheck)
        );
    }

    #[test]
    fn test_scan_file_artifact() {
        let data = b"\\\\.\\HGFS pipe check";
        let sites = bypass().scan(data);
        assert!(
            sites
                .iter()
                .any(|s| s.check_type == VmCheckType::FileArtifactCheck)
        );
    }

    #[test]
    fn test_generate_patches_registry() {
        let data = b"HARDWARE\\ACPI\\DSDT\\VBOX__ here";
        let sites = bypass().scan(data);
        let patches = bypass().generate_patches(data, &sites);
        assert!(!patches.is_empty());
        // Registry patches should zero out the bytes
        for p in &patches {
            if p.technique == DetectedTechnique::AntiVm(AntiVmTechnique::VboxRegistry) {
                assert!(p.replacement.iter().all(|&b| b == 0x00));
            }
        }
    }

    #[test]
    fn test_patch_registry_checks() {
        let mut data = b"HARDWARE\\ACPI\\DSDT\\VBOX__ here\x00".to_vec();
        let count = bypass().patch_registry_checks(&mut data);
        assert!(count > 0);
    }

    #[test]
    fn test_patch_process_name_checks() {
        let mut data = b"vmtoolsd.exe\x00vboxservice.exe\x00".to_vec();
        let count = bypass().patch_process_name_checks(&mut data);
        assert!(count >= 2);
    }

    #[test]
    fn test_vm_detection_site_serialization() {
        let site = VmDetectionSite {
            offset: 100,
            length: 10,
            check_type: VmCheckType::RegistryCheck,
            target_vm: "VirtualBox".to_owned(),
            description: "test".to_owned(),
            strategy: PatchStrategy::ForceFalse,
            confidence: 85,
        };
        let json = serde_json::to_string(&site).unwrap();
        let decoded: VmDetectionSite = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.target_vm, "VirtualBox");
    }
}
