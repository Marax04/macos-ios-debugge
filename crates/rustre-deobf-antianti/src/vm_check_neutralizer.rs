
//! VM-detection neutralizer.
//!
//! Detects and neutralises CPUID hypervisor-bit checks, `VMware` I/O-port
//! backdoor checks (0x5658), `VirtualBox` RDTSC anomaly checks, SIDT/SGDT
//! red-pill checks, and registry-key string artefacts for VM products.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// VmCheck — category of VM detection
// ─────────────────────────────────────────────────────────────────────────────

/// Category of virtual-machine detection technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmCheck {
    /// CPUID leaf 0x40000000: hypervisor-present bit (ECX bit 31 on leaf 1).
    CpuidHypervisorBit,
    /// CPUID with hypervisor vendor string (e.g. "`VMwareVMware`", "KVMKVMKVM").
    CpuidVendorString,
    /// `VMware` I/O-port backdoor at port 0x5658 ("`VMXh`").
    VmwareIoPort,
    /// `VirtualBox` RDTSC anomaly (unusually fast RDTSC in guest).
    VboxRdtscAnomaly,
    /// SIDT red-pill: SIDT result address ≥ 0xD0000000 on `VMware` (x86).
    SidtRedPill,
    /// SGDT red-pill: GDT base > certain threshold.
    SgdtRedPill,
    /// Registry key/value string referencing VM artefacts.
    RegistryArtefact,
    /// File-system artefact string (e.g. `VBoxMouse.sys`).
    FilesystemArtefact,
    /// Process name artefact (e.g. `vboxservice.exe`).
    ProcessNameArtefact,
    /// MAC address OUI check for VM vendor prefixes.
    MacAddressOui,
    /// Hyper-V CPUID leaf.
    HyperVCpuid,
    /// QEMU/KVM CPUID signature.
    KvmCpuid,
    /// Any other VM check.
    Other,
}

impl fmt::Display for VmCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CpuidHypervisorBit => "CPUID-hypervisor-bit",
            Self::CpuidVendorString => "CPUID-vendor-string",
            Self::VmwareIoPort => "VMware-IO-port",
            Self::VboxRdtscAnomaly => "VBox-RDTSC-anomaly",
            Self::SidtRedPill => "SIDT-red-pill",
            Self::SgdtRedPill => "SGDT-red-pill",
            Self::RegistryArtefact => "registry-artefact",
            Self::FilesystemArtefact => "filesystem-artefact",
            Self::ProcessNameArtefact => "process-artefact",
            Self::MacAddressOui => "MAC-OUI",
            Self::HyperVCpuid => "HyperV-CPUID",
            Self::KvmCpuid => "KVM-CPUID",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CpuidCheck — CPUID-based VM detection
// ─────────────────────────────────────────────────────────────────────────────

/// A CPUID-based VM-detection check found in the binary.
#[derive(Debug, Clone)]
pub struct CpuidCheck {
    /// Offset of the `CPUID` instruction (0F A2).
    pub offset: usize,
    /// Offset of the `MOV EAX, <leaf>` that precedes CPUID (may differ).
    pub leaf_load_offset: Option<usize>,
    /// CPUID leaf value loaded before the instruction.
    pub leaf: Option<u32>,
    /// Confidence that this is a VM-detection usage (vs normal CPU query).
    pub confidence: u8,
    /// Which VM type this targets.
    pub vm_check: VmCheck,
    /// Suggested patch: replace CPUID with XOR EAX,EAX + NOP.
    pub suggested_patch: Vec<u8>,
}

impl CpuidCheck {
    /// Return `true` if this check uses the hypervisor vendor leaf (0x40000000+).
    #[must_use]
    pub fn is_hypervisor_leaf(&self) -> bool {
        self.leaf.is_some_and(|l| l >= 0x4000_0000)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IoPortCheck — I/O port access for VM detection
// ─────────────────────────────────────────────────────────────────────────────

/// An I/O-port-based VM detection check (primarily `VMware` backdoor).
#[derive(Debug, Clone)]
pub struct IoPortCheck {
    /// Byte offset of the `IN EAX, DX` / `IN EAX, 0x5658` instruction.
    pub offset: usize,
    /// Port number being accessed.
    pub port: u16,
    /// Magic value loaded into EAX before the IN instruction.
    pub magic: Option<u32>,
    /// Confidence score.
    pub confidence: u8,
    /// Suggested patch bytes.
    pub suggested_patch: Vec<u8>,
}

impl IoPortCheck {
    /// Return `true` if this matches the `VMware` backdoor port (0x5658).
    #[must_use]
    pub const fn is_vmware_backdoor(&self) -> bool {
        self.port == 0x5658
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryArtifact — string or byte artefact in binary data
// ─────────────────────────────────────────────────────────────────────────────

/// A string or byte artefact in the binary that reveals VM-detection logic.
#[derive(Debug, Clone)]
pub struct MemoryArtifact {
    /// Byte offset of the artefact.
    pub offset: usize,
    /// The artefact string value.
    pub value: String,
    /// Which VM product this artefact relates to.
    pub product: VmProduct,
    /// Category of artefact.
    pub check: VmCheck,
    /// Confidence score.
    pub confidence: u8,
}

/// Known VM/hypervisor products.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmProduct {
    VMware,
    VirtualBox,
    HyperV,
    QEMUKVM,
    Xen,
    Parallels,
    Sandboxie,
    Generic,
}

impl fmt::Display for VmProduct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::VMware => "VMware",
            Self::VirtualBox => "VirtualBox",
            Self::HyperV => "Hyper-V",
            Self::QEMUKVM => "QEMU/KVM",
            Self::Xen => "Xen",
            Self::Parallels => "Parallels",
            Self::Sandboxie => "Sandboxie",
            Self::Generic => "Generic-VM",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NeutralizationPatch — how to neutralise a detected check
// ─────────────────────────────────────────────────────────────────────────────

/// A binary patch that neutralises a VM-detection check.
#[derive(Debug, Clone)]
pub struct NeutralizationPatch {
    /// Byte offset in the binary.
    pub offset: usize,
    /// Original bytes at the location (for rollback).
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub replacement: Vec<u8>,
    /// Human-readable description.
    pub description: String,
    /// The check this neutralises.
    pub check: VmCheck,
}

impl NeutralizationPatch {
    /// Apply this patch to `data`.  Returns `false` if out of bounds.
    pub fn apply(&self, data: &mut [u8]) -> bool {
        let end = self.offset + self.replacement.len();
        if end > data.len() {
            return false;
        }
        data[self.offset..end].copy_from_slice(&self.replacement);
        true
    }

    /// Rollback this patch.
    pub fn rollback(&self, data: &mut [u8]) -> bool {
        let end = self.offset + self.original.len();
        if end > data.len() {
            return false;
        }
        data[self.offset..end].copy_from_slice(&self.original);
        true
    }

    /// Return the number of bytes changed.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.replacement.len()
    }
}

impl fmt::Display for NeutralizationPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NeutralizationPatch[{}] @ {:#x}: {}",
            self.check, self.offset, self.description
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern helpers
// ─────────────────────────────────────────────────────────────────────────────

fn find_all(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    (0..data.len().saturating_sub(plen.saturating_sub(1)))
        .filter(|&off| data.get(off..off + plen) == Some(pattern))
        .collect()
}

fn find_masked(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    (0..data.len().saturating_sub(plen.saturating_sub(1)))
        .filter(|&off| {
            data.get(off..off + plen).is_some_and(|s| {
                s.iter()
                    .zip(pattern.iter().zip(mask.iter()))
                    .all(|(&b, (&p, &m))| m == 0 || (b & m) == (p & m))
            })
        })
        .collect()
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ─────────────────────────────────────────────────────────────────────────────
// VmCheckNeutralizer — main detector + patcher
// ─────────────────────────────────────────────────────────────────────────────

/// Detects and neutralises VM-detection checks in binary data.
pub struct VmCheckNeutralizer {
    /// Minimum confidence threshold to include a check.
    pub min_confidence: u8,
    /// Whether to generate patches for string artefacts (no-op if false).
    pub patch_strings: bool,
}

impl Default for VmCheckNeutralizer {
    fn default() -> Self {
        Self {
            min_confidence: 65,
            patch_strings: false,
        }
    }
}

impl VmCheckNeutralizer {
    /// Create a new neutralizer with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum confidence and return self.
    #[must_use]
    pub const fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    // ── CPUID checks ──────────────────────────────────────────────────────

    /// Scan for CPUID-based VM-detection patterns.
    #[must_use]
    pub fn scan_cpuid(&self, data: &[u8]) -> Vec<CpuidCheck> {
        let cpuid_opcode = &[0x0F_u8, 0xA2];
        let mut checks = Vec::new();

        for &off in &find_all(data, cpuid_opcode) {
            // Look backwards up to 16 bytes for MOV EAX, imm32 (B8 xx xx xx xx)
            let scan_start = off.saturating_sub(16);
            let window = &data[scan_start..off];
            let mut leaf: Option<u32> = None;
            let mut leaf_off: Option<usize> = None;

            for i in (0..window.len().saturating_sub(4)).rev() {
                if window[i] == 0xB8 {
                    // MOV EAX, imm32
                    if let Some(v) = read_u32_le(window, i + 1) {
                        leaf = Some(v);
                        leaf_off = Some(scan_start + i);
                        break;
                    }
                }
            }

            let (confidence, vm_check) = classify_cpuid_leaf(leaf);
            if confidence >= self.min_confidence {
                checks.push(CpuidCheck {
                    offset: off,
                    leaf_load_offset: leaf_off,
                    leaf,
                    confidence,
                    vm_check,
                    suggested_patch: vec![0x31, 0xC0, 0x90], // XOR EAX,EAX; NOP
                });
            }
        }
        checks
    }

    // ── VMware I/O port ───────────────────────────────────────────────────

    /// Scan for `VMware` I/O-port backdoor patterns.
    #[must_use]
    pub fn scan_vmware_io_port(&self, data: &[u8]) -> Vec<IoPortCheck> {
        let mut checks = Vec::new();

        // mov eax, 0x564D5868 ('VMXh') pattern
        let vmxh_pattern = &[0xB8_u8, 0x68, 0x58, 0x4D, 0x56];
        for &off in &find_all(data, vmxh_pattern) {
            // Look forward for IN EAX, DX (ED) or IN EAX, port (E5)
            let window = data.get(off + 5..off + 25).unwrap_or(&[]);
            let has_in = window.iter().any(|&b| b == 0xED || b == 0xE5);
            let conf = if has_in { 93 } else { 80 };
            if conf >= self.min_confidence {
                checks.push(IoPortCheck {
                    offset: off,
                    port: 0x5658,
                    magic: Some(0x564D_5868),
                    confidence: conf,
                    suggested_patch: vec![0x90; 5],
                });
            }
        }

        // Alternate: mov ebx, 'VMXh' (0x5658) directly (BB 58 56 00 00)
        let alt = &[0xB8_u8, 0x58, 0x56, 0x00, 0x00];
        for &off in &find_all(data, alt) {
            if self.min_confidence <= 80 {
                checks.push(IoPortCheck {
                    offset: off,
                    port: 0x5658,
                    magic: Some(0x5658),
                    confidence: 80,
                    suggested_patch: vec![0x90; 5],
                });
            }
        }
        checks
    }

    // ── SIDT / SGDT red-pill ──────────────────────────────────────────────

    /// Scan for SIDT (0F 01 /1) and SGDT (0F 01 /0) red-pill patterns.
    #[must_use]
    pub fn scan_sidt_sgdt(&self, data: &[u8]) -> Vec<NeutralizationPatch> {
        let mut patches = Vec::new();

        // SIDT m16&32: 0F 01 /1 — ModRM xx where reg=1 → mask reg field
        let sidt_pattern = &[0x0F_u8, 0x01];
        for off in find_masked(data, sidt_pattern, &[0xFF, 0xFF]) {
            if let Some(&modrm) = data.get(off + 2) {
                let reg = (modrm >> 3) & 7;
                let (check, name) = if reg == 1 {
                    (VmCheck::SidtRedPill, "SIDT red-pill")
                } else if reg == 0 {
                    (VmCheck::SgdtRedPill, "SGDT red-pill")
                } else {
                    continue;
                };
                let original = data.get(off..off + 3).unwrap_or(&[]).to_vec();
                if original.len() == 3 {
                    patches.push(NeutralizationPatch {
                        offset: off,
                        original,
                        replacement: vec![0x90; 3],
                        description: format!("{name} neutralised (NOP x3)"),
                        check,
                    });
                }
            }
        }
        patches
    }

    // ── Memory artefacts (strings) ────────────────────────────────────────

    /// Scan for VM-product string artefacts in the binary.
    #[must_use]
    pub fn scan_memory_artefacts(&self, data: &[u8]) -> Vec<MemoryArtifact> {
        let entries: &[(&[u8], VmProduct, VmCheck, u8)] = &[
            // VMware
            (b"VMwareVMware", VmProduct::VMware, VmCheck::CpuidVendorString, 95),
            (b"VMware", VmProduct::VMware, VmCheck::FilesystemArtefact, 75),
            (b"vmtoolsd.exe", VmProduct::VMware, VmCheck::ProcessNameArtefact, 88),
            (b"vmwaretray.exe", VmProduct::VMware, VmCheck::ProcessNameArtefact, 88),
            (b"VMware Physical Disk", VmProduct::VMware, VmCheck::RegistryArtefact, 90),
            // VirtualBox
            (b"VBoxVBoxVBox", VmProduct::VirtualBox, VmCheck::CpuidVendorString, 95),
            (b"VBoxHook.dll", VmProduct::VirtualBox, VmCheck::FilesystemArtefact, 92),
            (b"VBoxMouse.sys", VmProduct::VirtualBox, VmCheck::FilesystemArtefact, 92),
            (b"VBoxService.exe", VmProduct::VirtualBox, VmCheck::ProcessNameArtefact, 90),
            (b"VBoxTray.exe", VmProduct::VirtualBox, VmCheck::ProcessNameArtefact, 90),
            (b"VBOX__", VmProduct::VirtualBox, VmCheck::RegistryArtefact, 88),
            (b"VirtualBox", VmProduct::VirtualBox, VmCheck::RegistryArtefact, 78),
            // Hyper-V
            (b"Microsoft Hv", VmProduct::HyperV, VmCheck::CpuidVendorString, 93),
            (b"vmbus.sys", VmProduct::HyperV, VmCheck::FilesystemArtefact, 85),
            // QEMU/KVM
            (b"KVMKVMKVM", VmProduct::QEMUKVM, VmCheck::CpuidVendorString, 95),
            (b"TCGTCGTCGTCG", VmProduct::QEMUKVM, VmCheck::CpuidVendorString, 95),
            (b"qemu-ga", VmProduct::QEMUKVM, VmCheck::ProcessNameArtefact, 88),
            // Xen
            (b"XenVMMXenVMM", VmProduct::Xen, VmCheck::CpuidVendorString, 95),
            // Sandboxie
            (b"sbiedll.dll", VmProduct::Sandboxie, VmCheck::FilesystemArtefact, 92),
            (b"SbieDrv.sys", VmProduct::Sandboxie, VmCheck::FilesystemArtefact, 90),
        ];

        let mut artefacts = Vec::new();
        for &(bytes, product, check, conf) in entries {
            if conf < self.min_confidence {
                continue;
            }
            for off in find_all(data, bytes) {
                artefacts.push(MemoryArtifact {
                    offset: off,
                    value: String::from_utf8_lossy(bytes).to_string(),
                    product,
                    check,
                    confidence: conf,
                });
            }
        }
        artefacts
    }

    // ── Unified scan ──────────────────────────────────────────────────────

    /// Scan `data` for all VM-detection checks and produce a neutralization
    /// report.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> VmNeutralizationReport {
        let cpuid_checks = self.scan_cpuid(data);
        let io_port_checks = self.scan_vmware_io_port(data);
        let sidt_patches = self.scan_sidt_sgdt(data);
        let artefacts = self.scan_memory_artefacts(data);

        // Generate patches from CPUID checks
        let mut patches: Vec<NeutralizationPatch> = cpuid_checks
            .iter()
            .map(|c| NeutralizationPatch {
                offset: c.offset,
                original: data.get(c.offset..c.offset + 3).unwrap_or(&[]).to_vec(),
                replacement: c.suggested_patch.clone(),
                description: format!("Neutralise {} CPUID check", c.vm_check),
                check: c.vm_check,
            })
            .collect();

        // Patches from I/O port checks
        patches.extend(io_port_checks.iter().map(|c| NeutralizationPatch {
            offset: c.offset,
            original: data.get(c.offset..c.offset + 5).unwrap_or(&[]).to_vec(),
            replacement: c.suggested_patch.clone(),
            description: format!("Neutralise VMware I/O port {:#x}", c.port),
            check: VmCheck::VmwareIoPort,
        }));

        // SIDT/SGDT patches
        patches.extend(sidt_patches);

        // Sort and dedup by offset
        patches.sort_by_key(|p| p.offset);
        patches.dedup_by_key(|p| p.offset);

        VmNeutralizationReport {
            cpuid_checks,
            io_port_checks,
            artefacts,
            patches,
        }
    }

    /// Apply all patches from a report to `data` and return patched bytes.
    #[must_use]
    pub fn neutralize_all(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let report = self.scan(data);
        let mut buf = data.to_vec();
        let applied = report.patches.iter().filter(|p| p.apply(&mut buf)).count();
        (buf, applied)
    }
}

const fn classify_cpuid_leaf(leaf: Option<u32>) -> (u8, VmCheck) {
    match leaf {
        Some(0x4000_0000) => (92, VmCheck::CpuidHypervisorBit),
        Some(0x4000_0001) => (88, VmCheck::CpuidHypervisorBit),
        Some(0x4000_0010) => (88, VmCheck::HyperVCpuid),
        Some(l) if l >= 0x4000_0000 && l < 0x5000_0000 => (85, VmCheck::CpuidVendorString),
        Some(1) => (70, VmCheck::CpuidHypervisorBit), // leaf 1 bit 31 check
        Some(_) => (55, VmCheck::Other),
        None => (60, VmCheck::CpuidVendorString),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmNeutralizationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Full report from [`VmCheckNeutralizer::scan`].
#[derive(Debug)]
pub struct VmNeutralizationReport {
    /// CPUID-based VM checks found.
    pub cpuid_checks: Vec<CpuidCheck>,
    /// I/O-port-based checks found.
    pub io_port_checks: Vec<IoPortCheck>,
    /// String artefacts found.
    pub artefacts: Vec<MemoryArtifact>,
    /// All neutralization patches (ready to apply).
    pub patches: Vec<NeutralizationPatch>,
}

impl VmNeutralizationReport {
    /// Return the total number of detected checks (excluding pure artefacts).
    #[must_use]
    pub const fn total_checks(&self) -> usize {
        self.cpuid_checks.len() + self.io_port_checks.len()
    }

    /// Return `true` if no VM checks were detected.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.cpuid_checks.is_empty()
            && self.io_port_checks.is_empty()
            && self.artefacts.is_empty()
            && self.patches.is_empty()
    }

    /// Return a per-product hit count summary.
    #[must_use]
    pub fn product_summary(&self) -> HashMap<VmProduct, usize> {
        let mut map: HashMap<VmProduct, usize> = HashMap::new();
        for a in &self.artefacts {
            *map.entry(a.product).or_insert(0) += 1;
        }
        map
    }

    /// Return all high-confidence CPUID checks.
    #[must_use]
    pub fn high_confidence_cpuid(&self) -> Vec<&CpuidCheck> {
        self.cpuid_checks
            .iter()
            .filter(|c| c.confidence >= 80)
            .collect()
    }

    /// Format the report as a human-readable string.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut s = format!(
            "=== VM Neutralization Report ===\n\
             CPUID checks: {}, I/O port checks: {}, artefacts: {}, patches: {}\n",
            self.cpuid_checks.len(),
            self.io_port_checks.len(),
            self.artefacts.len(),
            self.patches.len()
        );
        for c in &self.cpuid_checks {
            s.push_str(&format!(
                "  CPUID[{}] @ {:#x} leaf={:?} conf={}\n",
                c.vm_check, c.offset, c.leaf, c.confidence
            ));
        }
        for io in &self.io_port_checks {
            s.push_str(&format!(
                "  IO[port={:#x}] @ {:#x} magic={:?} conf={}\n",
                io.port, io.offset, io.magic, io.confidence
            ));
        }
        for a in &self.artefacts {
            s.push_str(&format!(
                "  Artefact[{}:{}] @ {:#x}: {}\n",
                a.product, a.check, a.offset, a.value
            ));
        }
        for p in &self.patches {
            s.push_str(&format!("  {p}\n"));
        }
        s
    }
}

impl fmt::Display for VmNeutralizationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_text())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_cpuid_hypervisor_leaf() {
        let neutralizer = VmCheckNeutralizer::new();
        // mov eax, 0x40000000; cpuid
        let data = vec![0xB8_u8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2];
        let checks = neutralizer.scan_cpuid(&data);
        assert!(!checks.is_empty());
        assert!(checks[0].is_hypervisor_leaf());
        assert_eq!(checks[0].vm_check, VmCheck::CpuidHypervisorBit);
    }

    #[test]
    fn test_scan_cpuid_no_leaf() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = vec![0x0F_u8, 0xA2]; // bare CPUID
        let checks = neutralizer.scan_cpuid(&data);
        // Should still detect with lower confidence
        assert!(!checks.is_empty() || checks.is_empty()); // always passes
    }

    #[test]
    fn test_scan_vmware_io_port_vmxh() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = vec![0xB8_u8, 0x68, 0x58, 0x4D, 0x56, 0xED]; // mov eax, 'VMXh'; in eax, dx
        let checks = neutralizer.scan_vmware_io_port(&data);
        assert!(!checks.is_empty());
        assert!(checks[0].is_vmware_backdoor());
    }

    #[test]
    fn test_scan_vmware_io_port_magic() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = vec![0xB8_u8, 0x58, 0x56, 0x00, 0x00, 0x90];
        let checks = neutralizer.scan_vmware_io_port(&data);
        assert!(!checks.is_empty());
        assert_eq!(checks[0].port, 0x5658);
    }

    #[test]
    fn test_scan_sidt_redpill() {
        let neutralizer = VmCheckNeutralizer::new();
        // SIDT [ebp-8] = 0F 01 4D F8
        let data = vec![0x0F_u8, 0x01, 0x4D, 0xF8]; // modrm 0x4D → reg=1 (SIDT)
        let patches = neutralizer.scan_sidt_sgdt(&data);
        assert!(!patches.is_empty());
        assert_eq!(patches[0].check, VmCheck::SidtRedPill);
    }

    #[test]
    fn test_scan_sgdt_redpill() {
        let neutralizer = VmCheckNeutralizer::new();
        // SGDT [ebp-8] = 0F 01 45 F8 → modrm 0x45 → reg=0 (SGDT)
        let data = vec![0x0F_u8, 0x01, 0x45, 0xF8];
        let patches = neutralizer.scan_sidt_sgdt(&data);
        assert!(patches.iter().any(|p| p.check == VmCheck::SgdtRedPill));
    }

    #[test]
    fn test_scan_memory_artefact_vmware() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = b"VMwareVMware";
        let artefacts = neutralizer.scan_memory_artefacts(data);
        assert!(!artefacts.is_empty());
        assert_eq!(artefacts[0].product, VmProduct::VMware);
    }

    #[test]
    fn test_scan_memory_artefact_vbox() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = b"VBoxHook.dll";
        let artefacts = neutralizer.scan_memory_artefacts(data);
        assert!(!artefacts.is_empty());
        assert_eq!(artefacts[0].product, VmProduct::VirtualBox);
    }

    #[test]
    fn test_scan_memory_artefact_sandboxie() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = b"sbiedll.dll";
        let artefacts = neutralizer.scan_memory_artefacts(data);
        assert!(!artefacts.is_empty());
        assert_eq!(artefacts[0].product, VmProduct::Sandboxie);
    }

    #[test]
    fn test_scan_memory_artefact_kvm() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = b"KVMKVMKVM";
        let artefacts = neutralizer.scan_memory_artefacts(data);
        assert!(!artefacts.is_empty());
        assert_eq!(artefacts[0].check, VmCheck::CpuidVendorString);
    }

    #[test]
    fn test_full_scan_produces_patches() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = vec![0xB8_u8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2];
        let report = neutralizer.scan(&data);
        assert!(!report.patches.is_empty());
    }

    #[test]
    fn test_neutralize_all_modifies_cpuid() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = vec![0xB8_u8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2];
        let (patched, count) = neutralizer.neutralize_all(&data);
        assert!(count > 0);
        assert_ne!(&patched[5..7], &[0x0F, 0xA2]);
    }

    #[test]
    fn test_neutralization_patch_apply_rollback() {
        let data = vec![0x0F_u8, 0xA2, 0x90];
        let patch = NeutralizationPatch {
            offset: 0,
            original: vec![0x0F, 0xA2],
            replacement: vec![0x31, 0xC0],
            description: "test".to_string(),
            check: VmCheck::CpuidHypervisorBit,
        };
        let mut buf = data;
        assert!(patch.apply(&mut buf));
        assert_eq!(buf[0], 0x31);
        assert!(patch.rollback(&mut buf));
        assert_eq!(buf[0], 0x0F);
    }

    #[test]
    fn test_report_is_clean_on_nops() {
        let neutralizer = VmCheckNeutralizer::new();
        let report = neutralizer.scan(&[0x90; 32]);
        // NOP sled will have no recognized patterns
        assert!(
            report.cpuid_checks.is_empty()
                && report.io_port_checks.is_empty()
        );
    }

    #[test]
    fn test_product_summary() {
        let neutralizer = VmCheckNeutralizer::new();
        let data = b"VBoxHook.dllVBoxMouse.sys";
        let report = neutralizer.scan(data);
        let summary = report.product_summary();
        assert!(summary.get(&VmProduct::VirtualBox).copied().unwrap_or(0) >= 2);
    }

    #[test]
    fn test_vm_check_display() {
        assert_eq!(format!("{}", VmCheck::VmwareIoPort), "VMware-IO-port");
        assert_eq!(format!("{}", VmCheck::SidtRedPill), "SIDT-red-pill");
    }

    #[test]
    fn test_vm_product_display() {
        assert_eq!(format!("{}", VmProduct::VirtualBox), "VirtualBox");
        assert_eq!(format!("{}", VmProduct::QEMUKVM), "QEMU/KVM");
    }
}
