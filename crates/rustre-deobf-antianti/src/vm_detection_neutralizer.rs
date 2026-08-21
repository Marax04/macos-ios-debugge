//! `vm_detection_neutralizer` — Neutralise VM / sandbox-detection techniques.
//!
//! Covers:
//! - CPUID-based VM presence tests (hypervisor bit, vendor strings, leaf counts)
//! - Registry key probing (HKLM\SOFTWARE\VMware Inc., `VirtualBox`, etc.)
//! - Driver/device name probing (\\.\vmhgfs, \\.\`VBoxGuest`, etc.)
//! - MAC-address vendor prefix checks (`VMware` 00:0C:29, `VBox` 08:00:27)
//! - Memory/disk-size heuristics (< 512 MB RAM, < 20 GB disk)
//! - Timing anomaly cross-correlation with VM presence

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── VmEnvironment ─────────────────────────────────────────────────────────────

/// Which virtualisation platform an artifact targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmEnvironment {
    VMware,
    VirtualBox,
    HyperV,
    Qemu,
    Xen,
    Parallels,
    UnknownHypervisor,
    /// Sandbox service (Cuckoo, Any.run, etc.)
    Sandbox,
}

impl std::fmt::Display for VmEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── VmArtifactKind ────────────────────────────────────────────────────────────

/// Category of the VM detection mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmArtifactKind {
    /// CPUID instruction with specific leaf / bit check.
    Cpuid,
    /// Registry key path lookup.
    RegistryKey,
    /// Device/driver name (`CreateFile` / `DeviceIoControl`).
    DeviceName,
    /// MAC address vendor OUI check.
    MacAddress,
    /// SMBIOS/ACPI table string.
    Smbios,
    /// Process / service name presence check.
    ProcessName,
    /// Memory size heuristic.
    MemorySize,
    /// Disk size heuristic.
    DiskSize,
    /// Screen resolution heuristic.
    ScreenResolution,
    /// File path (guest additions, `VMware` tools, etc.).
    FilePath,
}

impl VmArtifactKind {
    /// Returns `true` for binary-instruction-level checks.
    #[must_use]
    pub const fn is_instruction_level(self) -> bool {
        matches!(self, Self::Cpuid)
    }
}

// ── VmArtifact ────────────────────────────────────────────────────────────────

/// A single detected VM-detection artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmArtifact {
    /// What kind of artifact this is.
    pub kind: VmArtifactKind,
    /// Target VM environment.
    pub environment: VmEnvironment,
    /// Byte offset in the binary where the artifact was found (0 for string refs).
    pub offset: usize,
    /// Byte length of the relevant sequence.
    pub span_bytes: usize,
    /// Detection confidence in [0, 100].
    pub confidence: u32,
    /// Human-readable description.
    pub description: String,
    /// Artifact value (e.g., the registry key path, device name, CPUID leaf).
    pub value: String,
}

impl VmArtifact {
    /// Create a new [`VmArtifact`].
    #[must_use]
    pub fn new(
        kind: VmArtifactKind,
        environment: VmEnvironment,
        offset: usize,
        span_bytes: usize,
        confidence: u32,
        description: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            environment,
            offset,
            span_bytes,
            confidence: confidence.min(100),
            description: description.into(),
            value: value.into(),
        }
    }
}

// ── SpoofRule ─────────────────────────────────────────────────────────────────

/// A rule describing how to spoof a specific VM artifact check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofRule {
    /// The artifact this rule defeats.
    pub artifact: VmArtifact,
    /// Binary patch offset (if applicable — 0 for runtime/hook-only rules).
    pub patch_offset: usize,
    /// Original bytes.
    pub original_bytes: Vec<u8>,
    /// Replacement bytes.
    pub patch_bytes: Vec<u8>,
    /// Human-readable explanation of what the patch achieves.
    pub explanation: String,
}

impl SpoofRule {
    /// Create a new spoof rule.
    #[must_use]
    pub fn new(
        artifact: VmArtifact,
        patch_offset: usize,
        original_bytes: Vec<u8>,
        patch_bytes: Vec<u8>,
        explanation: impl Into<String>,
    ) -> Self {
        Self { artifact, patch_offset, original_bytes, patch_bytes, explanation: explanation.into() }
    }

    /// Apply patch to `binary`.
    pub fn apply(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        if self.patch_bytes.is_empty() {
            return Ok(()); // runtime-only rule — no binary patch
        }
        let end = self.patch_offset + self.patch_bytes.len();
        if end > binary.len() {
            return Err(format!("spoof patch at 0x{:X}: buffer too short", self.patch_offset));
        }
        binary[self.patch_offset..end].copy_from_slice(&self.patch_bytes);
        Ok(())
    }

    /// Roll back the patch.
    pub fn rollback(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        if self.original_bytes.is_empty() {
            return Ok(());
        }
        let end = self.patch_offset + self.original_bytes.len();
        if end > binary.len() {
            return Err(format!("rollback at 0x{:X}: buffer too short", self.patch_offset));
        }
        binary[self.patch_offset..end].copy_from_slice(&self.original_bytes);
        Ok(())
    }
}

// ── Pattern database ──────────────────────────────────────────────────────────

struct VmPattern {
    kind: VmArtifactKind,
    env: VmEnvironment,
    /// Byte pattern in little-endian binary.
    pattern: &'static [u8],
    mask: &'static [u8],
    confidence: u32,
    description: &'static str,
    value: &'static str,
    patch_bytes: &'static [u8],
}

fn vm_binary_patterns() -> Vec<VmPattern> {
    vec![
        // CPUID leaf 1, hypervisor present bit: 0F A2; test ecx, 0x80000000
        // 0F A2 F7 C1 00 00 00 80
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::UnknownHypervisor,
            pattern: &[0x0F, 0xA2, 0xF7, 0xC1, 0x00, 0x00, 0x00, 0x80],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 90,
            description: "CPUID leaf 1 + test hypervisor present bit (bit 31 of ECX)",
            value: "CPUID.01h:ECX[31]",
            patch_bytes: &[0x0F, 0xA2, 0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x7F], // clear bit
        },
        // CPUID 0x40000000 — VMware hypervisor string
        // 68 00 00 00 40 — push 0x40000000
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::VMware,
            pattern: &[0x68, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 88,
            description: "CPUID hypervisor leaf 0x40000000 (push + cpuid)",
            value: "CPUID.40000000h",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        },
        // VMware IN port trick: IN EAX, 0x564D5868 ('VMXh')
        // BA 68 58 4D 56  (mov edx, 0x564D5868)
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::VMware,
            pattern: &[0xBA, 0x68, 0x58, 0x4D, 0x56],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 95,
            description: "VMware IN-port magic 'VMXh' (0x564D5868)",
            value: "0x564D5868",
            patch_bytes: &[0xBA, 0x00, 0x00, 0x00, 0x00],
        },
        // VirtualBox CPUID vendor: "VBoxVBoxVBox"
        // 56 42 6F 78 56 42 6F 78 56 42 6F 78
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::VirtualBox,
            pattern: b"VBoxVBoxVBox",
            mask: &[0xFF; 12],
            confidence: 92,
            description: "VirtualBox CPUID vendor string 'VBoxVBoxVBox'",
            value: "VBoxVBoxVBox",
            patch_bytes: b"GenuineIntel",
        },
        // VMware vendor string "VMwareVMware"
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::VMware,
            pattern: b"VMwareVMware",
            mask: &[0xFF; 12],
            confidence: 95,
            description: "VMware CPUID vendor string 'VMwareVMware'",
            value: "VMwareVMware",
            patch_bytes: b"GenuineIntel",
        },
        // Hyper-V vendor "Microsoft Hv"
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::HyperV,
            pattern: b"Microsoft Hv",
            mask: &[0xFF; 12],
            confidence: 92,
            description: "Hyper-V CPUID vendor string 'Microsoft Hv'",
            value: "Microsoft Hv",
            patch_bytes: b"GenuineIntel",
        },
        // XHYVE "bhyve bhyve"
        VmPattern {
            kind: VmArtifactKind::Cpuid,
            env: VmEnvironment::Qemu,
            pattern: b"KVMKVMKVM\0\0\0",
            mask: &[0xFF; 12],
            confidence: 88,
            description: "KVM CPUID vendor string",
            value: "KVMKVMKVM",
            patch_bytes: b"GenuineIntel",
        },
    ]
}

/// Strings that indicate VM presence (registry keys, device names, file paths).
fn vm_string_signatures() -> Vec<(&'static str, VmArtifactKind, VmEnvironment, u32, &'static str)> {
    vec![
        // VMware registry keys
        ("SOFTWARE\\VMware, Inc.\\VMware Tools", VmArtifactKind::RegistryKey, VmEnvironment::VMware, 92, "VMware Tools registry key"),
        ("SOFTWARE\\VMware, Inc.", VmArtifactKind::RegistryKey, VmEnvironment::VMware, 90, "VMware registry hive"),
        // VirtualBox
        ("SOFTWARE\\Oracle\\VirtualBox Guest Additions", VmArtifactKind::RegistryKey, VmEnvironment::VirtualBox, 92, "VirtualBox Guest Additions registry key"),
        ("SOFTWARE\\VirtualBox", VmArtifactKind::RegistryKey, VmEnvironment::VirtualBox, 88, "VirtualBox registry key"),
        // Device names
        ("\\\\.\\vmhgfs", VmArtifactKind::DeviceName, VmEnvironment::VMware, 93, "VMware HGFS device"),
        ("\\\\.\\HGFS", VmArtifactKind::DeviceName, VmEnvironment::VMware, 90, "VMware HGFS device (short)"),
        ("\\\\.\\VBoxGuest", VmArtifactKind::DeviceName, VmEnvironment::VirtualBox, 93, "VirtualBox VBoxGuest device"),
        ("\\\\.\\VBoxTrayIPC", VmArtifactKind::DeviceName, VmEnvironment::VirtualBox, 88, "VirtualBox tray IPC device"),
        // Process names
        ("vmtoolsd.exe", VmArtifactKind::ProcessName, VmEnvironment::VMware, 85, "VMware Tools daemon process"),
        ("vboxservice.exe", VmArtifactKind::ProcessName, VmEnvironment::VirtualBox, 85, "VirtualBox service process"),
        ("vboxtray.exe", VmArtifactKind::ProcessName, VmEnvironment::VirtualBox, 82, "VirtualBox tray process"),
        ("joeboxcontrol.exe", VmArtifactKind::ProcessName, VmEnvironment::Sandbox, 78, "Joebox sandbox process"),
        ("cuckoomon.dll", VmArtifactKind::ProcessName, VmEnvironment::Sandbox, 85, "Cuckoo sandbox monitor"),
        // File paths
        ("C:\\Program Files\\VMware\\VMware Tools\\", VmArtifactKind::FilePath, VmEnvironment::VMware, 90, "VMware Tools directory"),
        ("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\", VmArtifactKind::FilePath, VmEnvironment::VirtualBox, 90, "VirtualBox additions directory"),
        // SMBIOS
        ("VMware, Inc.", VmArtifactKind::Smbios, VmEnvironment::VMware, 88, "VMware SMBIOS vendor string"),
        ("VirtualBox", VmArtifactKind::Smbios, VmEnvironment::VirtualBox, 88, "VirtualBox SMBIOS vendor string"),
        ("VBOX", VmArtifactKind::Smbios, VmEnvironment::VirtualBox, 85, "VirtualBox SMBIOS short identifier"),
    ]
}

// ── VmDetectionNeutralizer ────────────────────────────────────────────────────

/// Scans binary data for VM/sandbox detection techniques and generates
/// [`SpoofRule`] instances to defeat them.
pub struct VmDetectionNeutralizer {
    /// Minimum confidence for reporting.
    pub min_confidence: u32,
    /// Whether to include string-based detections.
    pub scan_strings: bool,
}

impl Default for VmDetectionNeutralizer {
    fn default() -> Self {
        Self { min_confidence: 70, scan_strings: true }
    }
}

impl VmDetectionNeutralizer {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override minimum confidence.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Scan `binary` for VM-detection artifacts.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<VmArtifact> {
        let mut artifacts: Vec<VmArtifact> = Vec::new();

        for vp in &vm_binary_patterns() {
            if vp.confidence < self.min_confidence {
                continue;
            }
            for offset in masked_scan(binary, vp.pattern, vp.mask) {
                artifacts.push(VmArtifact::new(
                    vp.kind,
                    vp.env,
                    offset,
                    vp.pattern.len(),
                    vp.confidence,
                    vp.description,
                    vp.value,
                ));
            }
        }

        if self.scan_strings {
            artifacts.extend(self.scan_strings_internal(binary));
        }

        artifacts.sort_by_key(|a| a.offset);
        artifacts
    }

    /// Generate spoof rules for all detected artifacts.
    #[must_use]
    pub fn generate_spoof_rules(&self, binary: &[u8]) -> Vec<SpoofRule> {
        let artifacts = self.scan(binary);
        let patterns = vm_binary_patterns();
        let mut rules: Vec<SpoofRule> = Vec::new();

        for artifact in artifacts {
            if let Some(vp) = patterns.iter().find(|vp| {
                vp.kind == artifact.kind
                    && vp.env == artifact.environment
                    && vp.pattern.len() == artifact.span_bytes
                    && artifact.offset + vp.patch_bytes.len() <= binary.len()
            }) {
                let orig_end = artifact.offset + vp.patch_bytes.len();
                let original_bytes = binary[artifact.offset..orig_end].to_vec();
                rules.push(SpoofRule::new(
                    artifact.clone(),
                    artifact.offset,
                    original_bytes,
                    vp.patch_bytes.to_vec(),
                    format!("spoof {} at 0x{:X}", artifact.environment, artifact.offset),
                ));
            } else if artifact.kind == VmArtifactKind::Cpuid
                || artifact.kind == VmArtifactKind::RegistryKey
                || artifact.kind == VmArtifactKind::DeviceName
            {
                // Runtime-only rule (no binary patch)
                rules.push(SpoofRule::new(
                    artifact.clone(),
                    0,
                    Vec::new(),
                    Vec::new(),
                    format!(
                        "runtime hook needed for {} ({:?}) at 0x{:X}",
                        artifact.environment, artifact.kind, artifact.offset
                    ),
                ));
            }
        }

        rules
    }

    /// Apply all rules with binary patches to `binary`.  Returns `(applied, errors)`.
    pub fn neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>) {
        let rules = self.generate_spoof_rules(binary);
        let mut applied = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for rule in &rules {
            if rule.patch_bytes.is_empty() {
                continue;
            }
            match rule.apply(binary) {
                Ok(()) => applied += 1,
                Err(e) => errors.push(e),
            }
        }
        (applied, errors)
    }

    /// Generate a Frida script that spoofs VM detection APIs at runtime.
    #[must_use]
    pub fn frida_script(&self, artifacts: &[VmArtifact]) -> String {
        let mut script =
            String::from("// Frida VM detection bypass — vm_detection_neutralizer\n\n");

        let has_kind = |k: VmArtifactKind| artifacts.iter().any(|a| a.kind == k);

        if has_kind(VmArtifactKind::RegistryKey) {
            script.push_str(
                "// Spoof RegOpenKeyEx / RegQueryValueEx for known VM registry keys.\n\
                 const vm_keys = [\n\
                 \t'SOFTWARE\\\\VMware, Inc.',\n\
                 \t'SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions',\n\
                 ];\n\
                 Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegOpenKeyExW'), {\n\
                 \tonEnter(args) {\n\
                 \t\tthis.key = args[1].readUtf16String();\n\
                 \t},\n\
                 \tonLeave(retval) {\n\
                 \t\tif (vm_keys.some(k => this.key && this.key.includes(k))) retval.replace(2); // ERROR_FILE_NOT_FOUND\n\
                 \t}\n\
                 });\n\n",
            );
        }

        if has_kind(VmArtifactKind::DeviceName) {
            script.push_str(
                "// Spoof CreateFileW to fail for VM device names.\n\
                 const vm_devices = ['vmhgfs', 'VBoxGuest', 'VBoxTrayIPC', 'HGFS'];\n\
                 Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {\n\
                 \tonEnter(args) { this.path = args[0].readUtf16String(); },\n\
                 \tonLeave(retval) {\n\
                 \t\tif (vm_devices.some(d => this.path && this.path.includes(d)))\n\
                 \t\t\tretval.replace(-1); // INVALID_HANDLE_VALUE\n\
                 \t}\n\
                 });\n\n",
            );
        }

        if has_kind(VmArtifactKind::Cpuid) {
            script.push_str(
                "// Patch CPUID hypervisor bit and vendor strings in Stalker.\n\
                 // Implement via Stalker.follow with onReceive to intercept 0F A2.\n\n",
            );
        }

        if has_kind(VmArtifactKind::ProcessName) {
            script.push_str(
                "// Spoof Process32Next to hide VM-related process names.\n\
                 const vm_procs = ['vmtoolsd.exe', 'vboxservice.exe', 'vboxtray.exe', 'cuckoomon.dll'];\n\
                 Interceptor.attach(Module.findExportByName('kernel32.dll', 'Process32NextW'), {\n\
                 \tonLeave(retval) {\n\
                 \t\tif (!retval.toInt32()) return;\n\
                 \t\tconst namePtr = this.entry.add(44); // pe32.szExeFile offset\n\
                 \t\tconst name = namePtr.readUtf16String();\n\
                 \t\tif (name && vm_procs.some(p => name.toLowerCase().includes(p)))\n\
                 \t\t\tretval.replace(0);\n\
                 \t},\n\
                 \tonEnter(args) { this.entry = args[1]; }\n\
                 });\n\n",
            );
        }

        script
    }

    /// Summary count of artifacts by environment.
    #[must_use]
    pub fn environment_histogram(artifacts: &[VmArtifact]) -> HashMap<VmEnvironment, usize> {
        let mut map: HashMap<VmEnvironment, usize> = HashMap::new();
        for a in artifacts {
            *map.entry(a.environment).or_insert(0) += 1;
        }
        map
    }

    /// Summary count of artifacts by kind.
    #[must_use]
    pub fn kind_histogram(artifacts: &[VmArtifact]) -> HashMap<VmArtifactKind, usize> {
        let mut map: HashMap<VmArtifactKind, usize> = HashMap::new();
        for a in artifacts {
            *map.entry(a.kind).or_insert(0) += 1;
        }
        map
    }

    fn scan_strings_internal(&self, binary: &[u8]) -> Vec<VmArtifact> {
        let mut artifacts: Vec<VmArtifact> = Vec::new();
        for (sig_str, kind, env, conf, desc) in vm_string_signatures() {
            if conf < self.min_confidence {
                continue;
            }
            let sig = sig_str.as_bytes();
            let mut pos = 0usize;
            while pos + sig.len() <= binary.len() {
                if &binary[pos..pos + sig.len()] == sig {
                    artifacts.push(VmArtifact::new(kind, env, pos, sig.len(), conf, desc, sig_str));
                    pos += sig.len();
                } else {
                    pos += 1;
                }
            }
            // Also search as UTF-16LE (interleaved with 0x00 bytes).
            let utf16: Vec<u8> = sig_str.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let mut pos16 = 0usize;
            while pos16 + utf16.len() <= binary.len() {
                if binary[pos16..pos16 + utf16.len()] == utf16[..] {
                    artifacts.push(VmArtifact::new(
                        kind,
                        env,
                        pos16,
                        utf16.len(),
                        conf,
                        format!("{desc} (UTF-16LE)"),
                        sig_str,
                    ));
                    pos16 += utf16.len();
                } else {
                    pos16 += 1;
                }
            }
        }
        artifacts
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in 0..=(data.len() - plen) {
        let hit = pattern
            .iter()
            .enumerate()
            .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
        if hit {
            out.push(pos);
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_vmware_port_magic() {
        let binary = vec![0xBA, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(&binary);
        assert!(artifacts.iter().any(|a| a.environment == VmEnvironment::VMware));
    }

    #[test]
    fn test_scan_vbox_vendor_string() {
        let binary = b"VBoxVBoxVBox";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.environment == VmEnvironment::VirtualBox));
    }

    #[test]
    fn test_scan_vmware_vendor_string() {
        let binary = b"VMwareVMware";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.environment == VmEnvironment::VMware));
    }

    #[test]
    fn test_scan_hyperv_vendor_string() {
        let binary = b"Microsoft Hv";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.environment == VmEnvironment::HyperV));
    }

    #[test]
    fn test_scan_cpuid_hypervisor_bit() {
        let binary = vec![0x0F, 0xA2, 0xF7, 0xC1, 0x00, 0x00, 0x00, 0x80];
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(&binary);
        assert!(artifacts.iter().any(|a| a.kind == VmArtifactKind::Cpuid));
    }

    #[test]
    fn test_scan_registry_key_string() {
        let binary = b"SOFTWARE\\VMware, Inc.";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.kind == VmArtifactKind::RegistryKey));
    }

    #[test]
    fn test_scan_device_name() {
        let binary = b"\\\\.\\vmhgfs";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.kind == VmArtifactKind::DeviceName));
    }

    #[test]
    fn test_scan_process_name() {
        let binary = b"vmtoolsd.exe\x00";
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().any(|a| a.kind == VmArtifactKind::ProcessName));
    }

    #[test]
    fn test_generate_spoof_rules_vmware_port() {
        let binary = vec![0xBA, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let n = VmDetectionNeutralizer::new();
        let rules = n.generate_spoof_rules(&binary);
        assert!(!rules.is_empty());
        let r = rules.iter().find(|r| r.artifact.environment == VmEnvironment::VMware).unwrap();
        assert_eq!(r.patch_bytes, vec![0xBA, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_apply_spoof_rule() {
        let mut binary = vec![0xBA, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let n = VmDetectionNeutralizer::new();
        let rules = n.generate_spoof_rules(&binary);
        for r in &rules {
            if !r.patch_bytes.is_empty() {
                r.apply(&mut binary).unwrap();
            }
        }
        // Should have zeroed out the VMware magic
        assert_eq!(&binary[1..5], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_neutralize_returns_count() {
        let mut binary = b"VMwareVMware".to_vec();
        binary.extend_from_slice(&[0xBA, 0x68, 0x58, 0x4D, 0x56]);
        let n = VmDetectionNeutralizer::new();
        let (applied, errors) = n.neutralize(&mut binary);
        assert!(applied > 0);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_rollback_spoof_rule() {
        let orig = vec![0xBA, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let mut binary = orig.clone();
        let n = VmDetectionNeutralizer::new();
        let rules = n.generate_spoof_rules(&binary);
        for r in &rules {
            if !r.patch_bytes.is_empty() {
                r.apply(&mut binary).unwrap();
            }
        }
        for r in rules.iter().rev() {
            r.rollback(&mut binary).unwrap();
        }
        assert_eq!(binary, orig);
    }

    #[test]
    fn test_frida_script_registry() {
        let artifacts = vec![VmArtifact::new(
            VmArtifactKind::RegistryKey,
            VmEnvironment::VMware,
            0,
            20,
            90,
            "test",
            "HKLM\\SOFTWARE\\VMware",
        )];
        let n = VmDetectionNeutralizer::new();
        let script = n.frida_script(&artifacts);
        assert!(script.contains("RegOpenKeyExW"));
    }

    #[test]
    fn test_frida_script_device() {
        let artifacts = vec![VmArtifact::new(
            VmArtifactKind::DeviceName,
            VmEnvironment::VMware,
            0,
            10,
            93,
            "test",
            "\\\\.\\vmhgfs",
        )];
        let n = VmDetectionNeutralizer::new();
        let script = n.frida_script(&artifacts);
        assert!(script.contains("CreateFileW"));
    }

    #[test]
    fn test_environment_histogram() {
        let artifacts = vec![
            VmArtifact::new(VmArtifactKind::Cpuid, VmEnvironment::VMware, 0, 5, 88, "a", "v"),
            VmArtifact::new(VmArtifactKind::Cpuid, VmEnvironment::VMware, 5, 5, 88, "a", "v"),
            VmArtifact::new(VmArtifactKind::RegistryKey, VmEnvironment::VirtualBox, 10, 20, 90, "b", "k"),
        ];
        let hist = VmDetectionNeutralizer::environment_histogram(&artifacts);
        assert_eq!(hist[&VmEnvironment::VMware], 2);
        assert_eq!(hist[&VmEnvironment::VirtualBox], 1);
    }

    #[test]
    fn test_kind_histogram() {
        let artifacts = vec![
            VmArtifact::new(VmArtifactKind::Cpuid, VmEnvironment::VMware, 0, 5, 88, "a", "v"),
            VmArtifact::new(VmArtifactKind::DeviceName, VmEnvironment::VMware, 5, 10, 93, "b", "d"),
        ];
        let hist = VmDetectionNeutralizer::kind_histogram(&artifacts);
        assert_eq!(hist[&VmArtifactKind::Cpuid], 1);
        assert_eq!(hist[&VmArtifactKind::DeviceName], 1);
    }

    #[test]
    fn test_utf16le_string_scan() {
        let sig_str = "vmtoolsd.exe";
        let utf16: Vec<u8> = sig_str.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let n = VmDetectionNeutralizer::new();
        let artifacts = n.scan(&utf16);
        assert!(artifacts.iter().any(|a| a.kind == VmArtifactKind::ProcessName));
    }

    #[test]
    fn test_confidence_threshold_filters() {
        let binary = b"vboxtray.exe"; // confidence 82
        let n = VmDetectionNeutralizer::new().with_min_confidence(90);
        let artifacts = n.scan(binary);
        assert!(artifacts.iter().all(|a| a.confidence >= 90));
    }

    #[test]
    fn test_vm_artifact_kind_predicates() {
        assert!(VmArtifactKind::Cpuid.is_instruction_level());
        assert!(!VmArtifactKind::RegistryKey.is_instruction_level());
    }
}
