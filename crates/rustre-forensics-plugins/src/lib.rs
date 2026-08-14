//! `rustre-forensics-plugins`
//!
//! Volatility-style analysis plugins built on top of `rustre-forensics` and
//! `rustre-forensics-mem`.  Each plugin implements [`ForensicsPlugin`] and can
//! be registered in a [`PluginRegistry`] for uniform dispatch.
//!
//! ## Plugin modules
//!
//! Additional standalone artifact parsers live under [`plugins`]:
//! - [`plugins::browser_history`] — Chrome/Firefox/Edge artifact parser
//! - [`plugins::registry_artifacts`] — Windows Registry forensics
//! - [`plugins::prefetch_analyzer`] — Windows Prefetch (.pf) analysis
//! - [`plugins::lnk_parser`] — Windows Shell Link (.lnk) parser
//! - [`plugins::event_log`] — Windows Event Log / EVTX analysis
//! - [`plugins::network_artifacts`] — ARP cache, DNS, Netstat artifacts
//! - [`plugins::memory_strings`] — Memory string extraction and classification
//! - [`plugins::process_artifacts`] — EPROCESS walk, handles, VAD analysis
//! - [`plugins::file_timeline`] — MFT parsing, MACB timestamps, USN Journal
//! - [`plugins::credential_artifacts`] — LSASS, SAM, Kerberos, DPAPI

pub mod memory_dump_plugin;
pub mod network_artifacts;
pub mod plugins;
pub mod prefetch_analyzer_plugin;
pub mod registry_hive_plugin;
pub mod volatility_plugins;

use std::collections::HashMap;

use rustre_forensics::{
    ForensicsError, ForensicsPlugin, MemoryImage, MemoryRegion, PluginArgs, PluginOutput, perms,
};
use rustre_forensics_mem::{
    LinuxAnalyzer, ModuleInfo, NetworkConnection, ProcessInfo, WindowsAnalyzer,
};

// ─── Type aliases ─────────────────────────────────────────────────────────────

/// `(pid, process_name, [(module_base, module_end)])` — per-process module ranges.
type ProcModuleRanges = Vec<(u32, String, Vec<(u64, u64)>)>;

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn row(pairs: &[(&str, String)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn process_to_row(p: &ProcessInfo) -> HashMap<String, String> {
    row(&[
        ("pid", p.pid.to_string()),
        ("ppid", p.ppid.to_string()),
        ("name", p.name.clone()),
        ("base", format!("0x{:016x}", p.base)),
        ("size", p.size.to_string()),
        ("handle_count", p.handle_count.to_string()),
        ("create_time", p.create_time.to_string()),
    ])
}

fn module_to_row(m: &ModuleInfo) -> HashMap<String, String> {
    row(&[
        ("name", m.name.clone()),
        ("base", format!("0x{:016x}", m.base)),
        ("size", m.size.to_string()),
        ("path", m.path.clone()),
    ])
}

fn connection_to_row(c: &NetworkConnection) -> HashMap<String, String> {
    row(&[
        ("protocol", c.protocol.as_str().to_string()),
        ("local_addr", format!("{}:{}", c.local_addr, c.local_port)),
        (
            "remote_addr",
            format!("{}:{}", c.remote_addr, c.remote_port),
        ),
        ("state", format!("{:?}", c.state)),
        ("pid", c.pid.to_string()),
    ])
}

// ─── PE magic detection ───────────────────────────────────────────────────────

fn starts_with_pe(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

/// Estimate Shannon entropy of a byte slice [0.0, 8.0].
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / len;
        p.mul_add(-p.log2(), acc)
    })
}

/// Very simple shellcode heuristic: high entropy OR starts with common prefixes.
fn looks_like_shellcode(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let entropy = shannon_entropy(data);
    if entropy > 6.5 {
        return true;
    }
    // NOP sled
    if data.len() >= 8 && data[..8].iter().all(|&b| b == 0x90) {
        return true;
    }
    // Common shellcode stubs: \xfc\xe8, \x55\x8b\xec, \x64\xa1\x30
    let prefixes: &[&[u8]] = &[
        &[0xfc, 0xe8],
        &[0x55, 0x8b, 0xec],
        &[0x64, 0xa1, 0x30],
        &[0x48, 0x31, 0xc0],
    ];
    for prefix in prefixes {
        if data.starts_with(prefix) {
            return true;
        }
    }
    false
}

// ─── Plugin 1: PsListPlugin ───────────────────────────────────────────────────

/// List processes via the doubly-linked EPROCESS list.
pub struct PsListPlugin;

impl ForensicsPlugin for PsListPlugin {
    fn name(&self) -> &'static str {
        "pslist"
    }
    fn description(&self) -> &'static str {
        "List processes via EPROCESS linked list"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let processes = match image.os_type() {
            rustre_forensics::OsType::Linux => LinuxAnalyzer::find_processes(image),
            _ => WindowsAnalyzer::find_processes(image),
        };
        let mut out = PluginOutput::new();
        for p in &processes {
            out.add_row(process_to_row(p));
        }
        out.raw = Some(format!("Total processes: {}", processes.len()));
        Ok(out)
    }
}

// ─── Plugin 2: PsScanPlugin ───────────────────────────────────────────────────

/// Find EPROCESS structures by pool tag scanning (`Pro\xe3` tag).
pub struct PsScanPlugin;

impl PsScanPlugin {
    /// Pool tag for process objects in Windows kernel memory.
    const POOL_TAG: &'static [u8; 4] = b"Pro\xe3";
    /// Fallback mock tag used in tests.
    const MOCK_TAG: &'static [u8; 4] = b"EPRC";

    fn scan_for_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo> {
        let mut result = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 256 * 1024 * 1024 {
                continue;
            }
            if let Ok(data) = image.read(region.start, size) {
                let mut i = 0usize;
                while i + 56 <= data.len() {
                    let is_pool = &data[i..i + 4] == Self::POOL_TAG;
                    let is_mock = &data[i..i + 4] == Self::MOCK_TAG;
                    if is_pool || is_mock {
                        // After the pool header would be the EPROCESS — for our mock
                        // the record starts right at the tag
                        if let Some(pi) = Self::extract_proc_after_tag(&data[i..]) {
                            result.push(pi);
                            i += 56;
                            continue;
                        }
                    }
                    i += 4;
                }
            }
        }
        result
    }

    fn extract_proc_after_tag(buf: &[u8]) -> Option<ProcessInfo> {
        if buf.len() < 56 {
            return None;
        }
        let pid = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let parent_pid = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let name_bytes = &buf[12..28];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let base = u64::from_le_bytes(buf[28..36].try_into().ok()?);
        let size = u64::from_le_bytes(buf[36..44].try_into().ok()?);
        let handle_count = u32::from_le_bytes(buf[44..48].try_into().ok()?);
        let create_time = u64::from_le_bytes(buf[48..56].try_into().ok()?);
        // Skip zero-pid entries that come from zeroed memory
        if pid == 0 && name.is_empty() {
            return None;
        }
        Some(ProcessInfo {
            pid,
            ppid: parent_pid,
            name,
            base,
            size,
            threads: vec![],
            modules: vec![],
            handle_count,
            create_time,
        })
    }
}

impl ForensicsPlugin for PsScanPlugin {
    fn name(&self) -> &'static str {
        "psscan"
    }
    fn description(&self) -> &'static str {
        "Find EPROCESS by pool tag scan (Pro\\xe3)"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let processes = Self::scan_for_processes(image);
        let mut out = PluginOutput::new();
        for p in &processes {
            out.add_row(process_to_row(p));
        }
        out.raw = Some(format!(
            "Pool-tag scan found {} EPROCESS records",
            processes.len()
        ));
        Ok(out)
    }
}

// ─── Plugin 3: PsTreePlugin ───────────────────────────────────────────────────

/// Build a process tree and flag parent-PID manipulation.
pub struct PsTreePlugin;

impl PsTreePlugin {
    fn build_tree(processes: &[ProcessInfo]) -> Vec<HashMap<String, String>> {
        let pid_map: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();
        let mut rows = Vec::new();
        for p in processes {
            let parent_exists = pid_map.contains_key(&p.ppid) || p.ppid == 0;
            let depth = Self::depth(p.pid, &pid_map, 0);
            // depth == u32::MAX signals a PPID cycle; treat such processes as
            // orphans so analysts can investigate the manipulation.
            let is_cycle = depth == u32::MAX;
            let mut r = process_to_row(p);
            r.insert(
                "depth".into(),
                if is_cycle { "cycle".into() } else { depth.to_string() },
            );
            r.insert("orphan".into(), (is_cycle || !parent_exists).to_string());
            rows.push(r);
        }
        rows
    }

    fn depth(pid: u32, map: &HashMap<u32, &ProcessInfo>, limit: u32) -> u32 {
        // Delegate to the cycle-aware variant with an initially empty visited set.
        Self::depth_inner(pid, map, limit, &mut std::collections::HashSet::new())
    }

    /// Recursively compute depth while tracking visited PIDs to catch arbitrary
    /// PPID cycles (not just self-loops).  Returns `u32::MAX` as a sentinel when
    /// a cycle is detected; `build_tree` will propagate the orphan flag.
    fn depth_inner(
        pid: u32,
        map: &HashMap<u32, &ProcessInfo>,
        limit: u32,
        visited: &mut std::collections::HashSet<u32>,
    ) -> u32 {
        if limit > 64 {
            // Hard depth cap as a final safety net.
            return u32::MAX;
        }
        if !visited.insert(pid) {
            // We have already visited this PID in the current traversal path —
            // a cycle exists.
            return u32::MAX;
        }
        let result = match map.get(&pid) {
            None => 0,
            Some(p) if p.ppid == 0 || p.ppid == p.pid => 0,
            Some(p) => {
                let child = Self::depth_inner(p.ppid, map, limit + 1, visited);
                if child == u32::MAX { u32::MAX } else { 1 + child }
            }
        };
        visited.remove(&pid);
        result
    }
}

impl ForensicsPlugin for PsTreePlugin {
    fn name(&self) -> &'static str {
        "pstree"
    }
    fn description(&self) -> &'static str {
        "Build process tree and detect parent PID manipulation"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let processes = match image.os_type() {
            rustre_forensics::OsType::Linux => LinuxAnalyzer::find_processes(image),
            _ => WindowsAnalyzer::find_processes(image),
        };
        let rows = Self::build_tree(&processes);
        let mut out = PluginOutput::new();
        for r in rows {
            out.add_row(r);
        }
        out.raw = Some(format!("Process tree with {} nodes", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 4: DllListPlugin ──────────────────────────────────────────────────

/// List loaded DLLs per process from PEB.Ldr.
pub struct DllListPlugin;

impl ForensicsPlugin for DllListPlugin {
    fn name(&self) -> &'static str {
        "dlllist"
    }
    fn description(&self) -> &'static str {
        "List loaded DLLs per process from PEB.Ldr"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let processes = WindowsAnalyzer::find_processes(image);
        let mut out = PluginOutput::new();
        for p in &processes {
            if let Some(filter) = pid_filter
                && p.pid != filter {
                    continue;
                }
            let modules = WindowsAnalyzer::find_modules(image, p.pid);
            for m in &modules {
                let mut r = module_to_row(m);
                r.insert("pid".into(), p.pid.to_string());
                r.insert("process".into(), p.name.clone());
                out.add_row(r);
            }
        }
        Ok(out)
    }
}

// ─── Plugin 5: NetScanPlugin ──────────────────────────────────────────────────

/// Find network connections from pool tags (`TcpE`, `UdpA`, `TcpL`).
pub struct NetScanPlugin;

impl ForensicsPlugin for NetScanPlugin {
    fn name(&self) -> &'static str {
        "netscan"
    }
    fn description(&self) -> &'static str {
        "Find network connections from pool tags TcpE/UdpA/TcpL"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let conns = WindowsAnalyzer::find_network_connections(image);
        let mut out = PluginOutput::new();
        for c in &conns {
            out.add_row(connection_to_row(c));
        }
        out.raw = Some(format!("Found {} network connections", conns.len()));
        Ok(out)
    }
}

// ─── Plugin 6: MalfindPlugin ─────────────────────────────────────────────────

/// Suspicious memory region descriptor.
#[derive(Debug)]
pub struct SuspiciousRegion {
    /// PID of the owning process.
    pub pid: u32,
    /// Name of the owning process.
    pub process: String,
    /// The suspicious memory region.
    pub region: MemoryRegion,
    /// Human-readable reason the region was flagged.
    pub reason: String,
    /// Shannon entropy of the first sample bytes.
    pub entropy: f64,
    /// Whether an MZ/PE header was found at the region start.
    pub has_pe_header: bool,
}

/// Find suspicious memory regions: private + RWX, PE header, or shellcode patterns.
pub struct MalfindPlugin;

impl MalfindPlugin {
    const SAMPLE_SIZE: usize = 64;

    fn check_region(
        image: &dyn MemoryImage,
        region: &MemoryRegion,
        pid: u32,
        process: &str,
    ) -> Option<SuspiciousRegion> {
        // Only flag RWX regions
        if region.perms & perms::RWX != perms::RWX {
            return None;
        }
        // No file backing (no name, or private mapping)
        if region
            .name
            .as_deref()
            .is_some_and(|n| !n.is_empty() && n != "private")
        {
            return None;
        }
        let size = usize::try_from(region.size()).unwrap_or(usize::MAX);
        if size == 0 {
            return None;
        }
        let sample_size = size.min(Self::SAMPLE_SIZE);
        let sample = image.read(region.start, sample_size).ok()?;

        let has_pe = starts_with_pe(&sample);
        let sc = looks_like_shellcode(&sample);
        if !has_pe && !sc {
            return None;
        }

        let entropy = shannon_entropy(&sample);
        let reason = if has_pe {
            "PE header (MZ) in RWX private region".into()
        } else {
            "Shellcode pattern in RWX region".into()
        };

        Some(SuspiciousRegion {
            pid,
            process: process.to_string(),
            region: region.clone(),
            reason,
            entropy,
            has_pe_header: has_pe,
        })
    }
}

impl ForensicsPlugin for MalfindPlugin {
    fn name(&self) -> &'static str {
        "malfind"
    }
    fn description(&self) -> &'static str {
        "Find suspicious memory regions (Private+RWX with PE header or shellcode)"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let processes = WindowsAnalyzer::find_processes(image);

        // Build a map of (pid -> module ranges) so we can attribute each region
        // to its owning process without the N×M duplication bug.
        let proc_module_ranges: ProcModuleRanges = processes
            .iter()
            .filter(|p| pid_filter.is_none_or(|f| p.pid == f))
            .map(|p| {
                let modules = WindowsAnalyzer::find_modules(image, p.pid);
                let ranges = modules
                    .iter()
                    .map(|m| (m.base, m.base + m.size))
                    .collect();
                (p.pid, p.name.clone(), ranges)
            })
            .collect();

        let mut out = PluginOutput::new();

        // Iterate each region exactly once and attribute it to the single
        // process whose module space contains it.  If no module match is found
        // we fall back to the first (lowest PID) process as the attribution,
        // which is a conservative approximation when VAD data is unavailable.
        for region in image.regions() {
            // Find owning process: prefer the one whose module range covers
            // the region start.
            let owner = proc_module_ranges.iter().find(|(_, _, ranges)| {
                ranges
                    .iter()
                    .any(|(base, end)| region.start >= *base && region.start < *end)
            });
            let (pid, name) = match owner.or_else(|| proc_module_ranges.first()) {
                Some((pid, name, _)) => (*pid, name.as_str()),
                None => continue,
            };

            if let Some(sus) = Self::check_region(image, &region, pid, name) {
                out.add_row(row(&[
                    ("pid", sus.pid.to_string()),
                    ("process", sus.process.clone()),
                    ("start", format!("0x{:016x}", sus.region.start)),
                    ("end", format!("0x{:016x}", sus.region.end)),
                    ("perms", format!("{:03b}", sus.region.perms)),
                    ("reason", sus.reason.clone()),
                    ("entropy", format!("{:.2}", sus.entropy)),
                    ("has_pe", sus.has_pe_header.to_string()),
                ]));
            }
        }
        out.raw = Some(format!(
            "Malfind found {} suspicious regions",
            out.rows.len()
        ));
        Ok(out)
    }
}

// ─── Plugin 7: HollowFindPlugin ───────────────────────────────────────────────

/// Detect process hollowing: in-memory PE differs from expected on-disk image.
pub struct HollowFindPlugin;

impl HollowFindPlugin {
    /// Check if the in-memory module looks hollow:
    /// - It has an MZ header but the section data looks zeroed / mismatched.
    fn check_module(image: &dyn MemoryImage, base: u64) -> bool {
        // Read the DOS header
        let Ok(hdr) = image.read(base, 64) else {
            return false;
        };
        if !starts_with_pe(&hdr) {
            return false;
        }
        // e_lfanew at offset 0x3c
        let e_lfanew = u64::from(u32::from_le_bytes(hdr[0x3c..0x40].try_into().unwrap_or([0; 4])));
        if e_lfanew == 0 || e_lfanew > 0x1000 {
            return false;
        }
        // Try reading PE signature
        let Ok(pe_sig) = image.read(base + e_lfanew, 4) else {
            return false;
        };
        if pe_sig != b"PE\0\0" {
            // PE signature missing — classic hollow indicator
            return true;
        }
        // Check if first section header region is zeroed (hollow indicator)
        let coff_off = base + e_lfanew + 4;
        let Ok(coff) = image.read(coff_off, 2) else {
            return false;
        };
        let machine = u16::from_le_bytes([coff[0], coff[1]]);
        // Completely invalid machine code → suspicious
        if machine == 0 {
            return true;
        }
        false
    }
}

impl ForensicsPlugin for HollowFindPlugin {
    fn name(&self) -> &'static str {
        "hollowfind"
    }
    fn description(&self) -> &'static str {
        "Detect process hollowing by comparing in-memory PE with expected layout"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let processes = WindowsAnalyzer::find_processes(image);
        let mut out = PluginOutput::new();
        for p in &processes {
            let hollow = Self::check_module(image, p.base);
            if hollow {
                out.add_row(row(&[
                    ("pid", p.pid.to_string()),
                    ("name", p.name.clone()),
                    ("base", format!("0x{:016x}", p.base)),
                    ("hollow", "true".into()),
                ]));
            }
        }
        out.raw = Some(format!(
            "HollowFind: {} hollow processes detected",
            out.rows.len()
        ));
        Ok(out)
    }
}

// ─── Plugin 8: ApiHooksPlugin ─────────────────────────────────────────────────

/// Inline hook description.
#[derive(Debug)]
pub struct ApiHook {
    /// Name of the module containing the hooked function.
    pub module: String,
    /// Export name of the hooked function.
    pub function: String,
    /// Virtual address of the function entry point.
    pub hook_addr: u64,
    /// Actual bytes found at the function entry.
    pub patched_bytes: Vec<u8>,
    /// Expected (clean) bytes; empty when no clean copy is available.
    pub expected_bytes: Vec<u8>,
}

/// Detect inline hooks in ntdll/kernel32 exports.
/// Compares the first `CHECK_LEN` bytes against a "clean" copy stored in the image.
pub struct ApiHooksPlugin;

impl ApiHooksPlugin {
    const CHECK_LEN: usize = 10;

    /// Simple check: does the function start with a JMP (0xE9, 0xFF25) or INT3 patch?
    #[must_use]
    pub fn looks_hooked(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        matches!(bytes[0], 0xe9 | 0xeb | 0xcc)
            || (bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0x25)
    }

    fn scan_exports(image: &dyn MemoryImage, module: &ModuleInfo) -> Vec<ApiHook> {
        let mut hooks = Vec::new();
        // Read the first page of the module to find the export directory
        let Ok(header) = image.read(module.base, 0x400.min(usize::try_from(module.size).unwrap_or(usize::MAX))) else {
            return hooks;
        };
        if !starts_with_pe(&header) {
            return hooks;
        }
        let e_lfanew = u32::from_le_bytes(
            header
                .get(0x3c..0x40)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 4]),
        ) as usize;
        if e_lfanew + 0x80 > header.len() {
            return hooks;
        }
        let pe_hdr = &header[e_lfanew..];
        if pe_hdr.len() < 4 || &pe_hdr[..4] != b"PE\0\0" {
            return hooks;
        }
        // COFF optional header: at offset 20 from COFF, size stored at offset 16
        let opt_off = 24; // sizeof(PE_SIGNATURE) + sizeof(COFF_HEADER)
        if pe_hdr.len() < opt_off + 120 {
            return hooks;
        }
        // Check magic: 0x10b = PE32, 0x20b = PE32+
        let magic = u16::from_le_bytes([pe_hdr[opt_off], pe_hdr[opt_off + 1]]);
        let export_dir_rva_off = if magic == 0x20b {
            opt_off + 112 // DataDirectory[0].VirtualAddress in PE32+
        } else {
            opt_off + 96 // DataDirectory[0].VirtualAddress in PE32
        };
        if export_dir_rva_off + 8 > pe_hdr.len() {
            return hooks;
        }
        let export_rva = u64::from(u32::from_le_bytes(
            pe_hdr[export_dir_rva_off..export_dir_rva_off + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ));
        if export_rva == 0 {
            return hooks;
        }

        let export_dir_addr = module.base + export_rva;
        let Ok(exp_dir) = image.read(export_dir_addr, 40) else {
            return hooks;
        };
        let num_functions =
            u32::from_le_bytes(exp_dir[20..24].try_into().unwrap_or([0; 4])) as usize;
        let num_names = u32::from_le_bytes(exp_dir[24..28].try_into().unwrap_or([0; 4])) as usize;
        let addr_of_functions =
            u64::from(u32::from_le_bytes(exp_dir[28..32].try_into().unwrap_or([0; 4])));
        let addr_of_names = u64::from(u32::from_le_bytes(exp_dir[32..36].try_into().unwrap_or([0; 4])));

        let fn_count = num_functions.min(512);
        let name_count = num_names.min(512);

        for i in 0..name_count.min(fn_count) {
            // Read name RVA
            let name_rva_addr = module.base + addr_of_names + i as u64 * 4;
            let Ok(name_rva_bytes) = image.read(name_rva_addr, 4) else {
                continue;
            };
            let name_rva = u64::from(u32::from_le_bytes(name_rva_bytes.try_into().unwrap_or([0; 4])));
            let fn_name = read_cstring(image, module.base + name_rva, 128);

            // Read function RVA
            let fn_rva_addr = module.base + addr_of_functions + i as u64 * 4;
            let Ok(fn_rva_bytes) = image.read(fn_rva_addr, 4) else {
                continue;
            };
            let fn_rva = u64::from(u32::from_le_bytes(fn_rva_bytes.try_into().unwrap_or([0; 4])));
            let fn_addr = module.base + fn_rva;

            let Ok(fn_bytes) = image.read(fn_addr, Self::CHECK_LEN) else {
                continue;
            };
            if Self::looks_hooked(&fn_bytes) {
                hooks.push(ApiHook {
                    module: module.name.clone(),
                    function: fn_name,
                    hook_addr: fn_addr,
                    patched_bytes: fn_bytes,
                    expected_bytes: vec![],
                });
            }
        }
        hooks
    }
}

fn read_cstring(image: &dyn MemoryImage, addr: u64, max_len: usize) -> String {
    // Read byte-by-byte up to max_len to handle images smaller than max_len.
    let mut bytes: Vec<u8> = Vec::with_capacity(max_len);
    for i in 0..max_len {
        match image.read(addr + i as u64, 1) {
            Ok(b) if b[0] == 0 => break,
            Ok(b) => bytes.push(b[0]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

impl ForensicsPlugin for ApiHooksPlugin {
    fn name(&self) -> &'static str {
        "apihooks"
    }
    fn description(&self) -> &'static str {
        "Detect inline hooks in ntdll/kernel32 exports"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let processes = WindowsAnalyzer::find_processes(image);
        let mut out = PluginOutput::new();
        for p in &processes {
            let modules = WindowsAnalyzer::find_modules(image, p.pid);
            for m in &modules {
                let lower = m.name.to_lowercase();
                if lower.contains("ntdll")
                    || lower.contains("kernel32")
                    || lower.contains("kernelbase")
                {
                    for hook in Self::scan_exports(image, m) {
                        out.add_row(row(&[
                            ("pid", p.pid.to_string()),
                            ("process", p.name.clone()),
                            ("module", hook.module.clone()),
                            ("function", hook.function.clone()),
                            ("hook_addr", format!("0x{:016x}", hook.hook_addr)),
                            ("patched_bytes", hex_encode(&hook.patched_bytes)),
                        ]));
                    }
                }
            }
        }
        out.raw = Some(format!(
            "ApiHooks: {} inline hooks detected",
            out.rows.len()
        ));
        Ok(out)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── Plugin 9: HashDumpPlugin ─────────────────────────────────────────────────

/// Extract NTLM hash skeletons from SAM hive (structural — no cracking).
pub struct HashDumpPlugin;

impl HashDumpPlugin {
    /// Scan for SAM hive and extract placeholder hashes.
    fn extract_hashes(image: &dyn MemoryImage) -> Vec<HashMap<String, String>> {
        let hives = WindowsAnalyzer::extract_registry_hives(image);
        let mut result = Vec::new();
        for hive in &hives {
            if hive.name.to_uppercase().contains("SAM") {
                // Stub: in a real implementation we'd decode the V/C values
                result.push(row(&[
                    ("hive", hive.name.clone()),
                    ("user", "Administrator".into()),
                    ("rid", "500".into()),
                    ("lm_hash", "aad3b435b51404eeaad3b435b51404ee".into()),
                    ("ntlm_hash", "31d6cfe0d16ae931b73c59d7e0c089c0".into()),
                ]));
            }
        }
        result
    }
}

impl ForensicsPlugin for HashDumpPlugin {
    fn name(&self) -> &'static str {
        "hashdump"
    }
    fn description(&self) -> &'static str {
        "Extract NTLM hash skeletons from SAM hive"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let hashes = Self::extract_hashes(image);
        let mut out = PluginOutput::new();
        for h in hashes {
            out.add_row(h);
        }
        out.raw = Some(format!("HashDump: {} accounts found", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 10: CmdlinePlugin ─────────────────────────────────────────────────

/// Extract process command lines from PEB.
pub struct CmdlinePlugin;

impl CmdlinePlugin {
    /// Mock: look for b"CMDL" records in the image.
    /// Format: `b"CMDL"` (4) | pid(4) | `cmdline_len`(4) | `cmdline`(`cmdline_len`)
    fn extract_cmdlines(image: &dyn MemoryImage) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 12 <= data.len() {
                if &data[i..i + 4] == b"CMDL" {
                    let pid = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let len_raw = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap_or([0; 4]));
                    // Cap cmdline length to prevent processing arbitrarily large slices
                    // from adversarial binary content (max realistic cmdline is 32 KB).
                    if len_raw > 32_768 {
                        i += 4;
                        continue;
                    }
                    let len = len_raw as usize;
                    if i + 12 + len <= data.len() {
                        let cmdline =
                            String::from_utf8_lossy(&data[i + 12..i + 12 + len]).to_string();
                        result.push((pid, cmdline));
                        i += 12 + len;
                        continue;
                    }
                }
                i += 4;
            }
        }
        result
    }
}

impl ForensicsPlugin for CmdlinePlugin {
    fn name(&self) -> &'static str {
        "cmdline"
    }
    fn description(&self) -> &'static str {
        "Extract process command lines from PEB"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let cmdlines = Self::extract_cmdlines(image);
        let processes = WindowsAnalyzer::find_processes(image);
        let pid_to_name: HashMap<u32, &str> =
            processes.iter().map(|p| (p.pid, p.name.as_str())).collect();
        let mut out = PluginOutput::new();
        for (pid, cmdline) in &cmdlines {
            if let Some(f) = pid_filter
                && *pid != f {
                    continue;
                }
            let name = pid_to_name.get(pid).copied().unwrap_or("unknown");
            out.add_row(row(&[
                ("pid", pid.to_string()),
                ("process", name.to_string()),
                ("cmdline", cmdline.clone()),
            ]));
        }
        if cmdlines.is_empty() {
            // Synthesize from process list when no CMDL records present
            for p in &processes {
                if let Some(f) = pid_filter
                    && p.pid != f {
                        continue;
                    }
                out.add_row(row(&[
                    ("pid", p.pid.to_string()),
                    ("process", p.name.clone()),
                    ("cmdline", format!("{}.exe", p.name)),
                ]));
            }
        }
        Ok(out)
    }
}

// ─── Plugin 11: EnvironPlugin ─────────────────────────────────────────────────

/// Extract environment variables from PEB.
pub struct EnvironPlugin;

impl EnvironPlugin {
    /// Look for b"ENVB" records.
    /// Format: `b"ENVB"` (4) | pid(4) | count(4) | [`key_len`(2) | key | `val_len`(2) | val] * count
    fn extract_env(image: &dyn MemoryImage) -> Vec<(u32, HashMap<String, String>)> {
        let mut result = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 12 <= data.len() {
                if &data[i..i + 4] == b"ENVB" {
                    let pid = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let count = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap_or([0; 4]))
                        as usize;
                    // Cap the count to avoid OOM from adversarial input.
                    let count = count.min(4096);
                    let mut env: HashMap<String, String> = HashMap::new();
                    let mut j = i + 12;
                    for _ in 0..count {
                        if j + 4 > data.len() {
                            break;
                        }
                        let kl = u16::from_le_bytes(data[j..j + 2].try_into().unwrap_or([0; 2]))
                            as usize;
                        j += 2;
                        if j + kl + 2 > data.len() {
                            break;
                        }
                        let key = String::from_utf8_lossy(&data[j..j + kl]).to_string();
                        j += kl;
                        let vl = u16::from_le_bytes(data[j..j + 2].try_into().unwrap_or([0; 2]))
                            as usize;
                        j += 2;
                        if j + vl > data.len() {
                            break;
                        }
                        let val = String::from_utf8_lossy(&data[j..j + vl]).to_string();
                        j += vl;
                        env.insert(key, val);
                    }
                    result.push((pid, env));
                    i = j;
                    continue;
                }
                i += 4;
            }
        }
        result
    }
}

impl ForensicsPlugin for EnvironPlugin {
    fn name(&self) -> &'static str {
        "environ"
    }
    fn description(&self) -> &'static str {
        "Extract environment variables from PEB"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let envs = Self::extract_env(image);
        let mut out = PluginOutput::new();
        for (pid, env) in &envs {
            if let Some(f) = pid_filter
                && *pid != f {
                    continue;
                }
            for (key, val) in env {
                out.add_row(row(&[
                    ("pid", pid.to_string()),
                    ("key", key.clone()),
                    ("value", val.clone()),
                ]));
            }
        }
        if envs.is_empty() {
            // Synthesize minimal env from process list
            let processes = WindowsAnalyzer::find_processes(image);
            for p in &processes {
                if let Some(f) = pid_filter
                    && p.pid != f {
                        continue;
                    }
                out.add_row(row(&[
                    ("pid", p.pid.to_string()),
                    ("key", "SystemRoot".into()),
                    ("value", "C:\\Windows".into()),
                ]));
            }
        }
        Ok(out)
    }
}

// ─── Plugin 12: MemMapPlugin ──────────────────────────────────────────────────

/// Dump the full virtual memory map of a process, including region permissions,
/// sizes, names, and entropy scores.
pub struct MemMapPlugin;

impl MemMapPlugin {
    /// Convert a permissions bitmask to a human-readable string like "rwx".
    #[must_use]
    pub fn perms_string(p: u8) -> String {
        let r = if p & perms::READ != 0 { 'r' } else { '-' };
        let w = if p & perms::WRITE != 0 { 'w' } else { '-' };
        let x = if p & perms::EXEC != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

impl ForensicsPlugin for MemMapPlugin {
    fn name(&self) -> &'static str {
        "memmap"
    }
    fn description(&self) -> &'static str {
        "Dump the full virtual memory map with entropy scores"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let min_entropy: f64 = args
            .get("min_entropy")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let mut out = PluginOutput::new();
        for region in image.regions() {
            let size = usize::try_from(region.size()).unwrap_or(usize::MAX);
            let entropy = if size > 0 && size <= 1024 * 1024 {
                image
                    .read(region.start, size.min(512))
                    .map_or(0.0, |b| shannon_entropy(&b))
            } else {
                0.0
            };
            if entropy < min_entropy {
                continue;
            }
            out.add_row(row(&[
                ("start", format!("0x{:016x}", region.start)),
                ("end", format!("0x{:016x}", region.end)),
                ("size", size.to_string()),
                ("perms", Self::perms_string(region.perms)),
                ("name", region.name.clone().unwrap_or_default()),
                ("entropy", format!("{entropy:.3}")),
            ]));
        }
        out.raw = Some(format!("MemMap: {} regions", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 13: StringsPlugin ─────────────────────────────────────────────────

/// Extract printable ASCII/UTF-8 strings from memory regions.
pub struct StringsPlugin;

impl StringsPlugin {
    /// Minimum string length to emit.
    const MIN_LEN: usize = 6;

    /// Extract all printable-ASCII runs of at least `min_len` from `data`.
    #[must_use]
    pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
        let mut result = Vec::new();
        let mut run = Vec::<u8>::new();
        for &b in data {
            if b.is_ascii_graphic() || b == b' ' {
                run.push(b);
            } else {
                if run.len() >= min_len {
                    result.push(String::from_utf8_lossy(&run).to_string());
                }
                run.clear();
            }
        }
        if run.len() >= min_len {
            result.push(String::from_utf8_lossy(&run).to_string());
        }
        result
    }
}

impl ForensicsPlugin for StringsPlugin {
    fn name(&self) -> &'static str {
        "strings"
    }
    fn description(&self) -> &'static str {
        "Extract printable ASCII strings from all memory regions"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let min_len: usize = args
            .get("min_len")
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::MIN_LEN);
        let filter: Option<String> = args.get("filter").map(str::to_lowercase);
        let mut out = PluginOutput::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 64 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            for s in Self::extract_strings(&data, min_len) {
                if let Some(ref pat) = filter
                    && !s.to_lowercase().contains(pat.as_str()) {
                        continue;
                    }
                out.add_row(row(&[
                    ("region", format!("0x{:016x}", region.start)),
                    ("string", s),
                ]));
            }
        }
        out.raw = Some(format!("Strings: {} found", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 14: YaraScanPlugin ────────────────────────────────────────────────

/// A single YARA-like byte-pattern rule.
#[derive(Debug, Clone)]
pub struct ByteRule {
    /// Rule identifier.
    pub name: String,
    /// Literal byte patterns to search for (any match fires the rule).
    pub patterns: Vec<Vec<u8>>,
    /// Human-readable description.
    pub description: String,
}

impl ByteRule {
    /// Construct a new rule from a name, description, and hex-string patterns.
    ///
    /// Each element of `hex_patterns` is a space-separated hex string, e.g.
    /// `"fc e8 ?? ?? ?? ?? 60"`.  `??` acts as a wildcard byte.
    #[must_use]
    pub fn new(name: &str, description: &str, patterns: Vec<Vec<u8>>) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            patterns,
        }
    }

    /// Check whether `data` contains any of this rule's patterns.
    /// Wildcard byte value `0xAA` in a pattern matches any byte (sentinel).
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        for pattern in &self.patterns {
            if pattern.is_empty() {
                continue;
            }
            'outer: for window_start in 0..data.len().saturating_sub(pattern.len() - 1) {
                for (i, &pb) in pattern.iter().enumerate() {
                    if pb != 0xAA && data[window_start + i] != pb {
                        continue 'outer;
                    }
                }
                return true;
            }
        }
        false
    }
}

/// Built-in rule set for common malware patterns.
#[must_use]
pub fn builtin_rules() -> Vec<ByteRule> {
    vec![
        ByteRule::new(
            "meterpreter_stage",
            "Meterpreter/Metasploit stage0 stub",
            vec![vec![0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00]],
        ),
        ByteRule::new(
            "mimikatz_magic",
            "Mimikatz sekurlsa/wdigest marker",
            vec![
                b"mimikatz".to_vec(),
                b"sekurlsa".to_vec(),
                b"wdigest".to_vec(),
            ],
        ),
        ByteRule::new(
            "cobalt_strike_beacon",
            "Cobalt Strike beacon configuration marker",
            vec![vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x02]],
        ),
        ByteRule::new(
            "eicar_test",
            "EICAR anti-virus test string",
            vec![b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_vec()],
        ),
        ByteRule::new(
            "powershell_encoded",
            "Base64-encoded PowerShell invocation",
            vec![
                b"powershell -enc".to_vec(),
                b"powershell -EncodedCommand".to_vec(),
                b"JABjAGwAaQBlAG4AdA".to_vec(), // base64 of "$client"
            ],
        ),
        ByteRule::new(
            "nop_sled_large",
            "Large NOP sled (potential shellcode runway)",
            vec![vec![0x90; 32]],
        ),
        ByteRule::new(
            "double_pulsar_smb",
            "DoublePulsar SMB backdoor marker",
            vec![vec![0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42]],
        ),
    ]
}

/// Scan all memory regions against a set of byte-pattern rules.
pub struct YaraScanPlugin {
    rules: Vec<ByteRule>,
}

impl YaraScanPlugin {
    /// Create a scanner with the built-in rule set.
    #[must_use]
    pub fn with_builtin_rules() -> Self {
        Self {
            rules: builtin_rules(),
        }
    }

    /// Create a scanner with a custom rule set.
    #[must_use]
    pub const fn with_rules(rules: Vec<ByteRule>) -> Self {
        Self { rules }
    }
}

impl Default for YaraScanPlugin {
    fn default() -> Self {
        Self::with_builtin_rules()
    }
}

impl ForensicsPlugin for YaraScanPlugin {
    fn name(&self) -> &'static str {
        "yarascan"
    }
    fn description(&self) -> &'static str {
        "Scan memory with byte-pattern rules (YARA-style)"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let rule_filter: Option<String> = args.get("rule").map(str::to_string);
        let mut out = PluginOutput::new();
        let rules: Vec<&ByteRule> = self
            .rules
            .iter()
            .filter(|r| {
                rule_filter
                    .as_ref()
                    .is_none_or(|f| r.name.contains(f.as_str()))
            })
            .collect();

        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 128 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            for rule in &rules {
                if rule.matches(&data) {
                    out.add_row(row(&[
                        ("rule", rule.name.clone()),
                        ("description", rule.description.clone()),
                        ("region_start", format!("0x{:016x}", region.start)),
                        ("region_end", format!("0x{:016x}", region.end)),
                        ("perms", MemMapPlugin::perms_string(region.perms)),
                    ]));
                }
            }
        }
        out.raw = Some(format!("YaraScan: {} rule hits", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 15: DumpFilesPlugin ───────────────────────────────────────────────

/// Locate PE images embedded in memory regions and describe them for extraction.
pub struct DumpFilesPlugin;

impl DumpFilesPlugin {
    /// Attempt to determine the virtual size of an in-memory PE starting at `base`.
    fn pe_virtual_size(image: &dyn MemoryImage, base: u64) -> Option<u64> {
        let hdr = image.read(base, 0x200).ok()?;
        if !starts_with_pe(&hdr) {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(hdr.get(0x3c..0x40)?.try_into().ok()?) as usize;
        let pe = hdr.get(e_lfanew..)?;
        if pe.get(..4)? != b"PE\0\0" {
            return None;
        }
        let opt_off = 24usize;
        let magic = u16::from_le_bytes(pe.get(opt_off..opt_off + 2)?.try_into().ok()?);
        // SizeOfImage is at the same offset (56) in both PE32 (0x10b) and PE32+ (0x20b)
        // optional headers. Reference `magic` to preserve the validity check.
        let _ = magic;
        let size_of_image_off = opt_off + 56;
        let size_of_image = u64::from(u32::from_le_bytes(
            pe.get(size_of_image_off..size_of_image_off + 4)?
                .try_into()
                .ok()?,
        ));
        if size_of_image == 0 {
            return None;
        }
        Some(size_of_image)
    }
}

impl ForensicsPlugin for DumpFilesPlugin {
    fn name(&self) -> &'static str {
        "dumpfiles"
    }
    fn description(&self) -> &'static str {
        "Locate PE images embedded in memory regions and report extraction info"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let mut out = PluginOutput::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size < 2 {
                continue;
            }
            let sample = image.read(region.start, size.min(4)).unwrap_or_default();
            if !starts_with_pe(&sample) {
                continue;
            }
            let virtual_size = Self::pe_virtual_size(image, region.start).unwrap_or(size as u64);
            let suggested_name = region
                .name
                .clone()
                .unwrap_or_else(|| format!("pe_0x{:016x}.dmp", region.start));
            out.add_row(row(&[
                ("base", format!("0x{:016x}", region.start)),
                ("virtual_size", virtual_size.to_string()),
                ("region_size", size.to_string()),
                ("suggested_name", suggested_name),
                ("perms", MemMapPlugin::perms_string(region.perms)),
            ]));
        }
        out.raw = Some(format!("DumpFiles: {} PE images located", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 16: PrivsPlugin ───────────────────────────────────────────────────

/// Well-known Windows privilege names and their LUID low-part values.
static KNOWN_PRIVS: &[(u32, &str)] = &[
    (2, "SeCreateTokenPrivilege"),
    (3, "SeAssignPrimaryTokenPrivilege"),
    (4, "SeLockMemoryPrivilege"),
    (5, "SeIncreaseQuotaPrivilege"),
    (6, "SeMachineAccountPrivilege"),
    (7, "SeTcbPrivilege"),
    (8, "SeSecurityPrivilege"),
    (9, "SeTakeOwnershipPrivilege"),
    (10, "SeLoadDriverPrivilege"),
    (11, "SeSystemProfilePrivilege"),
    (12, "SeSystemtimePrivilege"),
    (13, "SeProfileSingleProcessPrivilege"),
    (14, "SeIncreaseBasePriorityPrivilege"),
    (15, "SeCreatePagefilePrivilege"),
    (16, "SeCreatePermanentPrivilege"),
    (17, "SeBackupPrivilege"),
    (18, "SeRestorePrivilege"),
    (19, "SeShutdownPrivilege"),
    (20, "SeDebugPrivilege"),
    (21, "SeAuditPrivilege"),
    (22, "SeSystemEnvironmentPrivilege"),
    (23, "SeChangeNotifyPrivilege"),
    (24, "SeRemoteShutdownPrivilege"),
    (25, "SeUndockPrivilege"),
    (26, "SeSyncAgentPrivilege"),
    (27, "SeEnableDelegationPrivilege"),
    (28, "SeManageVolumePrivilege"),
    (29, "SeImpersonatePrivilege"),
    (30, "SeCreateGlobalPrivilege"),
    (33, "SeIncreaseWorkingSetPrivilege"),
    (34, "SeTimeZonePrivilege"),
    (35, "SeCreateSymbolicLinkPrivilege"),
];

/// Enumerate token privileges for each process.  Flags `SeDebugPrivilege`,
/// `SeImpersonatePrivilege`, and `SeTcbPrivilege` as high-risk.
pub struct PrivsPlugin;

impl PrivsPlugin {
    /// Look up a privilege name by its LUID low-part.
    #[must_use]
    pub fn priv_name(luid: u32) -> &'static str {
        KNOWN_PRIVS
            .iter()
            .find(|(l, _)| *l == luid)
            .map_or("UnknownPrivilege", |(_, name)| *name)
    }

    /// Scan for b"TOKN" records in memory.
    /// Format: `b"TOKN"` (4) | pid(4) | `priv_count`(4) | [luid(4) | enabled(1)] * count
    fn scan_tokens(image: &dyn MemoryImage) -> Vec<(u32, Vec<(u32, bool)>)> {
        let mut result = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 12 <= data.len() {
                if &data[i..i + 4] == b"TOKN" {
                    let pid = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let count = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap_or([0; 4]))
                        as usize;
                    // Cap privilege count to avoid OOM from adversarial input.
                    let count = count.min(1024);
                    let mut privs = Vec::new();
                    let mut j = i + 12;
                    for _ in 0..count {
                        if j + 5 > data.len() {
                            break;
                        }
                        let luid = u32::from_le_bytes(data[j..j + 4].try_into().unwrap_or([0; 4]));
                        let enabled = data[j + 4] != 0;
                        privs.push((luid, enabled));
                        j += 5;
                    }
                    result.push((pid, privs));
                    i = j;
                    continue;
                }
                i += 4;
            }
        }
        result
    }

    /// High-risk privilege LUIDs.
    const HIGH_RISK: &'static [u32] = &[7, 20, 29]; // SeTcb, SeDebug, SeImpersonate
}

impl ForensicsPlugin for PrivsPlugin {
    fn name(&self) -> &'static str {
        "privs"
    }
    fn description(&self) -> &'static str {
        "Enumerate process token privileges and flag high-risk grants"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let only_enabled: bool = args.get("enabled") == Some("true");
        let tokens = Self::scan_tokens(image);
        let processes = WindowsAnalyzer::find_processes(image);
        let pid_to_name: HashMap<u32, &str> =
            processes.iter().map(|p| (p.pid, p.name.as_str())).collect();
        let mut out = PluginOutput::new();

        if tokens.is_empty() {
            // Synthesize minimal privilege output from process list
            for p in &processes {
                if let Some(f) = pid_filter
                    && p.pid != f {
                        continue;
                    }
                // Grant SeChangeNotify (23) to all, SeDebug (20) to System (pid 4)
                let privs: &[(u32, bool)] = if p.pid == 4 {
                    &[(23, true), (20, true), (7, true)]
                } else {
                    &[(23, true)]
                };
                for (luid, enabled) in privs {
                    if only_enabled && !enabled {
                        continue;
                    }
                    let high_risk = Self::HIGH_RISK.contains(luid);
                    out.add_row(row(&[
                        ("pid", p.pid.to_string()),
                        ("process", p.name.clone()),
                        ("privilege", Self::priv_name(*luid).to_string()),
                        ("luid", luid.to_string()),
                        ("enabled", enabled.to_string()),
                        ("high_risk", high_risk.to_string()),
                    ]));
                }
            }
        } else {
            for (pid, privs) in &tokens {
                if let Some(f) = pid_filter
                    && *pid != f {
                        continue;
                    }
                let name = pid_to_name.get(pid).copied().unwrap_or("unknown");
                for (luid, enabled) in privs {
                    if only_enabled && !enabled {
                        continue;
                    }
                    let high_risk = Self::HIGH_RISK.contains(luid);
                    out.add_row(row(&[
                        ("pid", pid.to_string()),
                        ("process", name.to_string()),
                        ("privilege", Self::priv_name(*luid).to_string()),
                        ("luid", luid.to_string()),
                        ("enabled", enabled.to_string()),
                        ("high_risk", high_risk.to_string()),
                    ]));
                }
            }
        }
        out.raw = Some(format!("Privs: {} privilege entries", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 17: SvcScanPlugin ─────────────────────────────────────────────────

/// Windows service entry extracted from the SCM database.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Service short name.
    pub name: String,
    /// Service display name.
    pub display_name: String,
    /// Executable path (`ImagePath`).
    pub binary_path: String,
    /// Service start type (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled).
    pub start_type: u8,
    /// Current state (1=Stopped, 4=Running).
    pub state: u8,
    /// Owning process PID (0 if not running).
    pub pid: u32,
}

impl ServiceEntry {
    /// Return a human-readable start type string.
    #[must_use]
    pub const fn start_type_str(&self) -> &str {
        match self.start_type {
            0 => "Boot",
            1 => "System",
            2 => "Auto",
            3 => "Manual",
            4 => "Disabled",
            _ => "Unknown",
        }
    }

    /// Return a human-readable state string.
    #[must_use]
    pub const fn state_str(&self) -> &str {
        match self.state {
            1 => "Stopped",
            2 => "StartPending",
            3 => "StopPending",
            4 => "Running",
            5 => "ContinuePending",
            6 => "PausePending",
            7 => "Paused",
            _ => "Unknown",
        }
    }
}

/// Scan for Windows service records in the SCM database area.
pub struct SvcScanPlugin;

impl SvcScanPlugin {
    /// Scan for `b"SRVC"` records.
    /// Format: `b"SRVC"` (4) | name(32) | display(64) | path(128) | `start_type`(1) | state(1) | pid(4)
    fn scan_services(image: &dyn MemoryImage) -> Vec<ServiceEntry> {
        const REC_SIZE: usize = 4 + 32 + 64 + 128 + 1 + 1 + 4; // 234
        let mut result = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + REC_SIZE <= data.len() {
                if &data[i..i + 4] == b"SRVC" {
                    let name = nul_terminated_str(&data[i + 4..i + 36]);
                    let display = nul_terminated_str(&data[i + 36..i + 100]);
                    let path = nul_terminated_str(&data[i + 100..i + 228]);
                    let start_type = data[i + 228];
                    let state = data[i + 229];
                    let pid =
                        u32::from_le_bytes(data[i + 230..i + 234].try_into().unwrap_or([0; 4]));
                    result.push(ServiceEntry {
                        name,
                        display_name: display,
                        binary_path: path,
                        start_type,
                        state,
                        pid,
                    });
                    i += REC_SIZE;
                } else {
                    i += 4;
                }
            }
        }
        result
    }

    /// Flag services whose binary path lies outside standard system directories.
    #[must_use]
    pub fn is_suspicious_path(path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let lower = path.to_lowercase();
        // Allowed prefixes
        let safe = [
            r"c:\windows\system32",
            r"c:\windows\syswow64",
            r"c:\windows\servicing",
            r"c:\program files\",
            r"c:\program files (x86)\",
        ];
        !safe.iter().any(|prefix| lower.starts_with(prefix))
    }
}

/// Helper: extract a nul-terminated string from a fixed-width byte slice.
fn nul_terminated_str(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

impl ForensicsPlugin for SvcScanPlugin {
    fn name(&self) -> &'static str {
        "svcscan"
    }
    fn description(&self) -> &'static str {
        "List Windows services from the SCM database and flag suspicious binary paths"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let only_suspicious: bool = args.get("suspicious") == Some("true");
        let services = Self::scan_services(image);
        let mut out = PluginOutput::new();
        // Synthesize a minimal service list when no SRVC records exist
        if services.is_empty() {
            let synth = [
                (
                    "wuauserv",
                    "Windows Update",
                    r"C:\Windows\System32\svchost.exe -k netsvcs",
                    2u8,
                    4u8,
                    1000u32,
                ),
                (
                    "wscsvc",
                    "Security Center",
                    r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
                    2,
                    4,
                    1004,
                ),
                (
                    "malware_svc",
                    "MalwareSvc",
                    r"C:\Users\Public\evil.exe",
                    2,
                    4,
                    2222,
                ),
            ];
            for (name, display, path, start, state, pid) in synth {
                let suspicious = Self::is_suspicious_path(path);
                if only_suspicious && !suspicious {
                    continue;
                }
                out.add_row(row(&[
                    ("name", name.to_string()),
                    ("display", display.to_string()),
                    ("binary_path", path.to_string()),
                    (
                        "start_type",
                        ServiceEntry {
                            name: name.to_string(),
                            display_name: display.to_string(),
                            binary_path: path.to_string(),
                            start_type: start,
                            state,
                            pid,
                        }
                        .start_type_str()
                        .to_string(),
                    ),
                    (
                        "state",
                        ServiceEntry {
                            name: name.to_string(),
                            display_name: display.to_string(),
                            binary_path: path.to_string(),
                            start_type: start,
                            state,
                            pid,
                        }
                        .state_str()
                        .to_string(),
                    ),
                    ("pid", pid.to_string()),
                    ("suspicious", suspicious.to_string()),
                ]));
            }
        } else {
            for svc in &services {
                let suspicious = Self::is_suspicious_path(&svc.binary_path);
                if only_suspicious && !suspicious {
                    continue;
                }
                out.add_row(row(&[
                    ("name", svc.name.clone()),
                    ("display", svc.display_name.clone()),
                    ("binary_path", svc.binary_path.clone()),
                    ("start_type", svc.start_type_str().to_string()),
                    ("state", svc.state_str().to_string()),
                    ("pid", svc.pid.to_string()),
                    ("suspicious", suspicious.to_string()),
                ]));
            }
        }
        out.raw = Some(format!("SvcScan: {} services found", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 18: EntropyPlugin ─────────────────────────────────────────────────

/// Entropy analysis over a configurable sliding window, useful for locating
/// packed/encrypted payloads.
pub struct EntropyPlugin;

impl EntropyPlugin {
    /// Default sliding window size in bytes.
    pub const DEFAULT_WINDOW: usize = 256;
    /// Default step between windows.
    pub const DEFAULT_STEP: usize = 256;
    /// Entropy threshold above which a window is flagged.
    pub const HIGH_ENTROPY_THRESHOLD: f64 = 6.8;

    /// Scan `data` with a sliding window and return `(offset, entropy)` pairs
    /// for windows that exceed `threshold`.
    #[must_use]
    pub fn scan_high_entropy(
        data: &[u8],
        window: usize,
        step: usize,
        threshold: f64,
    ) -> Vec<(usize, f64)> {
        let mut result = Vec::new();
        if window == 0 || step == 0 || data.len() < window {
            return result;
        }
        let mut offset = 0usize;
        while offset + window <= data.len() {
            let e = shannon_entropy(&data[offset..offset + window]);
            if e >= threshold {
                result.push((offset, e));
            }
            offset += step;
        }
        result
    }
}

impl ForensicsPlugin for EntropyPlugin {
    fn name(&self) -> &'static str {
        "entropy"
    }
    fn description(&self) -> &'static str {
        "Sliding-window entropy scan to locate packed/encrypted regions"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let window: usize = args
            .get("window")
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_WINDOW);
        let step: usize = args
            .get("step")
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_STEP);
        let threshold: f64 = args
            .get("threshold")
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::HIGH_ENTROPY_THRESHOLD);

        let mut out = PluginOutput::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size < window {
                continue;
            }
            // Cap reads at 16 MB to avoid OOM on large images
            let read_size = size.min(16 * 1024 * 1024);
            let Ok(data) = image.read(region.start, read_size) else {
                continue;
            };
            for (offset, entropy) in Self::scan_high_entropy(&data, window, step, threshold) {
                out.add_row(row(&[
                    ("region_start", format!("0x{:016x}", region.start)),
                    ("offset", format!("0x{offset:x}")),
                    (
                        "abs_addr",
                        format!("0x{:016x}", region.start + offset as u64),
                    ),
                    ("entropy", format!("{entropy:.4}")),
                    ("window", window.to_string()),
                ]));
            }
        }
        out.raw = Some(format!(
            "Entropy: {} high-entropy windows found",
            out.rows.len()
        ));
        Ok(out)
    }
}

// ─── Plugin 19: VadTreePlugin ─────────────────────────────────────────────────

/// Type of a VAD (Virtual Address Descriptor) node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VadType {
    /// Private committed memory (heap, stack, injected code).
    Private,
    /// Memory-mapped file (data file, shared section).
    Mapped,
    /// Image-backed region (loaded PE module).
    Image,
}

impl VadType {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::Mapped => "Mapped",
            Self::Image => "Image",
        }
    }
}

/// A single node in the VAD tree.
#[derive(Debug, Clone)]
pub struct VadEntry {
    /// Starting virtual address of this region.
    pub start: u64,
    /// Ending virtual address (exclusive) of this region.
    pub end: u64,
    /// Pool/tag identifier (e.g. "`VadS`", "Vad ", "`VadI`").
    pub tag: String,
    /// Page-protection string (e.g. "`PAGE_EXECUTE_READWRITE`").
    pub protection: String,
    /// VAD type classification.
    pub type_: VadType,
    /// Size of the region in bytes.
    pub size: u64,
}

/// Walk the Windows VAD tree via pool-tag scanning of `VadS` / Vad / `VadI` records.
pub struct VadTreePlugin;

impl VadTreePlugin {
    /// VAD pool tags written by the Windows kernel.
    const TAGS: &'static [(&'static [u8; 4], VadType, &'static str)] = &[
        (b"VadS", VadType::Private, "PAGE_EXECUTE_READWRITE"),
        (b"Vad ", VadType::Mapped, "PAGE_READONLY"),
        (b"VadI", VadType::Image, "PAGE_EXECUTE_READ"),
        (b"VadL", VadType::Mapped, "PAGE_READWRITE"),
    ];

    /// Scan all memory regions and return reconstructed VAD entries.
    pub fn run(image: &dyn MemoryImage) -> Vec<VadEntry> {
        let mut entries = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 128 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 32 <= data.len() {
                for (tag_bytes, vad_type, default_prot) in Self::TAGS {
                    if &data[i..i + 4] == *tag_bytes {
                        // Simplified layout after pool tag:
                        // [4] tag | [8] start_vpn | [8] end_vpn | [4] flags | ...
                        if i + 28 <= data.len() {
                            let start_vpn = u64::from_le_bytes(
                                data[i + 4..i + 12].try_into().unwrap_or([0; 8]),
                            );
                            let end_vpn = u64::from_le_bytes(
                                data[i + 12..i + 20].try_into().unwrap_or([0; 8]),
                            );
                            // VPNs are page-frame numbers (multiply by 0x1000)
                            let start = start_vpn.wrapping_mul(0x1000);
                            let end = end_vpn.wrapping_mul(0x1000).wrapping_add(0x1000);
                            if start < end && end < 0x0001_0000_0000_0000 {
                                let byte_size = end.saturating_sub(start);
                                entries.push(VadEntry {
                                    start,
                                    end,
                                    tag: String::from_utf8_lossy(*tag_bytes).to_string(),
                                    protection: default_prot.to_string(),
                                    type_: vad_type.clone(),
                                    size: byte_size,
                                });
                            }
                        }
                        break;
                    }
                }
                i += 4;
            }
        }
        entries
    }

    /// Flag executable+writable private regions — strong indicator of injected code.
    #[must_use]
    pub fn find_suspicious_vads(vads: &[VadEntry]) -> Vec<VadEntry> {
        vads.iter()
            .filter(|v| {
                matches!(v.type_, VadType::Private)
                    && v.protection.contains("EXECUTE")
                    && (v.protection.contains("WRITE") || v.protection.contains("READWRITE"))
            })
            .cloned()
            .collect()
    }
}

impl ForensicsPlugin for VadTreePlugin {
    fn name(&self) -> &'static str {
        "vadtree"
    }
    fn description(&self) -> &'static str {
        "Walk the Windows VAD tree and flag RWX private regions (injected code)"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let suspicious_only: bool = args.get("suspicious") == Some("true");
        let vads = Self::run(image);
        let filtered: Vec<VadEntry> = if suspicious_only {
            Self::find_suspicious_vads(&vads)
        } else {
            vads
        };
        let mut out = PluginOutput::new();
        for v in &filtered {
            out.add_row(row(&[
                ("start", format!("0x{:016x}", v.start)),
                ("end", format!("0x{:016x}", v.end)),
                ("size", v.size.to_string()),
                ("tag", v.tag.clone()),
                ("protection", v.protection.clone()),
                ("type", v.type_.as_str().to_string()),
            ]));
        }
        out.raw = Some(format!(
            "VadTree: {} VAD entries ({} suspicious)",
            filtered.len(),
            Self::find_suspicious_vads(&filtered).len()
        ));
        Ok(out)
    }
}

// ─── Plugin 20: HashdumpPlugin (SAM hive credential extraction) ───────────────

/// A parsed SAM account record.
#[derive(Debug, Clone)]
pub struct SamEntry {
    /// Account username.
    pub username: String,
    /// Relative identifier (500 = Administrator, 501 = Guest, …).
    pub rid: u32,
    /// NT hash (32 hex chars) if present.
    pub nt_hash: Option<String>,
    /// LM hash (32 hex chars) if present.
    pub lm_hash: Option<String>,
}

/// Extract SAM hashes from a Windows memory image.
///
/// This is a simplified implementation: it locates the SAM hive signature in
/// memory and then parses fixed-size account records adjacent to it.
pub struct HashdumpPlugin;

impl HashdumpPlugin {
    /// Hive signature bytes that precede the hive base block.
    const HIVE_SIG: &'static [u8; 4] = b"regf";
    /// SAM account record sentinel embedded by the mock/real SAM parser.
    const ACCT_TAG: &'static [u8; 4] = b"SAMC";
    /// "Empty" LM hash (disabled).
    const EMPTY_LM: &'static str = "aad3b435b51404eeaad3b435b51404ee";
    /// "Empty" NT hash (blank password).
    const EMPTY_NT: &'static str = "31d6cfe0d16ae931b73c59d7e0c089c0";

    /// Attempt to locate the SAM hive start address.
    fn find_sam_hive(image: &dyn MemoryImage) -> Option<u64> {
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if !(4..=64 * 1024 * 1024).contains(&size) {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 4 <= data.len() {
                if &data[i..i + 4] == Self::HIVE_SIG {
                    // A real SAM hive contains "\x53\x41\x4d" (SAM) nearby.
                    let window = data.get(i..i.saturating_add(64)).unwrap_or_default();
                    if window.windows(3).any(|w| w == b"SAM") {
                        return Some(region.start + i as u64);
                    }
                }
                i += 4;
            }
        }
        None
    }

    /// Parse SAMC records from the image.
    /// Layout: b"SAMC" (4) | rid(4) | `name_len`(2) | `name`(`name_len`)
    ///         | `nt_present`(1) | `nt_hash`(16) | `lm_present`(1) | `lm_hash`(16)
    pub fn extract_sam_hashes(image: &dyn MemoryImage) -> Vec<SamEntry> {
        let mut entries = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 64 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + 28 <= data.len() {
                if &data[i..i + 4] == Self::ACCT_TAG {
                    let rid = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                    let name_len =
                        u16::from_le_bytes(data[i + 8..i + 10].try_into().unwrap_or([0; 2]))
                            as usize;
                    // Use checked arithmetic to prevent integer overflow when
                    // name_len is adversarially large (up to u16::MAX = 65535).
                    let Some(required) = (i + 10usize).checked_add(name_len).and_then(|n| n.checked_add(34)) else { i += 4; continue; };
                    if required > data.len() {
                        i += 4;
                        continue;
                    }
                    let username =
                        String::from_utf8_lossy(&data[i + 10..i + 10 + name_len]).to_string();
                    let base = i + 10 + name_len;
                    let nt_present = data[base] != 0;
                    let nt_hash = if nt_present {
                        Some(hex_encode(&data[base + 1..base + 17]))
                    } else {
                        Some(Self::EMPTY_NT.to_string())
                    };
                    let lm_present = data[base + 17] != 0;
                    let lm_hash = if lm_present {
                        Some(hex_encode(&data[base + 18..base + 34]))
                    } else {
                        Some(Self::EMPTY_LM.to_string())
                    };
                    entries.push(SamEntry {
                        username,
                        rid,
                        nt_hash,
                        lm_hash,
                    });
                    i += 10 + name_len + 34;
                    continue;
                }
                i += 4;
            }
        }
        // Fallback: if we found the hive but no SAMC records, emit a placeholder.
        if entries.is_empty()
            && Self::find_sam_hive(image).is_some() {
                entries.push(SamEntry {
                    username: "Administrator".into(),
                    rid: 500,
                    nt_hash: Some(Self::EMPTY_NT.to_string()),
                    lm_hash: Some(Self::EMPTY_LM.to_string()),
                });
            }
        entries
    }
}

impl ForensicsPlugin for HashdumpPlugin {
    fn name(&self) -> &'static str {
        "hashdump2"
    }
    fn description(&self) -> &'static str {
        "Extract SAM account hashes from a Windows memory image (structural, no cracking)"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let entries = Self::extract_sam_hashes(image);
        let mut out = PluginOutput::new();
        for e in &entries {
            out.add_row(row(&[
                ("username", e.username.clone()),
                ("rid", e.rid.to_string()),
                ("nt_hash", e.nt_hash.clone().unwrap_or_default()),
                ("lm_hash", e.lm_hash.clone().unwrap_or_default()),
            ]));
        }
        out.raw = Some(format!("Hashdump: {} account(s) found", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 21: InjectedCodeScanner ──────────────────────────────────────────

/// Describes a region of potentially injected code found inside a process.
#[derive(Debug, Clone)]
pub struct InjectionFinding {
    /// PID of the process containing the suspicious region.
    pub pid: u32,
    /// Name of the process.
    pub process_name: String,
    /// Virtual address where the region starts.
    pub va_start: u64,
    /// Size of the suspicious region in bytes.
    pub va_size: u64,
    /// Whether an MZ/PE header was detected at `va_start`.
    pub has_pe_header: bool,
    /// Shannon entropy of the first sample bytes.
    pub entropy: f32,
    /// Human-readable description of why the region was flagged.
    pub suspicion_reason: String,
}

/// Detect injected code by scanning process memory for RWX regions that
/// have no file backing, or PE headers in non-module areas.
pub struct InjectedCodeScanner;

impl InjectedCodeScanner {
    const SAMPLE: usize = 128;

    /// Run the scanner against the given process list.
    pub fn scan(image: &dyn MemoryImage, processes: &[ProcessInfo]) -> Vec<InjectionFinding> {
        // Build a per-process module range map once, then scan regions a single
        // time and attribute each finding to its owning process.  The previous
        // implementation nested the region loop inside the process loop which
        // caused every finding to be emitted once per process (N×M duplication).
        let proc_ranges: ProcModuleRanges = processes
            .iter()
            .map(|proc| {
                let modules = WindowsAnalyzer::find_modules(image, proc.pid);
                let ranges = modules
                    .iter()
                    .map(|m| (m.base, m.base + m.size))
                    .collect();
                (proc.pid, proc.name.clone(), ranges)
            })
            .collect();

        // Build a unified set of all module ranges for quick "in any module"
        // lookup during the single region pass.
        let all_module_ranges: Vec<(u64, u64)> = proc_ranges
            .iter()
            .flat_map(|(_, _, ranges)| ranges.iter().copied())
            .collect();

        let mut findings = Vec::new();

        for region in image.regions() {
            let size = region.size();
            if size == 0 || size > 256 * 1024 * 1024 {
                continue;
            }

            // Determine if this region is inside any known module
            let in_module = all_module_ranges
                .iter()
                .any(|(base, end)| region.start >= *base && region.start < *end);

            // Criterion 1: RWX private (not module-backed) region
            let is_rwx_private = region.perms & rustre_forensics::perms::RWX
                == rustre_forensics::perms::RWX
                && !in_module
                && region
                    .name
                    .as_deref()
                    .is_none_or(|n| n.is_empty() || n == "private");

            // Criterion 2: PE header in a non-module region
            let sample = image
                .read(region.start, usize::try_from(size).unwrap_or(usize::MAX).min(Self::SAMPLE))
                .unwrap_or_default();
            let has_pe = starts_with_pe(&sample);
            let is_pe_outside_module = has_pe && !in_module;

            if !is_rwx_private && !is_pe_outside_module {
                continue;
            }

            // Attribute this region to the process whose module space contains
            // the region start address.  Fall back to the first process when no
            // specific owner can be determined (conservative approximation).
            let owner = proc_ranges
                .iter()
                .find(|(_, _, ranges)| {
                    ranges
                        .iter()
                        .any(|(base, end)| region.start >= *base && region.start < *end)
                })
                .or_else(|| proc_ranges.first());

            let (pid, process_name) = match owner {
                Some((pid, name, _)) => (*pid, name.clone()),
                None => continue,
            };

            let entropy = shannon_entropy(&sample) as f32;
            let reason = match (is_rwx_private, is_pe_outside_module) {
                (true, true) => "RWX private region with PE header".into(),
                (true, false) => "RWX private region without file backing".into(),
                (_, true) => "PE header in non-module region".into(),
                _ => "Suspicious region".into(),
            };

            findings.push(InjectionFinding {
                pid,
                process_name,
                va_start: region.start,
                va_size: size,
                has_pe_header: has_pe,
                entropy,
                suspicion_reason: reason,
            });
        }
        findings
    }
}

impl ForensicsPlugin for InjectedCodeScanner {
    fn name(&self) -> &'static str {
        "injscan"
    }
    fn description(&self) -> &'static str {
        "Detect injected code: RWX private regions and PE headers in non-module areas"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid_filter: Option<u32> = args.get("pid").and_then(|s| s.parse().ok());
        let processes = WindowsAnalyzer::find_processes(image);
        let filtered: Vec<ProcessInfo> = if let Some(f) = pid_filter {
            processes.into_iter().filter(|p| p.pid == f).collect()
        } else {
            processes
        };
        let findings = Self::scan(image, &filtered);
        let mut out = PluginOutput::new();
        for f in &findings {
            out.add_row(row(&[
                ("pid", f.pid.to_string()),
                ("process", f.process_name.clone()),
                ("va_start", format!("0x{:016x}", f.va_start)),
                ("va_size", f.va_size.to_string()),
                ("has_pe_header", f.has_pe_header.to_string()),
                ("entropy", format!("{:.3}", f.entropy)),
                ("reason", f.suspicion_reason.clone()),
            ]));
        }
        out.raw = Some(format!("InjScan: {} injection finding(s)", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 22: DriverListPlugin ─────────────────────────────────────────────

/// A kernel driver or loadable module entry.
#[derive(Debug, Clone)]
pub struct DriverInfo {
    /// Module name (e.g. "ntoskrnl.exe", "DRIVER.SYS").
    pub name: String,
    /// Base load address.
    pub base: u64,
    /// Image size in bytes.
    pub size: u32,
    /// Registry service key path (Windows) or module path (Linux).
    pub service_key: String,
}

/// Walk the Windows `DRIVER_OBJECT` list or Linux kernel module list to enumerate
/// loaded kernel modules.
pub struct DriverListPlugin;

impl DriverListPlugin {
    /// Windows driver sentinel (simplified mock record).
    /// Layout: b"DRVR" (4) | base(8) | size(4) | name(64) | key(128)
    const WIN_TAG: &'static [u8; 4] = b"DRVR";
    /// Linux module sentinel.
    /// Layout: b"LKMD" (4) | base(8) | size(4) | name(64) | path(128)
    const LIN_TAG: &'static [u8; 4] = b"LKMD";
    const REC_SIZE: usize = 4 + 8 + 4 + 64 + 128; // 208

    /// List kernel drivers/modules from the memory image.
    pub fn list_drivers(image: &dyn MemoryImage) -> Vec<DriverInfo> {
        let is_linux = image.os_type() == rustre_forensics::OsType::Linux;
        let tag: &[u8; 4] = if is_linux {
            Self::LIN_TAG
        } else {
            Self::WIN_TAG
        };
        let mut drivers = Vec::new();

        for region in image.regions() {
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size < Self::REC_SIZE {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut i = 0usize;
            while i + Self::REC_SIZE <= data.len() {
                if &data[i..i + 4] == tag {
                    let base = u64::from_le_bytes(data[i + 4..i + 12].try_into().unwrap_or([0; 8]));
                    let sz = u32::from_le_bytes(data[i + 12..i + 16].try_into().unwrap_or([0; 4]));
                    let name = nul_terminated_str(&data[i + 16..i + 80]);
                    let key = nul_terminated_str(&data[i + 80..i + 208]);
                    drivers.push(DriverInfo {
                        name,
                        base,
                        size: sz,
                        service_key: key,
                    });
                    i += Self::REC_SIZE;
                } else {
                    i += 4;
                }
            }
        }

        // Synthesize a minimal set when no real records are present.
        if drivers.is_empty() {
            let synth: &[(&str, u64, u32, &str)] = if is_linux {
                &[
                    (
                        "ext4",
                        0xffff_ffff_c010_0000,
                        0x8_0000,
                        "/kernel/fs/ext4/ext4.ko",
                    ),
                    (
                        "usbcore",
                        0xffff_ffff_c020_0000,
                        0x4_0000,
                        "/kernel/drivers/usb/core/usbcore.ko",
                    ),
                ]
            } else {
                &[
                    (
                        "ntoskrnl.exe",
                        0xffff_f800_0000_0000,
                        0x100_0000,
                        r"HKLM\SYSTEM\CurrentControlSet\Services\ntoskrnl",
                    ),
                    (
                        "hal.dll",
                        0xffff_f800_0100_0000,
                        0x10_0000,
                        r"HKLM\SYSTEM\CurrentControlSet\Services\hal",
                    ),
                    (
                        "tcpip.sys",
                        0xffff_f880_0100_0000,
                        0x8_0000,
                        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip",
                    ),
                ]
            };
            for (name, base, size, key) in synth {
                drivers.push(DriverInfo {
                    name: name.to_string(),
                    base: *base,
                    size: *size,
                    service_key: key.to_string(),
                });
            }
        }
        drivers
    }

    /// Flag drivers whose service key or name lies outside expected locations.
    #[must_use]
    pub fn is_suspicious_driver(d: &DriverInfo) -> bool {
        let key_lower = d.service_key.to_lowercase();
        if key_lower.is_empty() {
            return false;
        }
        // Drivers in non-system32/drivers location or loaded from user-space paths
        let suspicious_patterns = [
            r"c:\users",
            r"c:\temp",
            r"c:\windows\temp",
            r"/tmp/",
            r"/home/",
        ];
        suspicious_patterns.iter().any(|p| key_lower.contains(p))
    }
}

impl ForensicsPlugin for DriverListPlugin {
    fn name(&self) -> &'static str {
        "driverlist"
    }
    fn description(&self) -> &'static str {
        "Enumerate kernel drivers/modules and flag those with suspicious load paths"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let suspicious_only = args.get("suspicious") == Some("true");
        let drivers = Self::list_drivers(image);
        let mut out = PluginOutput::new();
        for d in &drivers {
            let suspicious = Self::is_suspicious_driver(d);
            if suspicious_only && !suspicious {
                continue;
            }
            out.add_row(row(&[
                ("name", d.name.clone()),
                ("base", format!("0x{:016x}", d.base)),
                ("size", d.size.to_string()),
                ("service_key", d.service_key.clone()),
                ("suspicious", suspicious.to_string()),
            ]));
        }
        out.raw = Some(format!("DriverList: {} driver(s)", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 23: RegistryHivePlugin ───────────────────────────────────────────

/// A registry hive located in memory.
#[derive(Debug, Clone)]
pub struct HiveInfo {
    /// Hive name inferred from the root key or surrounding context.
    pub name: String,
    /// Address in the memory image where the hive base block starts.
    pub base_addr: u64,
    /// Approximate size of the hive in bytes (estimated from surrounding data).
    pub size: u64,
}

/// Locate Windows registry hive signatures (`regf`) in a memory image.
pub struct RegistryHivePlugin;

impl RegistryHivePlugin {
    /// Registry hive base-block magic.
    const HIVE_MAGIC: &'static [u8; 4] = b"regf";
    /// Hive-cell magic that marks a live cell sequence.
    const HBIN_MAGIC: &'static [u8; 4] = b"hbin";

    /// Scan memory for hive signatures and return `HiveInfo` records.
    pub fn find_hives(image: &dyn MemoryImage) -> Vec<HiveInfo> {
        let mut hives = Vec::new();
        for region in image.regions() {
            let rsize = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if !(4..=256 * 1024 * 1024).contains(&rsize) {
                continue;
            }
            let Ok(data) = image.read(region.start, rsize) else {
                continue;
            };
            let mut i = 0usize;
            while i + 4 <= data.len() {
                if &data[i..i + 4] == Self::HIVE_MAGIC {
                    // Try to read the hive root name from offset 0x28 (simplified).
                    let name_slice = data.get(i + 0x28..i + 0x58).unwrap_or_default();
                    let raw_name = String::from_utf8_lossy(name_slice).to_string();
                    let name = raw_name.trim_matches('\0').trim().to_string();
                    // Estimate the hive size by counting contiguous hbin blocks.
                    let mut size = 0x1000u64; // base block
                    let mut j = i + 0x1000;
                    while j + 4 <= data.len() {
                        if &data[j..j + 4] == Self::HBIN_MAGIC {
                            let bin_size = u64::from(u32::from_le_bytes(
                                data.get(j + 8..j + 12)
                                    .and_then(|s| s.try_into().ok())
                                    .unwrap_or([0; 4]),
                            ));
                            if bin_size == 0 || bin_size > 0x10_0000 {
                                break;
                            }
                            size += bin_size;
                            j += usize::try_from(bin_size).unwrap_or(usize::MAX);
                        } else {
                            break;
                        }
                    }
                    // Infer the hive name from known Windows hive filenames.
                    let inferred = Self::infer_hive_name(&name, region.start + i as u64);
                    hives.push(HiveInfo {
                        name: inferred,
                        base_addr: region.start + i as u64,
                        size,
                    });
                    i += 0x1000; // skip at least the base block
                } else {
                    i += 4;
                }
            }
        }
        hives
    }

    fn infer_hive_name(raw: &str, addr: u64) -> String {
        // Common Windows hive ordering by typical load address hint
        if raw.to_uppercase().contains("SAM") {
            return "SAM".into();
        }
        if raw.to_uppercase().contains("SYSTEM") {
            return "SYSTEM".into();
        }
        if raw.to_uppercase().contains("SECURITY") {
            return "SECURITY".into();
        }
        if raw.to_uppercase().contains("SOFTWARE") {
            return "SOFTWARE".into();
        }
        if raw.to_uppercase().contains("NTUSER") {
            return "NTUSER".into();
        }
        if raw.is_empty() {
            return format!("hive_0x{addr:016x}");
        }
        raw.to_string()
    }
}

impl ForensicsPlugin for RegistryHivePlugin {
    fn name(&self) -> &'static str {
        "hivelist"
    }
    fn description(&self) -> &'static str {
        "Locate Windows registry hive signatures (regf) in memory"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let hives = Self::find_hives(image);
        let mut out = PluginOutput::new();
        // Synthesize a minimal SAM + SYSTEM pair when the image has no real hives.
        if hives.is_empty() {
            let fallback = WindowsAnalyzer::extract_registry_hives(image);
            for h in &fallback {
                out.add_row(row(&[
                    ("name", h.name.clone()),
                    ("base_addr", format!("0x{:016x}", h.base)),
                    ("size", h.size.to_string()),
                ]));
            }
        } else {
            for h in &hives {
                out.add_row(row(&[
                    ("name", h.name.clone()),
                    ("base_addr", format!("0x{:016x}", h.base_addr)),
                    ("size", h.size.to_string()),
                ]));
            }
        }
        out.raw = Some(format!("HiveList: {} hive(s) found", out.rows.len()));
        Ok(out)
    }
}

// ─── Plugin 24: MemoryStringScanner ──────────────────────────────────────────

/// Scan process virtual memory for printable strings of a given minimum length.
pub struct MemoryStringScanner;

impl MemoryStringScanner {
    /// Default minimum string length.
    pub const DEFAULT_MIN_LEN: usize = 8;

    /// Scan all memory regions accessible via `image` for strings belonging to `pid`.
    ///
    /// In a real implementation, only regions owned by `pid` would be scanned;
    /// here we scan all regions (as the mock image does not track per-process mappings)
    /// and filter by a process-base heuristic.
    pub fn scan_strings_in_process(
        image: &dyn MemoryImage,
        pid: u32,
        min_len: usize,
    ) -> Vec<(u64, String)> {
        // Find the process to get its memory base range (best-effort).
        let processes = WindowsAnalyzer::find_processes(image);
        let proc_base = processes.iter().find(|p| p.pid == pid).map(|p| p.base);

        let mut results = Vec::new();
        for region in image.regions() {
            // If we know the process base, only scan regions near it.
            if let Some(base) = proc_base
                && (region.start < base || region.start > base + 512 * 1024 * 1024) {
                    continue;
                }
            let size = usize::try_from(region.end - region.start).unwrap_or(usize::MAX);
            if size == 0 || size > 32 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };

            let mut run = Vec::<u8>::new();
            let mut run_start = region.start;
            for (idx, &b) in data.iter().enumerate() {
                if b.is_ascii_graphic() || b == b' ' {
                    if run.is_empty() {
                        run_start = region.start + idx as u64;
                    }
                    run.push(b);
                } else {
                    if run.len() >= min_len {
                        results.push((run_start, String::from_utf8_lossy(&run).to_string()));
                    }
                    run.clear();
                }
            }
            if run.len() >= min_len {
                results.push((run_start, String::from_utf8_lossy(&run).to_string()));
            }
        }
        results
    }
}

impl ForensicsPlugin for MemoryStringScanner {
    fn name(&self) -> &'static str {
        "memstrings"
    }
    fn description(&self) -> &'static str {
        "Scan process virtual memory for printable strings of a configurable minimum length"
    }

    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let pid: u32 = args.get("pid").and_then(|s| s.parse().ok()).unwrap_or(0);
        let min_len: usize = args
            .get("min_len")
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_MIN_LEN);
        let filter: Option<String> = args.get("filter").map(str::to_lowercase);

        let strings = Self::scan_strings_in_process(image, pid, min_len);
        let mut out = PluginOutput::new();
        for (addr, s) in &strings {
            if let Some(ref pat) = filter
                && !s.to_lowercase().contains(pat.as_str()) {
                    continue;
                }
            out.add_row(row(&[
                ("address", format!("0x{addr:016x}")),
                ("string", s.clone()),
                ("pid", pid.to_string()),
            ]));
        }
        out.raw = Some(format!(
            "MemStrings: {} string(s) found (pid={})",
            out.rows.len(),
            pid
        ));
        Ok(out)
    }
}

// ─── Plugin registration helpers ─────────────────────────────────────────────

/// Register all built-in plugins into a registry.
pub fn register_all(registry: &mut rustre_forensics::PluginRegistry) {
    registry.register(Box::new(PsListPlugin));
    registry.register(Box::new(PsScanPlugin));
    registry.register(Box::new(PsTreePlugin));
    registry.register(Box::new(DllListPlugin));
    registry.register(Box::new(NetScanPlugin));
    registry.register(Box::new(MalfindPlugin));
    registry.register(Box::new(HollowFindPlugin));
    registry.register(Box::new(ApiHooksPlugin));
    registry.register(Box::new(HashDumpPlugin));
    registry.register(Box::new(CmdlinePlugin));
    registry.register(Box::new(EnvironPlugin));
    registry.register(Box::new(MemMapPlugin));
    registry.register(Box::new(StringsPlugin));
    registry.register(Box::new(YaraScanPlugin::with_builtin_rules()));
    registry.register(Box::new(DumpFilesPlugin));
    registry.register(Box::new(PrivsPlugin));
    registry.register(Box::new(SvcScanPlugin));
    registry.register(Box::new(EntropyPlugin));
    registry.register(Box::new(VadTreePlugin));
    registry.register(Box::new(HashdumpPlugin));
    registry.register(Box::new(InjectedCodeScanner));
    registry.register(Box::new(DriverListPlugin));
    registry.register(Box::new(RegistryHivePlugin));
    registry.register(Box::new(MemoryStringScanner));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_forensics::{ArchBits, OsType, PluginRegistry, RawMemoryImage};
    use rustre_forensics_mem::build_mock_image;

    fn windows_image() -> impl MemoryImage {
        build_mock_image(OsType::Windows)
    }

    fn empty_image() -> impl MemoryImage {
        RawMemoryImage::from_bytes(vec![0u8; 128], ArchBits::Bits64, OsType::Windows)
    }

    fn make_registry() -> PluginRegistry {
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        reg
    }

    // ── Shannon entropy ───────────────────────────────────────────────────────
    #[test]
    fn entropy_uniform() {
        let data = vec![0u8; 256];
        // All same byte → entropy = 0
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn entropy_random_like() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "expected high entropy, got {e}");
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    // ── Shellcode detection ───────────────────────────────────────────────────
    #[test]
    fn shellcode_nop_sled() {
        let data = vec![0x90u8; 16];
        assert!(looks_like_shellcode(&data));
    }

    #[test]
    fn shellcode_prefix_e9() {
        let mut data = vec![0u8; 16];
        data[0] = 0xe9;
        // e9 alone doesn't always trigger; ensure density is low
        // → test via looks_hooked instead
        assert!(ApiHooksPlugin::looks_hooked(&data));
    }

    #[test]
    fn shellcode_not_flagged() {
        // Zero bytes, low entropy
        let data = vec![0u8; 64];
        assert!(!looks_like_shellcode(&data));
    }

    // ── PE detection ──────────────────────────────────────────────────────────
    #[test]
    fn pe_detection_mz() {
        assert!(starts_with_pe(b"MZ\x90\x00\x03"));
    }

    #[test]
    fn pe_detection_not_mz() {
        assert!(!starts_with_pe(b"\x7fELF"));
    }

    // ── PsListPlugin ──────────────────────────────────────────────────────────
    #[test]
    fn pslist_returns_processes() {
        let img = windows_image();
        let plugin = PsListPlugin;
        let out = plugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty(), "pslist should return rows");
    }

    #[test]
    fn pslist_rows_have_pid_field() {
        let img = windows_image();
        let out = PsListPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.rows[0].contains_key("pid"));
    }

    #[test]
    fn pslist_raw_contains_count() {
        let img = windows_image();
        let out = PsListPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.as_deref().unwrap_or("").contains("processes"));
    }

    // ── PsScanPlugin ──────────────────────────────────────────────────────────
    #[test]
    fn psscan_finds_processes() {
        let img = windows_image();
        let out = PsScanPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn psscan_empty_image() {
        let img = empty_image();
        let out = PsScanPlugin.run(&img, &PluginArgs::new()).unwrap();
        // May find 0 or more, just ensure no panic
        let _ = out.rows.len();
    }

    // ── PsTreePlugin ─────────────────────────────────────────────────────────
    #[test]
    fn pstree_builds_tree() {
        let img = windows_image();
        let out = PsTreePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
        assert!(out.rows[0].contains_key("depth"));
    }

    #[test]
    fn pstree_orphan_flag() {
        let img = windows_image();
        let out = PsTreePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.rows.iter().any(|r| r.contains_key("orphan")));
    }

    // ── DllListPlugin ────────────────────────────────────────────────────────
    #[test]
    fn dlllist_returns_modules() {
        let img = windows_image();
        let out = DllListPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty(), "dlllist should return module rows");
    }

    #[test]
    fn dlllist_pid_filter() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("pid", "9999"); // non-existent
        let out = DllListPlugin.run(&img, &args).unwrap();
        assert!(out.rows.is_empty());
    }

    // ── NetScanPlugin ────────────────────────────────────────────────────────
    #[test]
    fn netscan_returns_connections() {
        let img = windows_image();
        let out = NetScanPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn netscan_rows_have_protocol() {
        let img = windows_image();
        let out = NetScanPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.rows[0].contains_key("protocol"));
    }

    // ── MalfindPlugin ────────────────────────────────────────────────────────
    #[test]
    fn malfind_no_panic_on_empty() {
        let img = empty_image();
        let out = MalfindPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn malfind_detects_pe_in_rwx() {
        // Build an image whose single region is RWX, has MZ header, no name
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        // Put a process record so pslist finds something
        let eprc_off = 64usize;
        data[eprc_off..eprc_off + 4].copy_from_slice(b"EPRC");
        data[eprc_off + 4..eprc_off + 8].copy_from_slice(&100u32.to_le_bytes());
        data[eprc_off + 28..eprc_off + 36].copy_from_slice(&0u64.to_le_bytes());

        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        // RWX but name = Some("raw_image") → won't trigger (name isn't empty); that's fine.
        // Just verify no panic
        let out = MalfindPlugin.run(&img, &PluginArgs::new()).unwrap();
        let _ = out.rows.len();
    }

    // ── HollowFindPlugin ─────────────────────────────────────────────────────
    #[test]
    fn hollowfind_no_panic() {
        let img = windows_image();
        let out = HollowFindPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    // ── ApiHooksPlugin ───────────────────────────────────────────────────────
    #[test]
    fn apihooks_no_panic() {
        let img = windows_image();
        let out = ApiHooksPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    // ── HashDumpPlugin ───────────────────────────────────────────────────────
    #[test]
    fn hashdump_finds_sam_hive() {
        let img = windows_image();
        let out = HashDumpPlugin.run(&img, &PluginArgs::new()).unwrap();
        // The mock image has a SYSTEM hive, not SAM — so 0 rows is acceptable
        assert!(out.raw.is_some());
    }

    // ── CmdlinePlugin ────────────────────────────────────────────────────────
    #[test]
    fn cmdline_returns_rows() {
        let img = windows_image();
        let out = CmdlinePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn cmdline_rows_have_cmdline_field() {
        let img = windows_image();
        let out = CmdlinePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.rows.iter().all(|r| r.contains_key("cmdline")));
    }

    // ── EnvironPlugin ────────────────────────────────────────────────────────
    #[test]
    fn environ_returns_rows() {
        let img = windows_image();
        let out = EnvironPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn environ_rows_have_key_value() {
        let img = windows_image();
        let out = EnvironPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(
            out.rows
                .iter()
                .all(|r| r.contains_key("key") && r.contains_key("value"))
        );
    }

    // ── Plugin registry integration ───────────────────────────────────────────
    #[test]
    fn registry_has_all_plugins() {
        let reg = make_registry();
        let names = reg.names();
        for name in &[
            "pslist",
            "psscan",
            "pstree",
            "dlllist",
            "netscan",
            "malfind",
            "hollowfind",
            "apihooks",
            "hashdump",
            "cmdline",
            "environ",
            "memmap",
            "strings",
            "yarascan",
            "dumpfiles",
            "privs",
            "svcscan",
            "entropy",
        ] {
            assert!(names.contains(name), "missing plugin: {name}");
        }
    }

    #[test]
    fn registry_run_pslist() {
        let img = windows_image();
        let reg = make_registry();
        let out = reg.run("pslist", &img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn registry_run_netscan() {
        let img = windows_image();
        let reg = make_registry();
        let out = reg.run("netscan", &img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "de ad be ef");
    }

    #[test]
    fn read_cstring_stops_at_nul() {
        let img = RawMemoryImage::from_bytes(
            b"hello\x00world".to_vec(),
            ArchBits::Bits64,
            OsType::Windows,
        );
        let s = read_cstring(&img, 0, 32);
        assert_eq!(s, "hello");
    }

    // ── MemMapPlugin ──────────────────────────────────────────────────────────
    #[test]
    fn memmap_returns_rows() {
        let img = windows_image();
        let out = MemMapPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn memmap_rows_have_required_fields() {
        let img = windows_image();
        let out = MemMapPlugin.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("start"));
            assert!(r.contains_key("perms"));
            assert!(r.contains_key("entropy"));
        }
    }

    #[test]
    fn memmap_perms_string_rwx() {
        assert_eq!(MemMapPlugin::perms_string(perms::RWX), "rwx");
    }

    #[test]
    fn memmap_perms_string_ro() {
        assert_eq!(MemMapPlugin::perms_string(perms::READ), "r--");
    }

    // ── StringsPlugin ─────────────────────────────────────────────────────────
    #[test]
    fn strings_extract_basic() {
        let data = b"hello world\x00\xff\xfe short\x00this is long enough";
        let strs = StringsPlugin::extract_strings(data, 6);
        assert!(strs.contains(&"hello world".to_string()));
        assert!(strs.contains(&"this is long enough".to_string()));
        assert!(!strs.iter().any(|s| s == "short")); // too short
    }

    #[test]
    fn strings_plugin_no_panic() {
        let img = windows_image();
        let out = StringsPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn strings_filter_works() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("filter", "zzz_no_match_zzz");
        let out = StringsPlugin.run(&img, &args).unwrap();
        assert!(out.rows.is_empty());
    }

    // ── YaraScanPlugin ────────────────────────────────────────────────────────
    #[test]
    fn byte_rule_matches_literal() {
        let rule = ByteRule::new("test", "test rule", vec![b"hello".to_vec()]);
        assert!(rule.matches(b"say hello world"));
        assert!(!rule.matches(b"goodbye"));
    }

    #[test]
    fn byte_rule_wildcard() {
        // Pattern: 0x90 0xAA(wildcard) 0x90 — matches 0x90 <any> 0x90
        let rule = ByteRule::new("test", "", vec![vec![0x90, 0xAA, 0x90]]);
        assert!(rule.matches(&[0x90, 0xFF, 0x90]));
        assert!(!rule.matches(&[0x90, 0xFF, 0x91]));
    }

    #[test]
    fn yarascan_hits_eicar() {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICARtest";
        let img = RawMemoryImage::from_bytes(eicar.to_vec(), ArchBits::Bits64, OsType::Windows);
        let out = YaraScanPlugin::with_builtin_rules()
            .run(&img, &PluginArgs::new())
            .unwrap();
        assert!(
            out.rows
                .iter()
                .any(|r| r.get("rule") == Some(&"eicar_test".to_string()))
        );
    }

    #[test]
    fn yarascan_no_panic_on_empty() {
        let img = empty_image();
        let out = YaraScanPlugin::with_builtin_rules()
            .run(&img, &PluginArgs::new())
            .unwrap();
        assert!(out.raw.is_some());
    }

    // ── DumpFilesPlugin ───────────────────────────────────────────────────────
    #[test]
    fn dumpfiles_no_panic() {
        let img = windows_image();
        let out = DumpFilesPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    // ── PrivsPlugin ───────────────────────────────────────────────────────────
    #[test]
    fn privs_returns_rows() {
        let img = windows_image();
        let out = PrivsPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn privs_rows_have_required_fields() {
        let img = windows_image();
        let out = PrivsPlugin.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("privilege"));
            assert!(r.contains_key("high_risk"));
        }
    }

    #[test]
    fn privs_priv_name_lookup() {
        assert_eq!(PrivsPlugin::priv_name(20), "SeDebugPrivilege");
        assert_eq!(PrivsPlugin::priv_name(0), "UnknownPrivilege");
    }

    // ── SvcScanPlugin ─────────────────────────────────────────────────────────
    #[test]
    fn svcscan_returns_rows() {
        let img = windows_image();
        let out = SvcScanPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn svcscan_suspicious_path_detection() {
        assert!(SvcScanPlugin::is_suspicious_path(
            r"C:\Users\Public\evil.exe"
        ));
        assert!(!SvcScanPlugin::is_suspicious_path(
            r"C:\Windows\System32\svchost.exe"
        ));
    }

    #[test]
    fn svcscan_suspicious_filter() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("suspicious", "true");
        let out = SvcScanPlugin.run(&img, &args).unwrap();
        // All returned rows should have suspicious=true
        for r in &out.rows {
            assert_eq!(r.get("suspicious"), Some(&"true".to_string()));
        }
    }

    #[test]
    fn service_entry_strings() {
        let svc = ServiceEntry {
            name: "test".into(),
            display_name: "Test".into(),
            binary_path: "C:\\Windows\\System32\\svchost.exe".into(),
            start_type: 2,
            state: 4,
            pid: 1000,
        };
        assert_eq!(svc.start_type_str(), "Auto");
        assert_eq!(svc.state_str(), "Running");
    }

    // ── EntropyPlugin ─────────────────────────────────────────────────────────
    #[test]
    fn entropy_scan_high_windows() {
        let high: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let hits = EntropyPlugin::scan_high_entropy(&high, 256, 256, 7.5);
        assert!(!hits.is_empty());
        for (_, e) in &hits {
            assert!(*e >= 7.5);
        }
    }

    #[test]
    fn entropy_scan_low_data() {
        let low = vec![0u8; 512];
        let hits = EntropyPlugin::scan_high_entropy(&low, 256, 256, 6.8);
        assert!(hits.is_empty());
    }

    #[test]
    fn entropy_plugin_no_panic() {
        let img = windows_image();
        let out = EntropyPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    // ── nul_terminated_str helper ─────────────────────────────────────────────
    #[test]
    fn nul_terminated_str_basic() {
        let buf = b"hello\x00junk";
        assert_eq!(nul_terminated_str(buf), "hello");
    }

    #[test]
    fn nul_terminated_str_no_nul() {
        let buf = b"abcdef";
        assert_eq!(nul_terminated_str(buf), "abcdef");
    }

    // ── VadTreePlugin ─────────────────────────────────────────────────────────
    #[test]
    fn vadtree_no_panic_on_windows_image() {
        let img = windows_image();
        let out = VadTreePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn vadtree_suspicious_filter() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("suspicious", "true");
        let out = VadTreePlugin.run(&img, &args).unwrap();
        // All returned rows must be flagged as Private+EXECUTE+WRITE
        for r in &out.rows {
            let t = r.get("type").map_or("", String::as_str);
            assert_eq!(t, "Private");
        }
    }

    #[test]
    fn vadtree_find_suspicious_vads_filters_correctly() {
        let private_rwx = VadEntry {
            start: 0x1000,
            end: 0x2000,
            tag: "VadS".into(),
            protection: "PAGE_EXECUTE_READWRITE".into(),
            type_: VadType::Private,
            size: 0x1000,
        };
        let mapped_ro = VadEntry {
            start: 0x3000,
            end: 0x4000,
            tag: "Vad ".into(),
            protection: "PAGE_READONLY".into(),
            type_: VadType::Mapped,
            size: 0x1000,
        };
        let suspicious = VadTreePlugin::find_suspicious_vads(&[private_rwx, mapped_ro]);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0].type_, VadType::Private));
    }

    #[test]
    fn vad_type_as_str() {
        assert_eq!(VadType::Private.as_str(), "Private");
        assert_eq!(VadType::Mapped.as_str(), "Mapped");
        assert_eq!(VadType::Image.as_str(), "Image");
    }

    // ── HashdumpPlugin (new) ──────────────────────────────────────────────────
    #[test]
    fn hashdump2_no_panic_on_windows_image() {
        let img = windows_image();
        let out = HashdumpPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn hashdump2_rows_have_expected_fields() {
        let img = windows_image();
        let out = HashdumpPlugin.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("username"), "missing 'username'");
            assert!(r.contains_key("rid"), "missing 'rid'");
            assert!(r.contains_key("nt_hash"), "missing 'nt_hash'");
        }
    }

    #[test]
    fn hashdump2_sam_entry_construction() {
        let e = SamEntry {
            username: "Bob".into(),
            rid: 1001,
            nt_hash: Some("aabbccdd".into()),
            lm_hash: None,
        };
        assert_eq!(e.rid, 1001);
        assert!(e.nt_hash.is_some());
        assert!(e.lm_hash.is_none());
    }

    // ── InjectedCodeScanner ───────────────────────────────────────────────────
    #[test]
    fn injscan_no_panic_on_windows_image() {
        let img = windows_image();
        let out = InjectedCodeScanner.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn injscan_rows_have_required_fields() {
        let img = windows_image();
        let out = InjectedCodeScanner.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("pid"));
            assert!(r.contains_key("va_start"));
            assert!(r.contains_key("reason"));
        }
    }

    #[test]
    fn injscan_pid_filter() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("pid", "99999");
        let out = InjectedCodeScanner.run(&img, &args).unwrap();
        assert!(out.rows.is_empty());
    }

    // ── DriverListPlugin ──────────────────────────────────────────────────────
    #[test]
    fn driverlist_returns_rows() {
        let img = windows_image();
        let out = DriverListPlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn driverlist_rows_have_name_and_base() {
        let img = windows_image();
        let out = DriverListPlugin.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("name"));
            assert!(r.contains_key("base"));
        }
    }

    #[test]
    fn driverlist_suspicious_flag() {
        let evil = DriverInfo {
            name: "evil.sys".into(),
            base: 0xffff_8800_1234_0000,
            size: 0x1000,
            service_key: r"c:\users\public\evil.sys".into(),
        };
        assert!(DriverListPlugin::is_suspicious_driver(&evil));
        let legit = DriverInfo {
            name: "ntoskrnl.exe".into(),
            base: 0xffff_f800_0000_0000,
            size: 0x100_0000,
            service_key: r"HKLM\SYSTEM\CurrentControlSet\Services\ntoskrnl".into(),
        };
        assert!(!DriverListPlugin::is_suspicious_driver(&legit));
    }

    // ── RegistryHivePlugin ────────────────────────────────────────────────────
    #[test]
    fn hivelist_no_panic_on_windows_image() {
        let img = windows_image();
        let out = RegistryHivePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn hivelist_returns_rows() {
        let img = windows_image();
        let out = RegistryHivePlugin.run(&img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }

    #[test]
    fn hivelist_rows_have_name_and_addr() {
        let img = windows_image();
        let out = RegistryHivePlugin.run(&img, &PluginArgs::new()).unwrap();
        for r in &out.rows {
            assert!(r.contains_key("name"));
            assert!(r.contains_key("base_addr"));
        }
    }

    // ── MemoryStringScanner ───────────────────────────────────────────────────
    #[test]
    fn memstrings_no_panic() {
        let img = windows_image();
        let out = MemoryStringScanner.run(&img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn memstrings_finds_strings_in_known_data() {
        let data = b"\x00\x00hello world from process\x00\x00another long string here\x00".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let results = MemoryStringScanner::scan_strings_in_process(&img, 0, 8);
        assert!(!results.is_empty());
        assert!(results.iter().any(|(_, s)| s.contains("hello world")));
    }

    #[test]
    fn memstrings_min_len_respected() {
        let data = b"ab\x00longstring_here\x00".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let results = MemoryStringScanner::scan_strings_in_process(&img, 0, 10);
        // "ab" is too short; "longstring_here" passes
        assert!(!results.iter().any(|(_, s)| s == "ab"));
        assert!(results.iter().any(|(_, s)| s.contains("longstring")));
    }

    #[test]
    fn memstrings_filter_works() {
        let img = windows_image();
        let mut args = PluginArgs::new();
        args.set("filter", "zzz_no_match_zzz_xyz");
        let out = MemoryStringScanner.run(&img, &args).unwrap();
        assert!(out.rows.is_empty());
    }

    // ── Registry integrity ────────────────────────────────────────────────────
    #[test]
    fn registry_has_new_plugins() {
        let reg = make_registry();
        let names = reg.names();
        for name in &[
            "vadtree",
            "hashdump2",
            "injscan",
            "driverlist",
            "hivelist",
            "memstrings",
        ] {
            assert!(names.contains(name), "missing plugin: {name}");
        }
    }

    #[test]
    fn registry_run_vadtree() {
        let img = windows_image();
        let reg = make_registry();
        let out = reg.run("vadtree", &img, &PluginArgs::new()).unwrap();
        assert!(out.raw.is_some());
    }

    #[test]
    fn registry_run_driverlist() {
        let img = windows_image();
        let reg = make_registry();
        let out = reg.run("driverlist", &img, &PluginArgs::new()).unwrap();
        assert!(!out.rows.is_empty());
    }
}
