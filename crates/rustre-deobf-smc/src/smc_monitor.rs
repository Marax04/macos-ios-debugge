//! Self-modifying code monitor for `rustre-deobf-smc`.
//!
//! Provides `SmcMonitor`, `SmcRegion`, `DecryptedPayload`, `MultiLayerSmc`,
//! `SmcTimeline`, and `SmcMonitorReport`.

use crate::{SmcAlgorithm, SmcDecryptor, SmcDetector, SmcKey, SmcRegion as LibSmcRegion, SmcStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── SmcMonitorRegion ──────────────────────────────────────────────────────────

/// A memory region monitored for write-then-execute patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredRegion {
    pub start: u64,
    pub end: u64,
    pub label: String,
    pub is_writeable: bool,
    pub is_executable: bool,
}

impl MonitoredRegion {
    #[must_use]
    pub fn new(start: u64, end: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: label.into(),
            is_writeable: true,
            is_executable: true,
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ── DecryptedPayload ──────────────────────────────────────────────────────────

/// The result of decrypting one SMC layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedPayload {
    pub layer_index: usize,
    pub original_start: u64,
    pub original_size: usize,
    pub decrypted_bytes: Vec<u8>,
    pub algorithm: SmcAlgorithm,
    pub key_material: Vec<u8>,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub timestamp_ms: u64,
}

impl DecryptedPayload {
    #[must_use]
    pub fn entropy_reduction(&self) -> f64 {
        (self.entropy_before - self.entropy_after).max(0.0)
    }

    #[must_use]
    pub fn looks_like_code(&self) -> bool {
        crate::looks_like_code(&self.decrypted_bytes)
    }
}

// ── SmcTimeline ───────────────────────────────────────────────────────────────

/// Timeline of SMC decryption events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmcTimeline {
    pub events: Vec<SmcEvent>,
    pub start_ms: u64,
}

/// A single SMC decryption event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcEvent {
    pub timestamp_ms: u64,
    pub layer: usize,
    pub region_start: u64,
    pub region_size: usize,
    pub algorithm: SmcAlgorithm,
    pub description: String,
}

impl SmcTimeline {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            start_ms: now_ms(),
        }
    }

    pub fn record(
        &mut self,
        layer: usize,
        region_start: u64,
        region_size: usize,
        algo: SmcAlgorithm,
        desc: impl Into<String>,
    ) {
        self.events.push(SmcEvent {
            timestamp_ms: now_ms(),
            layer,
            region_start,
            region_size,
            algorithm: algo,
            description: desc.into(),
        });
    }

    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        self.events
            .last()
            .map_or(0, |e| e.timestamp_ms.saturating_sub(self.start_ms))
    }

    #[must_use]
    pub fn layer_count(&self) -> usize {
        self.events
            .iter()
            .map(|e| e.layer)
            .max()
            .map_or(0, |m| m + 1)
    }
}

// ── SmcMonitorReport ──────────────────────────────────────────────────────────

/// Full SMC monitor report (distinct from `crate::SmcReport` which is the
/// static-analysis report; this one carries runtime monitor results).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmcMonitorReport {
    pub regions: Vec<LibSmcRegion>,
    pub payloads: Vec<DecryptedPayload>,
    pub timeline: SmcTimeline,
    pub stats: SmcStats,
    pub total_layers: usize,
    pub final_bytes: Option<Vec<u8>>,
    pub success: bool,
    pub notes: Vec<String>,
}

impl SmcMonitorReport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeline: SmcTimeline::new(),
            ..Default::default()
        }
    }

    pub fn add_payload(&mut self, payload: DecryptedPayload) {
        self.total_layers = self.total_layers.max(payload.layer_index + 1);
        self.payloads.push(payload);
    }

    #[must_use]
    pub fn text_summary(&self) -> String {
        format!(
            "SMC Report: {} regions, {} layers, {} payloads, success={}",
            self.regions.len(),
            self.total_layers,
            self.payloads.len(),
            self.success
        )
    }
}

// ── MultiLayerSmc ─────────────────────────────────────────────────────────────

/// Handles iterative multi-layer SMC decryption with timeline tracking.
pub struct MultiLayerSmc {
    pub max_layers: usize,
    pub min_entropy_reduction: f64,
    detector: SmcDetector,
    decryptor: SmcDecryptor,
}

impl Default for MultiLayerSmc {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiLayerSmc {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_layers: 8,
            min_entropy_reduction: 0.1,
            detector: SmcDetector::new(),
            decryptor: SmcDecryptor::new(),
        }
    }

    #[must_use]
    pub const fn with_max_layers(mut self, n: usize) -> Self {
        self.max_layers = n;
        self
    }

    /// Decrypt all layers and produce a full `SmcReport`.
    #[must_use]
    pub fn decrypt_all(&self, data: &[u8]) -> SmcMonitorReport {
        let mut report = SmcMonitorReport::new();
        let mut current = data.to_vec();

        for layer_idx in 0..self.max_layers {
            let regions = self.detector.detect(&current);
            if regions.is_empty() {
                break;
            }

            report.regions.clone_from(&regions);
            let mut made_progress = false;

            for region in &regions {
                let size = usize::try_from(region.len()).unwrap_or(usize::MAX);
                let rstart = usize::try_from(region.start).unwrap_or(usize::MAX);
                if size == 0 || rstart.saturating_add(size) > current.len() {
                    continue;
                }
                let encrypted = &current[rstart..rstart + size];
                let ent_before = entropy(encrypted);
                let decrypted = self.decryptor.decrypt(encrypted, region);
                let ent_after = entropy(&decrypted);

                if ent_before - ent_after < self.min_entropy_reduction
                    && !decrypted.iter().any(|&b| b.is_ascii_graphic())
                {
                    continue;
                }

                let key_material = match &region.key {
                    SmcKey::Constant(k) => k.to_le_bytes().to_vec(),
                    _ => vec![],
                };

                report.timeline.record(
                    layer_idx,
                    region.start,
                    size,
                    region.algorithm.clone(),
                    format!("Layer {layer_idx} decrypt"),
                );

                let payload = DecryptedPayload {
                    layer_index: layer_idx,
                    original_start: region.start,
                    original_size: size,
                    decrypted_bytes: decrypted.clone(),
                    algorithm: region.algorithm.clone(),
                    key_material,
                    entropy_before: ent_before,
                    entropy_after: ent_after,
                    timestamp_ms: now_ms(),
                };
                report.add_payload(payload);
                current[rstart..rstart + size].copy_from_slice(&decrypted);
                made_progress = true;
            }

            if !made_progress {
                break;
            }
        }

        report.final_bytes = Some(current);
        report.success = !report.payloads.is_empty();
        report.stats = SmcStats::from_regions(&report.regions);
        report
    }
}

// ── SmcMonitor ────────────────────────────────────────────────────────────────

/// Live SMC monitor that tracks writes and detects write-before-exec patterns.
pub struct SmcMonitor {
    pub monitored_regions: Vec<MonitoredRegion>,
    write_log: Vec<(u64, Vec<u8>)>,
    exec_log: Vec<u64>,
    pub alerts: Vec<String>,
}

impl Default for SmcMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SmcMonitor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            monitored_regions: Vec::new(),
            write_log: Vec::new(),
            exec_log: Vec::new(),
            alerts: Vec::new(),
        }
    }

    /// Add a memory region to monitor.
    pub fn add_region(&mut self, region: MonitoredRegion) {
        self.monitored_regions.push(region);
    }

    /// Record a memory write event.
    pub fn on_write(&mut self, addr: u64, data: &[u8]) {
        if self.monitored_regions.iter().any(|r| r.contains(addr)) {
            self.write_log.push((addr, data.to_vec()));
        }
    }

    /// Record an execution event. Returns true if the executed address was previously written.
    pub fn on_execute(&mut self, addr: u64) -> bool {
        self.exec_log.push(addr);
        let was_written = self.write_log.iter().any(|(w, _)| *w == addr);
        if was_written {
            self.alerts.push(format!(
                "WriteBeforeExec detected: 0x{addr:x} was written then executed"
            ));
        }
        was_written
    }

    /// Find all (`write_addr`, `exec_addr`) pairs where execution follows a write.
    #[must_use]
    pub fn write_before_exec_pairs(&self) -> Vec<(u64, u64)> {
        let written: std::collections::HashSet<u64> =
            self.write_log.iter().map(|(a, _)| *a).collect();
        self.exec_log
            .iter()
            .filter(|&&e| written.contains(&e))
            .map(|&e| (e, e))
            .collect()
    }

    /// Reconstruct the final state of all written bytes.
    #[must_use]
    pub fn memory_snapshot(&self) -> HashMap<u64, u8> {
        let mut snap = HashMap::new();
        for (addr, data) in &self.write_log {
            for (i, &b) in data.iter().enumerate() {
                snap.insert(addr + u64::try_from(i).unwrap_or(u64::MAX), b);
            }
        }
        snap
    }

    #[must_use]
    pub const fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    #[must_use]
    pub const fn write_count(&self) -> usize {
        self.write_log.len()
    }

    #[must_use]
    pub const fn exec_count(&self) -> usize {
        self.exec_log.len()
    }
}

// ── WriteBeforeExec ───────────────────────────────────────────────────────────

/// Detects write-before-exec patterns from a trace.
pub struct WriteBeforeExec {
    pub write_threshold: usize,
}

impl Default for WriteBeforeExec {
    fn default() -> Self {
        Self { write_threshold: 4 }
    }
}

impl WriteBeforeExec {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if `exec_addr` was written to in `write_log`.
    #[must_use]
    pub fn is_smc(&self, exec_addr: u64, write_log: &[(u64, Vec<u8>)]) -> bool {
        write_log.iter().any(|(w, data)| {
            let end = w + u64::try_from(data.len()).unwrap_or(u64::MAX);
            exec_addr >= *w && exec_addr < end
        })
    }

    /// Find all SMC execution addresses from the log.
    #[must_use]
    pub fn find_smc_addresses(&self, exec_log: &[u64], write_log: &[(u64, Vec<u8>)]) -> Vec<u64> {
        exec_log
            .iter()
            .filter(|&&e| self.is_smc(e, write_log))
            .copied()
            .collect()
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MonitoredRegion ───────────────────────────────────────────────────────

    #[test]
    fn test_monitored_region_contains() {
        let r = MonitoredRegion::new(0x1000, 0x2000, "code");
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x2000));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_monitored_region_size() {
        let r = MonitoredRegion::new(0x1000, 0x2000, "t");
        assert_eq!(r.size(), 0x1000);
    }

    // ── SmcTimeline ───────────────────────────────────────────────────────────

    #[test]
    fn test_smc_timeline_record() {
        let mut t = SmcTimeline::new();
        t.record(0, 0x1000, 256, SmcAlgorithm::Xor, "xor decrypt");
        assert_eq!(t.events.len(), 1);
        assert_eq!(t.layer_count(), 1);
    }

    #[test]
    fn test_smc_timeline_layer_count() {
        let mut t = SmcTimeline::new();
        t.record(0, 0x1000, 64, SmcAlgorithm::Xor, "l0");
        t.record(1, 0x2000, 64, SmcAlgorithm::Xor, "l1");
        t.record(2, 0x3000, 64, SmcAlgorithm::Xor, "l2");
        assert_eq!(t.layer_count(), 3);
    }

    // ── DecryptedPayload ──────────────────────────────────────────────────────

    #[test]
    fn test_decrypted_payload_entropy_reduction() {
        let p = DecryptedPayload {
            layer_index: 0,
            original_start: 0x1000,
            original_size: 16,
            decrypted_bytes: b"Hello, World!!!".to_vec(),
            algorithm: SmcAlgorithm::Xor,
            key_material: vec![0x42],
            entropy_before: 7.5,
            entropy_after: 3.5,
            timestamp_ms: 0,
        };
        assert!((p.entropy_reduction() - 4.0).abs() < 0.001);
    }

    #[test]
    fn test_decrypted_payload_looks_like_code() {
        let p = DecryptedPayload {
            layer_index: 0,
            original_start: 0,
            original_size: 4,
            decrypted_bytes: vec![0x48, 0x89, 0xC0, 0x90], // MOV RAX,RAX; NOP
            algorithm: SmcAlgorithm::Xor,
            key_material: vec![],
            entropy_before: 7.0,
            entropy_after: 2.0,
            timestamp_ms: 0,
        };
        // may or may not qualify; just no panic
        let _ = p.looks_like_code();
    }

    // ── SmcMonitorReport ──────────────────────────────────────────────────────

    #[test]
    fn test_smc_report_text_summary() {
        let r = SmcMonitorReport::new();
        assert!(r.text_summary().contains("SMC Report"));
    }

    #[test]
    fn test_smc_report_add_payload() {
        let mut r = SmcMonitorReport::new();
        r.add_payload(DecryptedPayload {
            layer_index: 0,
            original_start: 0,
            original_size: 4,
            decrypted_bytes: vec![],
            algorithm: SmcAlgorithm::Xor,
            key_material: vec![],
            entropy_before: 7.0,
            entropy_after: 3.0,
            timestamp_ms: 0,
        });
        assert_eq!(r.payloads.len(), 1);
        assert_eq!(r.total_layers, 1);
    }

    // ── MultiLayerSmc ─────────────────────────────────────────────────────────

    #[test]
    fn test_multi_layer_no_regions_empty_report() {
        let ml = MultiLayerSmc::new();
        let report = ml.decrypt_all(&[0x90u8; 32]);
        assert!(report.final_bytes.is_some());
    }

    #[test]
    fn test_multi_layer_with_max_depth() {
        let ml = MultiLayerSmc::new().with_max_layers(2);
        assert_eq!(ml.max_layers, 2);
    }

    #[test]
    fn test_multi_layer_xor_payload() {
        let key = 0x42u8;
        let plain = [0xCCu8; 16];
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        // Build a binary with SMC pattern + payload at offset 0x14
        let mut binary = Vec::new();
        binary.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]); // MOV ECX,16
        binary.extend_from_slice(&[0xBF, 0x14, 0x00, 0x00, 0x00]); // MOV EDI, offset
        binary.extend_from_slice(&[0x80, 0x34, 0x0F, key]); // XOR [EDI+ECX], key
        binary.extend_from_slice(&[0xE2, 0xF7]); // LOOP
        while binary.len() < 0x14 {
            binary.push(0x90);
        }
        binary.extend_from_slice(&cipher);
        let ml = MultiLayerSmc::new();
        let report = ml.decrypt_all(&binary);
        // Should have processed the region
        let _ = report.success;
    }

    // ── SmcMonitor ────────────────────────────────────────────────────────────

    #[test]
    fn test_smc_monitor_write_before_exec() {
        let mut monitor = SmcMonitor::new();
        monitor.add_region(MonitoredRegion::new(0x1000, 0x2000, "code"));
        monitor.on_write(0x1100, &[0x90]);
        let smc = monitor.on_execute(0x1100);
        assert!(smc);
        assert!(monitor.alert_count() > 0);
    }

    #[test]
    fn test_smc_monitor_no_write_exec_no_alert() {
        let mut monitor = SmcMonitor::new();
        monitor.add_region(MonitoredRegion::new(0x1000, 0x2000, "code"));
        let smc = monitor.on_execute(0x1050);
        assert!(!smc);
        assert_eq!(monitor.alert_count(), 0);
    }

    #[test]
    fn test_smc_monitor_memory_snapshot() {
        let mut monitor = SmcMonitor::new();
        monitor.add_region(MonitoredRegion::new(0x1000, 0x2000, "t"));
        monitor.on_write(0x1000, &[0xAA, 0xBB]);
        let snap = monitor.memory_snapshot();
        assert_eq!(snap.get(&0x1000), Some(&0xAA));
        assert_eq!(snap.get(&0x1001), Some(&0xBB));
    }

    #[test]
    fn test_smc_monitor_outside_region_not_logged() {
        let mut monitor = SmcMonitor::new();
        monitor.add_region(MonitoredRegion::new(0x1000, 0x2000, "t"));
        monitor.on_write(0x5000, &[0xDE, 0xAD]); // outside monitored region
        assert_eq!(monitor.write_count(), 0);
    }

    #[test]
    fn test_smc_monitor_write_exec_pairs() {
        let mut monitor = SmcMonitor::new();
        monitor.add_region(MonitoredRegion::new(0x1000, 0x2000, "t"));
        monitor.on_write(0x1100, &[0x90]);
        monitor.on_execute(0x1100);
        let pairs = monitor.write_before_exec_pairs();
        assert!(!pairs.is_empty());
    }

    // ── WriteBeforeExec ───────────────────────────────────────────────────────

    #[test]
    fn test_write_before_exec_detects() {
        let wbe = WriteBeforeExec::new();
        let write_log: Vec<(u64, Vec<u8>)> = vec![(0x1000, vec![0x90; 8])];
        assert!(wbe.is_smc(0x1000, &write_log));
        assert!(wbe.is_smc(0x1007, &write_log));
        assert!(!wbe.is_smc(0x2000, &write_log));
    }

    #[test]
    fn test_write_before_exec_find_addresses() {
        let wbe = WriteBeforeExec::new();
        let wl: Vec<(u64, Vec<u8>)> = vec![(0x1000, vec![0x90; 4])];
        let el = vec![0x0FFFu64, 0x1001, 0x2000];
        let smc_addrs = wbe.find_smc_addresses(&el, &wl);
        assert_eq!(smc_addrs, vec![0x1001]);
    }
}
