//! AFL++ QEMU mode integration stubs.
//!
//! QEMU mode lets AFL++ instrument binaries that cannot be recompiled by
//! running them under QEMU user-mode emulation with a patched TCG backend
//! that injects coverage feedback.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

// ─── TargetArch ───────────────────────────────────────────────────────────────

/// Target architecture for QEMU user-mode emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArch {
    /// x86-64.
    X86_64,
    /// i386 / x86.
    I386,
    /// `AArch64` / ARM64.
    Aarch64,
    /// ARM 32-bit.
    Arm,
    /// MIPS 32-bit.
    Mips,
    /// MIPS 64-bit.
    Mips64,
    /// RISC-V 64.
    RiscV64,
    /// PowerPC 64.
    Ppc64,
}

impl fmt::Display for TargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::X86_64 => "x86_64",
            Self::I386 => "i386",
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::RiscV64 => "riscv64",
            Self::Ppc64 => "ppc64",
        };
        write!(f, "{s}")
    }
}

// ─── QemuModeConfig ───────────────────────────────────────────────────────────

/// Configuration for running the target under QEMU.
#[derive(Debug, Clone)]
pub struct QemuModeConfig {
    /// Path to the `qemu-<arch>` binary.
    pub qemu_path: PathBuf,
    /// Target architecture.
    pub target_arch: TargetArch,
    /// Use QEMU user-mode (vs system-mode).
    pub user_mode: bool,
    /// Shared memory size for coverage map (default 65536).
    pub shm_size: usize,
    /// Extra QEMU command-line arguments.
    pub extra_args: Vec<String>,
    /// Whether compcov (compare instrumentation) is enabled.
    pub compcov_enabled: bool,
    /// `AFL_QEMU_COMPCOV_LEVEL` (1 or 2).
    pub compcov_level: u8,
    /// Whether persistent mode via `AFL_QEMU_PERSISTENT_ADDR` is used.
    pub persistent: bool,
    /// Persistent address (entry to persistent loop).
    pub persistent_addr: Option<u64>,
    /// Address at which the fuzz target returns from persistent mode.
    pub persistent_ret: Option<u64>,
    /// Maximum iterations per persistent run.
    pub persistent_cnt: u64,
}

impl QemuModeConfig {
    /// Default shared memory size for AFL coverage maps.
    pub const DEFAULT_SHM_SIZE: usize = 65536;

    /// Create a minimal config.
    #[must_use]
    pub fn new(qemu_path: impl Into<PathBuf>, target_arch: TargetArch) -> Self {
        Self {
            qemu_path: qemu_path.into(),
            target_arch,
            user_mode: true,
            shm_size: Self::DEFAULT_SHM_SIZE,
            extra_args: Vec::new(),
            compcov_enabled: false,
            compcov_level: 1,
            persistent: false,
            persistent_addr: None,
            persistent_ret: None,
            persistent_cnt: 1000,
        }
    }

    /// Enable compare coverage.
    #[must_use] 
    pub const fn with_compcov(mut self, level: u8) -> Self {
        self.compcov_enabled = true;
        self.compcov_level = level;
        self
    }

    /// Enable persistent mode.
    #[must_use] 
    pub const fn with_persistent(mut self, addr: u64, ret: u64, count: u64) -> Self {
        self.persistent = true;
        self.persistent_addr = Some(addr);
        self.persistent_ret = Some(ret);
        self.persistent_cnt = count;
        self
    }

    /// Return the QEMU binary name for this config.
    #[must_use]
    pub fn qemu_binary_name(&self) -> String {
        format!("qemu-{}", self.target_arch)
    }

    /// Build the environment variables AFL++ would set for this config.
    #[must_use]
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        if self.compcov_enabled {
            env.insert(
                "AFL_COMPCOV_LEVEL".to_string(),
                self.compcov_level.to_string(),
            );
        }
        if let Some(addr) = self.persistent_addr {
            env.insert("AFL_QEMU_PERSISTENT_ADDR".to_string(), format!("{addr:#x}"));
        }
        if let Some(ret) = self.persistent_ret {
            env.insert("AFL_QEMU_PERSISTENT_RET".to_string(), format!("{ret:#x}"));
        }
        if self.persistent {
            env.insert(
                "AFL_QEMU_PERSISTENT_CNT".to_string(),
                self.persistent_cnt.to_string(),
            );
        }
        env
    }
}

// ─── QemuCoverageMap ──────────────────────────────────────────────────────────

/// Coverage map produced by QEMU instrumented execution.
///
/// Equivalent to the AFL++ SHM coverage bitmap, indexed by
/// `(block_addr >> 1) XOR prev_block`.
#[derive(Debug, Clone)]
pub struct QemuCoverageMap {
    /// 64 KiB bitmap.
    pub bitmap: Vec<u8>,
}

impl QemuCoverageMap {
    /// Bitmap size (64 KiB).
    pub const SIZE: usize = 65536;

    /// Create a zeroed coverage map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bitmap: vec![0u8; Self::SIZE],
        }
    }

    /// Create a "virgin" map (all 0xFF = not yet seen).
    #[must_use]
    pub fn new_virgin() -> Self {
        Self {
            bitmap: vec![0xFF; Self::SIZE],
        }
    }

    /// Record a transition `prev_loc → cur_loc`.
    pub fn record(&mut self, prev_loc: u64, cur_loc: u64) {
        let idx = usize::try_from((cur_loc >> 1) ^ prev_loc).unwrap_or(0) & (Self::SIZE - 1);
        self.bitmap[idx] = self.bitmap[idx].saturating_add(1);
    }

    /// Number of set (non-zero) bytes.
    #[must_use]
    pub fn coverage(&self) -> usize {
        self.bitmap.iter().filter(|&&b| b != 0).count()
    }

    /// Coverage as a percentage of the map size.
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        f64::from(u32::try_from(self.coverage()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(Self::SIZE).unwrap_or(u32::MAX)) * 100.0
    }

    /// Merge another map into self (take maximum byte value).
    pub fn merge_max(&mut self, other: &Self) {
        for (a, &b) in self.bitmap.iter_mut().zip(&other.bitmap) {
            *a = (*a).max(b);
        }
    }

    /// Check if `other` has new bits vs. this map.
    #[must_use]
    pub fn has_new_bits(&self, other: &Self) -> bool {
        self.bitmap
            .iter()
            .zip(&other.bitmap)
            .any(|(&a, &b)| b != 0 && a == 0)
    }
}

impl Default for QemuCoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

// ─── QemuForkServer ───────────────────────────────────────────────────────────

/// Stub for the QEMU-mode fork-server protocol.
///
/// In production this communicates with a patched `qemu-user` binary over a
/// pipe.  Here we model the state machine without spawning real processes.
#[derive(Debug, Default)]
pub struct QemuForkServer {
    /// Whether the fork-server handshake has completed.
    pub ready: bool,
    /// Number of fork-server rounds executed.
    pub run_count: u64,
    /// Accumulated coverage.
    pub coverage: QemuCoverageMap,
    /// Config.
    pub config: Option<QemuModeConfig>,
}

impl QemuForkServer {
    /// Create an unconnected fork server.
    #[must_use]
    pub fn new(config: QemuModeConfig) -> Self {
        Self {
            ready: false,
            run_count: 0,
            coverage: QemuCoverageMap::new(),
            config: Some(config),
        }
    }

    /// Simulate the initial handshake.
    pub const fn handshake(&mut self) -> bool {
        self.ready = true;
        true
    }

    /// Simulate running one test case with `input` bytes.
    /// Returns the exit status (0 = clean, non-zero = crash/signal).
    pub fn run_one(&mut self, input: &[u8]) -> i32 {
        if !self.ready {
            return -1;
        }
        self.run_count += 1;
        // Toy: record an edge based on input length
        let prev = (input.len() as u64).wrapping_mul(0x811c_9dc5);
        let cur = prev.wrapping_add(1);
        self.coverage.record(prev, cur);
        0
    }

    /// Total runs.
    #[must_use]
    pub const fn run_count(&self) -> u64 {
        self.run_count
    }

    /// Reset coverage map.
    pub fn reset_coverage(&mut self) {
        self.coverage = QemuCoverageMap::new();
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TargetArch ───────────────────────────────────────────────────────────

    #[test]
    fn arch_display() {
        assert_eq!(TargetArch::X86_64.to_string(), "x86_64");
        assert_eq!(TargetArch::Aarch64.to_string(), "aarch64");
    }

    // ── QemuModeConfig ────────────────────────────────────────────────────────

    #[test]
    fn config_qemu_binary_name() {
        let cfg = QemuModeConfig::new("/usr/bin/qemu-x86_64", TargetArch::X86_64);
        assert_eq!(cfg.qemu_binary_name(), "qemu-x86_64");
    }

    #[test]
    fn config_with_compcov() {
        let cfg = QemuModeConfig::new("/usr/bin/qemu-arm", TargetArch::Arm).with_compcov(2);
        assert!(cfg.compcov_enabled);
        assert_eq!(cfg.compcov_level, 2);
    }

    #[test]
    fn config_with_persistent() {
        let cfg = QemuModeConfig::new("/usr/bin/qemu-aarch64", TargetArch::Aarch64)
            .with_persistent(0x401000, 0x401100, 5000);
        assert!(cfg.persistent);
        assert_eq!(cfg.persistent_addr, Some(0x401000));
    }

    #[test]
    fn config_env_vars_persistent() {
        let cfg =
            QemuModeConfig::new("/q", TargetArch::X86_64).with_persistent(0x1000, 0x1100, 100);
        let env = cfg.env_vars();
        assert!(env.contains_key("AFL_QEMU_PERSISTENT_ADDR"));
        assert!(env.contains_key("AFL_QEMU_PERSISTENT_CNT"));
    }

    #[test]
    fn config_env_vars_compcov() {
        let cfg = QemuModeConfig::new("/q", TargetArch::I386).with_compcov(1);
        let env = cfg.env_vars();
        assert_eq!(env.get("AFL_COMPCOV_LEVEL").map(String::as_str), Some("1"));
    }

    // ── QemuCoverageMap ───────────────────────────────────────────────────────

    #[test]
    fn coverage_map_record() {
        let mut m = QemuCoverageMap::new();
        m.record(0x1000, 0x2000);
        assert!(m.coverage() >= 1);
    }

    #[test]
    fn coverage_map_new_virgin_all_ff() {
        let v = QemuCoverageMap::new_virgin();
        assert!(v.bitmap.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn coverage_map_merge_max() {
        let mut a = QemuCoverageMap::new();
        a.bitmap[0] = 5;
        let mut b = QemuCoverageMap::new();
        b.bitmap[0] = 10;
        a.merge_max(&b);
        assert_eq!(a.bitmap[0], 10);
    }

    #[test]
    fn coverage_map_has_new_bits() {
        let a = QemuCoverageMap::new();
        let mut b = QemuCoverageMap::new();
        b.bitmap[42] = 1;
        assert!(a.has_new_bits(&b));
    }

    #[test]
    fn coverage_pct_empty() {
        let m = QemuCoverageMap::new();
        assert_eq!(m.coverage_pct(), 0.0);
    }

    // ── QemuForkServer ────────────────────────────────────────────────────────

    #[test]
    fn fork_server_handshake() {
        let cfg = QemuModeConfig::new("/q", TargetArch::X86_64);
        let mut fs = QemuForkServer::new(cfg);
        assert!(!fs.ready);
        assert!(fs.handshake());
        assert!(fs.ready);
    }

    #[test]
    fn fork_server_run_increments() {
        let cfg = QemuModeConfig::new("/q", TargetArch::X86_64);
        let mut fs = QemuForkServer::new(cfg);
        fs.handshake();
        fs.run_one(b"hello");
        fs.run_one(b"world");
        assert_eq!(fs.run_count(), 2);
    }

    #[test]
    fn fork_server_run_before_handshake_returns_error() {
        let cfg = QemuModeConfig::new("/q", TargetArch::X86_64);
        let mut fs = QemuForkServer::new(cfg);
        assert_eq!(fs.run_one(b"abc"), -1);
    }

    #[test]
    fn fork_server_reset_coverage() {
        let cfg = QemuModeConfig::new("/q", TargetArch::X86_64);
        let mut fs = QemuForkServer::new(cfg);
        fs.handshake();
        fs.run_one(b"data");
        assert!(fs.coverage.coverage() > 0);
        fs.reset_coverage();
        assert_eq!(fs.coverage.coverage(), 0);
    }
}
