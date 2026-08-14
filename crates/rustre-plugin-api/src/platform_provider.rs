// rustre-plugin-api/src/platform_provider.rs
// Platform provider sub-API: Platform, CallingConventionDef, built-in platforms.

use std::collections::HashMap;

use crate::Plugin;

// ─── Register Definitions ────────────────────────────────────────────────────

/// A named CPU register.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Register {
    pub name: String,
    /// Width in bits.
    pub width: usize,
    /// True if this is a floating-point / SIMD register.
    pub is_float: bool,
}

impl Register {
    #[must_use]
    pub fn new(name: &str, width: usize) -> Self {
        Self {
            name: name.to_string(),
            width,
            is_float: false,
        }
    }
    #[must_use]
    pub fn float(name: &str, width: usize) -> Self {
        Self {
            name: name.to_string(),
            width,
            is_float: true,
        }
    }
}

// ─── Stack Convention ────────────────────────────────────────────────────────

/// Which direction the stack grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackGrowth {
    Down,
    Up,
}

// ─── Calling Convention ──────────────────────────────────────────────────────

/// Full definition of a calling convention.
#[derive(Debug, Clone)]
pub struct CallingConventionDef {
    /// Human-readable name (e.g. "System V AMD64 ABI").
    pub name: String,
    /// Short identifier (e.g. "sysv64").
    pub id: String,
    /// Registers used to pass integer/pointer arguments (in order).
    pub int_arg_regs: Vec<Register>,
    /// Registers used to pass floating-point arguments (in order).
    pub float_arg_regs: Vec<Register>,
    /// Register that holds the primary return value.
    pub return_reg: Register,
    /// Register that holds the secondary return value (e.g. RDX on some ABIs).
    pub return_reg_high: Option<Register>,
    /// Registers the callee must preserve.
    pub callee_saved: Vec<Register>,
    /// Registers the caller must preserve (caller-saved).
    pub caller_saved: Vec<Register>,
    /// Register used as the stack pointer.
    pub stack_pointer: Register,
    /// Register used as the frame/base pointer.
    pub frame_pointer: Option<Register>,
    /// Stack growth direction.
    pub stack_growth: StackGrowth,
    /// Required stack alignment in bytes at call site.
    pub stack_align: usize,
    /// Whether the callee cleans up stack args (true for stdcall/fastcall).
    pub callee_cleanup: bool,
    /// Whether the convention supports variadic arguments.
    pub variadic: bool,
    /// Shadow/home space required on the stack before first arg (bytes).
    pub shadow_space: usize,
}

impl CallingConventionDef {
    /// System V AMD64 ABI (Linux, macOS x86-64).
    #[must_use]
    pub fn sysv_amd64() -> Self {
        let reg = |n: &str| Register::new(n, 64);
        let freg = |n: &str| Register::float(n, 128);
        Self {
            name: "System V AMD64 ABI".to_string(),
            id: "sysv64".to_string(),
            int_arg_regs: vec![
                reg("rdi"),
                reg("rsi"),
                reg("rdx"),
                reg("rcx"),
                reg("r8"),
                reg("r9"),
            ],
            float_arg_regs: vec![
                freg("xmm0"),
                freg("xmm1"),
                freg("xmm2"),
                freg("xmm3"),
                freg("xmm4"),
                freg("xmm5"),
                freg("xmm6"),
                freg("xmm7"),
            ],
            return_reg: reg("rax"),
            return_reg_high: Some(reg("rdx")),
            callee_saved: vec![
                reg("rbx"),
                reg("rbp"),
                reg("r12"),
                reg("r13"),
                reg("r14"),
                reg("r15"),
            ],
            caller_saved: vec![
                reg("rax"),
                reg("rcx"),
                reg("rdx"),
                reg("rsi"),
                reg("rdi"),
                reg("r8"),
                reg("r9"),
                reg("r10"),
                reg("r11"),
            ],
            stack_pointer: reg("rsp"),
            frame_pointer: Some(reg("rbp")),
            stack_growth: StackGrowth::Down,
            stack_align: 16,
            callee_cleanup: false,
            variadic: true,
            shadow_space: 0,
        }
    }

    /// Microsoft x64 calling convention (Windows).
    #[must_use]
    pub fn win64() -> Self {
        let reg = |n: &str| Register::new(n, 64);
        let freg = |n: &str| Register::float(n, 128);
        Self {
            name: "Microsoft x64".to_string(),
            id: "win64".to_string(),
            int_arg_regs: vec![reg("rcx"), reg("rdx"), reg("r8"), reg("r9")],
            float_arg_regs: vec![freg("xmm0"), freg("xmm1"), freg("xmm2"), freg("xmm3")],
            return_reg: reg("rax"),
            return_reg_high: None,
            callee_saved: vec![
                reg("rbx"),
                reg("rbp"),
                reg("rdi"),
                reg("rsi"),
                reg("r12"),
                reg("r13"),
                reg("r14"),
                reg("r15"),
            ],
            caller_saved: vec![
                reg("rax"),
                reg("rcx"),
                reg("rdx"),
                reg("r8"),
                reg("r9"),
                reg("r10"),
                reg("r11"),
            ],
            stack_pointer: reg("rsp"),
            frame_pointer: Some(reg("rbp")),
            stack_growth: StackGrowth::Down,
            stack_align: 16,
            callee_cleanup: false,
            variadic: true,
            shadow_space: 32,
        }
    }

    /// ARM64 (`AArch64`) procedure call standard (AAPCS64).
    #[must_use]
    pub fn aapcs64() -> Self {
        let reg = |n: &str| Register::new(n, 64);
        let freg = |n: &str| Register::float(n, 128);
        Self {
            name: "AArch64 Procedure Call Standard".to_string(),
            id: "aapcs64".to_string(),
            int_arg_regs: vec![
                reg("x0"),
                reg("x1"),
                reg("x2"),
                reg("x3"),
                reg("x4"),
                reg("x5"),
                reg("x6"),
                reg("x7"),
            ],
            float_arg_regs: vec![
                freg("v0"),
                freg("v1"),
                freg("v2"),
                freg("v3"),
                freg("v4"),
                freg("v5"),
                freg("v6"),
                freg("v7"),
            ],
            return_reg: reg("x0"),
            return_reg_high: Some(reg("x1")),
            callee_saved: vec![
                reg("x19"),
                reg("x20"),
                reg("x21"),
                reg("x22"),
                reg("x23"),
                reg("x24"),
                reg("x25"),
                reg("x26"),
                reg("x27"),
                reg("x28"),
                reg("x29"),
                reg("x30"),
            ],
            caller_saved: vec![
                reg("x0"),
                reg("x1"),
                reg("x2"),
                reg("x3"),
                reg("x4"),
                reg("x5"),
                reg("x6"),
                reg("x7"),
                reg("x8"),
                reg("x9"),
                reg("x10"),
                reg("x11"),
                reg("x12"),
                reg("x13"),
                reg("x14"),
                reg("x15"),
                reg("x16"),
                reg("x17"),
            ],
            stack_pointer: reg("sp"),
            frame_pointer: Some(reg("x29")),
            stack_growth: StackGrowth::Down,
            stack_align: 16,
            callee_cleanup: false,
            variadic: true,
            shadow_space: 0,
        }
    }

    /// ARM 32-bit AAPCS.
    #[must_use]
    pub fn aapcs32() -> Self {
        let reg = |n: &str| Register::new(n, 32);
        let freg = |n: &str| Register::float(n, 64);
        Self {
            name: "ARM Procedure Call Standard (32-bit)".to_string(),
            id: "aapcs32".to_string(),
            int_arg_regs: vec![reg("r0"), reg("r1"), reg("r2"), reg("r3")],
            float_arg_regs: vec![
                freg("d0"),
                freg("d1"),
                freg("d2"),
                freg("d3"),
                freg("d4"),
                freg("d5"),
                freg("d6"),
                freg("d7"),
            ],
            return_reg: reg("r0"),
            return_reg_high: Some(reg("r1")),
            callee_saved: vec![
                reg("r4"),
                reg("r5"),
                reg("r6"),
                reg("r7"),
                reg("r8"),
                reg("r9"),
                reg("r10"),
                reg("r11"),
            ],
            caller_saved: vec![reg("r0"), reg("r1"), reg("r2"), reg("r3"), reg("r12")],
            stack_pointer: reg("sp"),
            frame_pointer: Some(reg("r11")),
            stack_growth: StackGrowth::Down,
            stack_align: 8,
            callee_cleanup: false,
            variadic: true,
            shadow_space: 0,
        }
    }
}

// ─── Platform ─────────────────────────────────────────────────────────────────

/// Describes a complete target platform.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Unique identifier (e.g. "linux-x86-64").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Architecture name (e.g. "`x86_64`", "aarch64", "arm").
    pub arch: String,
    /// Operating system name (e.g. "linux", "windows", "macos", "bare").
    pub os: String,
    /// Pointer size in bytes.
    pub pointer_size: usize,
    /// Default calling convention.
    pub default_calling_convention: CallingConventionDef,
    /// All calling conventions supported by this platform.
    pub calling_conventions: Vec<CallingConventionDef>,
    /// Endianness.
    pub endian: Endian,
    /// True if the platform uses position-independent code by default.
    pub pic_default: bool,
    /// Platform-specific properties.
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Platform {
    /// Linux x86-64.
    #[must_use]
    pub fn linux_x86_64() -> Self {
        let cc = CallingConventionDef::sysv_amd64();
        Self {
            id: "linux-x86-64".to_string(),
            name: "Linux x86-64".to_string(),
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            pointer_size: 8,
            calling_conventions: vec![cc.clone()],
            default_calling_convention: cc,
            endian: Endian::Little,
            pic_default: true,
            properties: HashMap::new(),
        }
    }

    /// Windows x86-64.
    #[must_use]
    pub fn windows_x86_64() -> Self {
        let cc = CallingConventionDef::win64();
        Self {
            id: "windows-x86-64".to_string(),
            name: "Windows x86-64".to_string(),
            arch: "x86_64".to_string(),
            os: "windows".to_string(),
            pointer_size: 8,
            calling_conventions: vec![cc.clone()],
            default_calling_convention: cc,
            endian: Endian::Little,
            pic_default: false,
            properties: HashMap::new(),
        }
    }

    /// macOS arm64 (Apple Silicon).
    #[must_use]
    pub fn macos_arm64() -> Self {
        let cc = CallingConventionDef::aapcs64();
        Self {
            id: "macos-arm64".to_string(),
            name: "macOS ARM64 (Apple Silicon)".to_string(),
            arch: "aarch64".to_string(),
            os: "macos".to_string(),
            pointer_size: 8,
            calling_conventions: vec![cc.clone()],
            default_calling_convention: cc,
            endian: Endian::Little,
            pic_default: true,
            properties: HashMap::new(),
        }
    }

    /// Linux ARM (32-bit).
    #[must_use]
    pub fn linux_arm() -> Self {
        let cc = CallingConventionDef::aapcs32();
        Self {
            id: "linux-arm".to_string(),
            name: "Linux ARM (32-bit)".to_string(),
            arch: "arm".to_string(),
            os: "linux".to_string(),
            pointer_size: 4,
            calling_conventions: vec![cc.clone()],
            default_calling_convention: cc,
            endian: Endian::Little,
            pic_default: false,
            properties: HashMap::new(),
        }
    }

    /// Look up a calling convention by its short ID.
    #[must_use]
    pub fn calling_convention(&self, id: &str) -> Option<&CallingConventionDef> {
        self.calling_conventions.iter().find(|c| c.id == id)
    }

    /// Number of bits in a pointer.
    #[must_use]
    pub const fn pointer_bits(&self) -> usize {
        self.pointer_size * 8
    }
}

// ─── PlatformProviderPlugin Trait ────────────────────────────────────────────

pub trait PlatformProviderPlugin: Plugin {
    /// Return the platforms this plugin provides.
    fn platforms(&self) -> Vec<Platform>;

    /// Look up a platform by ID.
    fn get_platform(&self, id: &str) -> Option<Platform>;

    /// True if this provider supports the given platform ID.
    fn supports(&self, id: &str) -> bool {
        self.get_platform(id).is_some()
    }

    /// List all platform IDs.
    fn platform_ids(&self) -> Vec<String> {
        self.platforms().into_iter().map(|p| p.id).collect()
    }
}

// ─── Platform Registry ───────────────────────────────────────────────────────

/// Global registry of all known platforms.
#[derive(Default)]
pub struct PlatformRegistry {
    platforms: HashMap<String, Platform>,
}

impl PlatformRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-loaded with all built-in platforms.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Platform::linux_x86_64());
        r.register(Platform::windows_x86_64());
        r.register(Platform::macos_arm64());
        r.register(Platform::linux_arm());
        r
    }

    pub fn register(&mut self, platform: Platform) {
        self.platforms.insert(platform.id.clone(), platform);
    }

    pub fn unregister(&mut self, id: &str) {
        self.platforms.remove(id);
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Platform> {
        self.platforms.get(id)
    }

    #[must_use]
    pub fn list_ids(&self) -> Vec<&str> {
        self.platforms
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.platforms.len()
    }

    /// Find all platforms matching an architecture name.
    #[must_use]
    pub fn for_arch(&self, arch: &str) -> Vec<&Platform> {
        self.platforms.values().filter(|p| p.arch == arch).collect()
    }

    /// Find all platforms matching an OS name.
    #[must_use]
    pub fn for_os(&self, os: &str) -> Vec<&Platform> {
        self.platforms.values().filter(|p| p.os == os).collect()
    }

    /// Find platforms with a specific pointer size.
    #[must_use]
    pub fn for_pointer_size(&self, bytes: usize) -> Vec<&Platform> {
        self.platforms
            .values()
            .filter(|p| p.pointer_size == bytes)
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Register ─────────────────────────────────────────────────────────

    #[test]
    fn test_register_new() {
        let r = Register::new("rax", 64);
        assert_eq!(r.name, "rax");
        assert_eq!(r.width, 64);
        assert!(!r.is_float);
    }

    #[test]
    fn test_register_float() {
        let r = Register::float("xmm0", 128);
        assert!(r.is_float);
        assert_eq!(r.width, 128);
    }

    // ── CallingConventionDef ──────────────────────────────────────────────

    #[test]
    fn test_sysv_amd64() {
        let cc = CallingConventionDef::sysv_amd64();
        assert_eq!(cc.id, "sysv64");
        assert_eq!(cc.int_arg_regs.len(), 6);
        assert_eq!(cc.float_arg_regs.len(), 8);
        assert_eq!(cc.return_reg.name, "rax");
        assert!(!cc.callee_cleanup);
        assert!(cc.variadic);
        assert_eq!(cc.shadow_space, 0);
        assert_eq!(cc.stack_align, 16);
    }

    #[test]
    fn test_win64() {
        let cc = CallingConventionDef::win64();
        assert_eq!(cc.id, "win64");
        assert_eq!(cc.int_arg_regs.len(), 4);
        assert_eq!(cc.int_arg_regs[0].name, "rcx");
        assert_eq!(cc.shadow_space, 32);
    }

    #[test]
    fn test_aapcs64() {
        let cc = CallingConventionDef::aapcs64();
        assert_eq!(cc.id, "aapcs64");
        assert_eq!(cc.int_arg_regs.len(), 8);
        assert_eq!(cc.int_arg_regs[0].name, "x0");
        assert_eq!(cc.stack_pointer.name, "sp");
    }

    #[test]
    fn test_aapcs32() {
        let cc = CallingConventionDef::aapcs32();
        assert_eq!(cc.id, "aapcs32");
        assert_eq!(cc.int_arg_regs.len(), 4);
        assert_eq!(cc.int_arg_regs[0].name, "r0");
        assert_eq!(cc.stack_align, 8);
    }

    #[test]
    fn test_calling_convention_callee_saved() {
        let cc = CallingConventionDef::sysv_amd64();
        let saved_names: Vec<&str> = cc.callee_saved.iter().map(|r| r.name.as_str()).collect();
        assert!(saved_names.contains(&"rbx"));
        assert!(saved_names.contains(&"r15"));
    }

    // ── Platform ─────────────────────────────────────────────────────────

    #[test]
    fn test_linux_x86_64() {
        let p = Platform::linux_x86_64();
        assert_eq!(p.id, "linux-x86-64");
        assert_eq!(p.arch, "x86_64");
        assert_eq!(p.os, "linux");
        assert_eq!(p.pointer_size, 8);
        assert_eq!(p.pointer_bits(), 64);
        assert!(p.pic_default);
        assert_eq!(p.endian, Endian::Little);
    }

    #[test]
    fn test_windows_x86_64() {
        let p = Platform::windows_x86_64();
        assert_eq!(p.id, "windows-x86-64");
        assert_eq!(p.os, "windows");
        assert!(!p.pic_default);
    }

    #[test]
    fn test_macos_arm64() {
        let p = Platform::macos_arm64();
        assert_eq!(p.id, "macos-arm64");
        assert_eq!(p.arch, "aarch64");
        assert_eq!(p.os, "macos");
        assert_eq!(p.pointer_size, 8);
    }

    #[test]
    fn test_linux_arm() {
        let p = Platform::linux_arm();
        assert_eq!(p.id, "linux-arm");
        assert_eq!(p.arch, "arm");
        assert_eq!(p.pointer_size, 4);
        assert_eq!(p.pointer_bits(), 32);
    }

    #[test]
    fn test_platform_calling_convention_lookup() {
        let p = Platform::linux_x86_64();
        assert!(p.calling_convention("sysv64").is_some());
        assert!(p.calling_convention("win64").is_none());
    }

    #[test]
    fn test_platform_default_cc_id() {
        let p = Platform::windows_x86_64();
        assert_eq!(p.default_calling_convention.id, "win64");
    }

    // ── PlatformRegistry ─────────────────────────────────────────────────

    #[test]
    fn test_registry_with_builtins() {
        let reg = PlatformRegistry::with_builtins();
        assert_eq!(reg.count(), 4);
        assert!(reg.get("linux-x86-64").is_some());
        assert!(reg.get("windows-x86-64").is_some());
        assert!(reg.get("macos-arm64").is_some());
        assert!(reg.get("linux-arm").is_some());
    }

    #[test]
    fn test_registry_register_custom() {
        let mut reg = PlatformRegistry::new();
        let mut p = Platform::linux_x86_64();
        p.id = "custom-platform".to_string();
        reg.register(p);
        assert!(reg.get("custom-platform").is_some());
    }

    #[test]
    fn test_registry_unregister() {
        let mut reg = PlatformRegistry::with_builtins();
        reg.unregister("linux-arm");
        assert!(reg.get("linux-arm").is_none());
        assert_eq!(reg.count(), 3);
    }

    #[test]
    fn test_registry_for_arch() {
        let reg = PlatformRegistry::with_builtins();
        let x64 = reg.for_arch("x86_64");
        assert_eq!(x64.len(), 2); // linux and windows
    }

    #[test]
    fn test_registry_for_os() {
        let reg = PlatformRegistry::with_builtins();
        let linux = reg.for_os("linux");
        assert_eq!(linux.len(), 2); // x86-64 and arm
    }

    #[test]
    fn test_registry_for_pointer_size() {
        let reg = PlatformRegistry::with_builtins();
        let p64 = reg.for_pointer_size(8);
        assert_eq!(p64.len(), 3); // linux-x64, windows-x64, macos-arm64
        let p32 = reg.for_pointer_size(4);
        assert_eq!(p32.len(), 1); // linux-arm
    }

    #[test]
    fn test_registry_list_ids() {
        let reg = PlatformRegistry::with_builtins();
        let ids = reg.list_ids();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn test_registry_empty_new() {
        let reg = PlatformRegistry::new();
        assert_eq!(reg.count(), 0);
        assert!(reg.get("linux-x86-64").is_none());
    }

    // ── Endian / misc ────────────────────────────────────────────────────

    #[test]
    fn test_endian_all_little() {
        let platforms = [
            Platform::linux_x86_64(),
            Platform::windows_x86_64(),
            Platform::macos_arm64(),
            Platform::linux_arm(),
        ];
        for p in &platforms {
            assert_eq!(p.endian, Endian::Little, "{} should be little-endian", p.id);
        }
    }

    #[test]
    fn test_platform_properties_empty_by_default() {
        let p = Platform::linux_x86_64();
        assert!(p.properties.is_empty());
    }

    #[test]
    fn test_platform_properties_custom() {
        let mut p = Platform::linux_x86_64();
        p.properties
            .insert("kernel_version".to_string(), "5.15".to_string());
        assert_eq!(
            p.properties.get("kernel_version"),
            Some(&"5.15".to_string())
        );
    }
}
