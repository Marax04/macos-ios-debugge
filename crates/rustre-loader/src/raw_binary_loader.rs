// raw_binary_loader.rs — Raw binary loader for RustRE

// ─── ArchHint ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchHint {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Z80,
    Avr,
    Raw,
}

impl ArchHint {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "aarch64",
            Self::Mips => "mips",
            Self::Z80 => "z80",
            Self::Avr => "avr",
            Self::Raw => "raw",
        }
    }

    #[must_use] 
    pub const fn default_word_size(&self) -> u8 {
        match self {
            Self::X86_64 | Self::Arm64 => 8,
            Self::Z80 | Self::Avr => 2,
            Self::X86 | Self::Arm | Self::Mips | Self::Raw => 4,
        }
    }
}

// ─── LoadConfig ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoadConfig {
    pub base_addr: u64,
    pub arch: ArchHint,
    pub entry_point: Option<u64>,
    pub is_big_endian: bool,
    pub word_size: u8,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            base_addr: 0,
            arch: ArchHint::Raw,
            entry_point: None,
            is_big_endian: false,
            word_size: 4,
        }
    }
}

impl LoadConfig {
    #[must_use] 
    pub const fn x86(base: u64) -> Self {
        Self { base_addr: base, arch: ArchHint::X86, entry_point: None, is_big_endian: false, word_size: 4 }
    }

    #[must_use] 
    pub const fn x86_64(base: u64) -> Self {
        Self { base_addr: base, arch: ArchHint::X86_64, entry_point: None, is_big_endian: false, word_size: 8 }
    }
}

// ─── BinaryRegion ─────────────────────────────────────────────────────────────

/// Permissions flags.
pub const PERM_READ: u8    = 0b001;
pub const PERM_WRITE: u8   = 0b010;
pub const PERM_EXECUTE: u8 = 0b100;

#[derive(Debug, Clone)]
pub struct BinaryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: u8,
    pub name: String,
}

impl BinaryRegion {
    #[must_use] 
    pub fn new(start: u64, end: u64, perms: u8, name: &str) -> Self {
        Self { start, end, perms, name: name.to_string() }
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    #[must_use] 
    pub const fn is_executable(&self) -> bool { self.perms & PERM_EXECUTE != 0 }
    #[must_use] 
    pub const fn is_writable(&self) -> bool { self.perms & PERM_WRITE != 0 }
    #[must_use] 
    pub const fn is_readable(&self) -> bool { self.perms & PERM_READ != 0 }
}

// ─── LoadedBinary ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoadedBinary {
    pub data: Vec<u8>,
    pub base_addr: u64,
    pub entry_point: u64,
    pub arch: ArchHint,
    pub is_big_endian: bool,
    pub word_size: u8,
    pub regions: Vec<BinaryRegion>,
}

impl LoadedBinary {
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    #[must_use] 
    pub fn region_at(&self, addr: u64) -> Option<&BinaryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    #[must_use] 
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let offset = usize::try_from(addr.checked_sub(self.base_addr)?).ok()?;
        self.data.get(offset).copied()
    }

    #[must_use]
    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let offset = usize::try_from(addr.checked_sub(self.base_addr)?).ok()?;
        if offset + 2 > self.data.len() { return None; }
        let bytes = [self.data[offset], self.data[offset + 1]];
        if self.is_big_endian {
            Some(u16::from_be_bytes(bytes))
        } else {
            Some(u16::from_le_bytes(bytes))
        }
    }

    #[must_use]
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let offset = usize::try_from(addr.checked_sub(self.base_addr)?).ok()?;
        if offset + 4 > self.data.len() { return None; }
        let bytes = [self.data[offset], self.data[offset+1], self.data[offset+2], self.data[offset+3]];
        if self.is_big_endian {
            Some(u32::from_be_bytes(bytes))
        } else {
            Some(u32::from_le_bytes(bytes))
        }
    }

    #[must_use]
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let offset = usize::try_from(addr.checked_sub(self.base_addr)?).ok()?;
        if offset + 8 > self.data.len() { return None; }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[offset..offset + 8]);
        if self.is_big_endian {
            Some(u64::from_be_bytes(bytes))
        } else {
            Some(u64::from_le_bytes(bytes))
        }
    }
}

// ─── Arch detection heuristics ────────────────────────────────────────────────

/// Detect architecture from file magic bytes and patterns.
#[must_use] 
pub fn detect_arch_from_content(data: &[u8]) -> ArchHint {
    if data.len() < 4 { return ArchHint::Raw; }

    // Known format magics
    if data[0] == 0x4D && data[1] == 0x5A { // MZ
        if data.len() > 0x40 {
            let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
            if e_lfanew + 6 < data.len() && data[e_lfanew] == 0x50 && data[e_lfanew+1] == 0x45 {
                let machine = u16::from_le_bytes([data[e_lfanew+4], data[e_lfanew+5]]);
                return match machine {
                    0x8664 => ArchHint::X86_64,
                    0x01C0 | 0x01C2 => ArchHint::Arm,
                    0xAA64 => ArchHint::Arm64,
                    0x0166 => ArchHint::Mips,
                    _ => ArchHint::X86,
                };
            }
        }
        return ArchHint::X86;
    }

    if data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        if data.len() > 18 {
            let machine = u16::from_le_bytes([data[18], data[19]]);
            return match machine {
                3 => ArchHint::X86,
                62 => ArchHint::X86_64,
                40 => ArchHint::Arm,
                183 => ArchHint::Arm64,
                8 | 10 => ArchHint::Mips,
                _ => ArchHint::Raw,
            };
        }
        return ArchHint::Raw;
    }

    // Mach-O
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xFEED_FACE || magic == 0xCEFA_EDFE {
            return ArchHint::X86;
        }
        if magic == 0xFEED_FACF || magic == 0xCFFA_EDFE {
            return ArchHint::X86_64;
        }
    }

    // Heuristic: look for x86 prologue patterns
    let ebp_frame_count = count_pattern(data, &[0x55, 0x8B, 0xEC]);
    let rbp_frame_count = count_pattern(data, &[0x55, 0x48, 0x89, 0xE5]);
    let arm_bl_count = count_arm_bl_patterns(data);

    if rbp_frame_count > 2 {
        return ArchHint::X86_64;
    }
    if ebp_frame_count > 2 {
        return ArchHint::X86;
    }
    if arm_bl_count > 3 {
        return ArchHint::Arm;
    }

    ArchHint::Raw
}

fn count_pattern(data: &[u8], pattern: &[u8]) -> usize {
    data.windows(pattern.len()).filter(|w| *w == pattern).count()
}

fn count_arm_bl_patterns(data: &[u8]) -> usize {
    // ARM32 BL: top byte has bits 31:28 = 1110 and bits 27:25 = 101
    // 0xEB xx xx xx = BL in ARM LE
    data.chunks(4).filter(|chunk| {
        chunk.len() == 4 && (chunk[3] == 0xEB || chunk[3] == 0xEA || chunk[3] == 0xE0)
    }).count()
}

// ─── Base address auto-detection ─────────────────────────────────────────────

/// Heuristically find the lowest referenced address for potential base.
#[must_use] 
pub fn auto_detect_base(data: &[u8], word_size: u8) -> u64 {
    // Look for pointers that appear like code/data addresses
    let mut candidates: Vec<u64> = Vec::new();
    if word_size == 4 {
        for i in (0..data.len().saturating_sub(3)).step_by(4) {
            let v = u64::from(u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]));
            // Common load bases: 0x400000, 0x10000, 0x8000_0000, etc.
            if v.trailing_zeros() >= 16 && (0x1000..=0xFFFF_0000).contains(&v) {
                candidates.push(v);
            }
        }
    } else {
        for i in (0..data.len().saturating_sub(7)).step_by(8) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[i..i+8]);
            let v = u64::from_le_bytes(bytes);
            if v.trailing_zeros() >= 12 && (0x0040_0000..=0xFFFF_FFFF_0000).contains(&v) {
                candidates.push(v);
            }
        }
    }
    if candidates.is_empty() {
        return 0;
    }
    candidates.sort_unstable();
    candidates[0]
}

// ─── Instruction density heuristic ───────────────────────────────────────────

/// Estimate instruction density of a block: number of valid x86 1-byte opcodes.
fn instruction_density(block: &[u8]) -> f64 {
    let valid_single_byte: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, // push regs
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, // pop regs
        0x90, 0xC3, 0xC9, 0xCC, 0xCB,                   // nop, ret, leave, int3
    ];
    let count = block.iter().filter(|b| valid_single_byte.contains(b)).count();
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(block.len().max(1)).unwrap_or(u32::MAX))
}

// ─── split_into_sections ─────────────────────────────────────────────────────

#[must_use] 
pub fn split_into_sections(data: &[u8], base: u64) -> Vec<BinaryRegion> {
    if data.is_empty() {
        return vec![];
    }
    let block_size = 4096usize;
    let mut regions = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let end = (i + block_size).min(data.len());
        let block = &data[i..end];
        let density = instruction_density(block);
        let (perms, name) = if density > 0.04 {
            (PERM_READ | PERM_EXECUTE, "code")
        } else {
            (PERM_READ, "data")
        };
        let start_addr = base + i as u64;
        let end_addr = base + end as u64;
        // Merge with previous region if same type
        if let Some(last) = regions.last_mut() as Option<&mut BinaryRegion>
            && last.perms == perms && last.end == start_addr {
                last.end = end_addr;
                i += block_size;
                continue;
            }
        regions.push(BinaryRegion::new(start_addr, end_addr, perms, name));
        i += block_size;
    }
    regions
}

// ─── RawBinaryLoader ─────────────────────────────────────────────────────────

pub struct RawBinaryLoader;

impl RawBinaryLoader {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Load raw binary data with configuration.
    #[must_use] 
    pub fn load(&self, data: &[u8], config: &LoadConfig) -> LoadedBinary {
        let arch = if config.arch == ArchHint::Raw {
            detect_arch_from_content(data)
        } else {
            config.arch.clone()
        };
        let word_size = if config.word_size == 0 { arch.default_word_size() } else { config.word_size };
        let base = if config.base_addr == 0 {
            auto_detect_base(data, word_size)
        } else {
            config.base_addr
        };
        let entry = config.entry_point.unwrap_or(base);
        let regions = split_into_sections(data, base);
        LoadedBinary {
            data: data.to_vec(),
            base_addr: base,
            entry_point: entry,
            arch,
            is_big_endian: config.is_big_endian,
            word_size,
            regions,
        }
    }

    /// Load from a file path (reads bytes, then calls load).
    #[must_use] 
    pub fn load_bytes(&self, data: &[u8]) -> LoadedBinary {
        self.load(data, &LoadConfig::default())
    }
}

impl Default for RawBinaryLoader {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loader() -> RawBinaryLoader { RawBinaryLoader::new() }

    fn make_elf_x86_64() -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0] = 0x7F; d[1] = b'E'; d[2] = b'L'; d[3] = b'F';
        // e_machine at offset 18: EM_X86_64 = 62
        d[18] = 62; d[19] = 0;
        d
    }

    fn make_mz_x86() -> Vec<u8> {
        let mut d = vec![0u8; 256];
        d[0] = 0x4D; d[1] = 0x5A;
        d[0x3C] = 0x40;
        d[0x40] = 0x50; d[0x41] = 0x45;
        // machine = 0x014C (x86)
        d[0x44] = 0x4C; d[0x45] = 0x01;
        d
    }

    #[test]
    fn test_detect_arch_elf_x86_64() {
        let data = make_elf_x86_64();
        assert_eq!(detect_arch_from_content(&data), ArchHint::X86_64);
    }

    #[test]
    fn test_detect_arch_mz_x86() {
        let data = make_mz_x86();
        assert_eq!(detect_arch_from_content(&data), ArchHint::X86);
    }

    #[test]
    fn test_detect_arch_raw_empty() {
        assert_eq!(detect_arch_from_content(&[]), ArchHint::Raw);
    }

    #[test]
    fn test_detect_arch_x86_heuristic() {
        // Many push ebp / mov ebp,esp patterns
        let mut data = vec![0u8; 256];
        for i in 0..8 {
            data[i * 16] = 0x55;
            data[i * 16 + 1] = 0x8B;
            data[i * 16 + 2] = 0xEC;
        }
        let arch = detect_arch_from_content(&data);
        assert_eq!(arch, ArchHint::X86);
    }

    #[test]
    fn test_load_basic() {
        let data = vec![0x90u8; 64]; // NOPs
        let config = LoadConfig::x86(0x0040_0000);
        let loaded = loader().load(&data, &config);
        assert_eq!(loaded.base_addr, 0x0040_0000);
        assert_eq!(loaded.data.len(), 64);
    }

    #[test]
    fn test_load_entry_point_set() {
        let data = vec![0u8; 64];
        let config = LoadConfig { base_addr: 0x1000, entry_point: Some(0x1010), arch: ArchHint::X86, is_big_endian: false, word_size: 4 };
        let loaded = loader().load(&data, &config);
        assert_eq!(loaded.entry_point, 0x1010);
    }

    #[test]
    fn test_split_into_sections_nonempty() {
        let data = vec![0x55u8; 8192];
        let regions = split_into_sections(&data, 0x0040_0000);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_binary_region_contains() {
        let r = BinaryRegion::new(0x1000, 0x2000, PERM_READ | PERM_EXECUTE, "code");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_read_u8() {
        let data = vec![0xABu8, 0xCD];
        let loaded = loader().load(&data, &LoadConfig { base_addr: 0x100, ..Default::default() });
        assert_eq!(loaded.read_u8(0x100), Some(0xAB));
        assert_eq!(loaded.read_u8(0x101), Some(0xCD));
    }

    #[test]
    fn test_read_u32_le() {
        let data = vec![0x78u8, 0x56, 0x34, 0x12];
        let config = LoadConfig { base_addr: 0, is_big_endian: false, ..Default::default() };
        let loaded = loader().load(&data, &config);
        assert_eq!(loaded.read_u32(0), Some(0x1234_5678));
    }

    #[test]
    fn test_read_u32_be() {
        let data = vec![0x12u8, 0x34, 0x56, 0x78];
        let config = LoadConfig { base_addr: 0, is_big_endian: true, ..Default::default() };
        let loaded = loader().load(&data, &config);
        assert_eq!(loaded.read_u32(0), Some(0x1234_5678));
    }

    #[test]
    fn test_region_at_finds_correct() {
        let data = vec![0u8; 8192];
        let loaded = loader().load(&data, &LoadConfig { base_addr: 0x1000, ..Default::default() });
        let r = loaded.region_at(0x1000);
        assert!(r.is_some());
    }

    #[test]
    fn test_auto_detect_base_finds_aligned() {
        let mut data = vec![0u8; 64];
        // Write 0x00400000 at offset 0
        data[0] = 0x00; data[1] = 0x00; data[2] = 0x40; data[3] = 0x00;
        let base = auto_detect_base(&data, 4);
        assert_eq!(base, 0x0040_0000);
    }

    #[test]
    fn test_arch_hint_word_size() {
        assert_eq!(ArchHint::X86.default_word_size(), 4);
        assert_eq!(ArchHint::X86_64.default_word_size(), 8);
        assert_eq!(ArchHint::Z80.default_word_size(), 2);
    }

    #[test]
    fn test_perm_flags() {
        let r = BinaryRegion::new(0, 0x100, PERM_READ | PERM_EXECUTE, "text");
        assert!(r.is_executable());
        assert!(!r.is_writable());
    }

    #[test]
    fn test_load_bytes_default_config() {
        let data = vec![0u8; 16];
        let loaded = loader().load_bytes(&data);
        assert_eq!(loaded.data.len(), 16);
    }
}
