//! `register_alias_map` — Register alias mapping for x86-64 and ARM.
//!
//! Tracks sub-register relationships (e.g. `rax` ⊇ `eax` ⊇ `ax` ⊇ `al`/`ah`),
//! SIMD register containment (`ymm0` ⊇ `xmm0`), and ARM register aliases.
//! Provides liveness propagation across register aliases.

use std::collections::HashMap;
use std::fmt;

// ─── RegisterWidth ────────────────────────────────────────────────────────────

/// Bit-width of a register or register alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegisterWidth {
    /// 8-bit (byte) register.
    Bits8,
    /// 16-bit (word) register.
    Bits16,
    /// 32-bit (doubleword) register.
    Bits32,
    /// 64-bit (quadword) register.
    Bits64,
    /// 128-bit (XMM/Q) register.
    Bits128,
    /// 256-bit (YMM) register.
    Bits256,
    /// 512-bit (ZMM) register.
    Bits512,
    /// Unknown / variable.
    Unknown,
}

impl RegisterWidth {
    /// Return the number of bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bits8 => 1,
            Self::Bits16 => 2,
            Self::Bits32 => 4,
            Self::Bits64 => 8,
            Self::Bits128 => 16,
            Self::Bits256 => 32,
            Self::Bits512 => 64,
            Self::Unknown => 0,
        }
    }

    /// Return the number of bits.
    #[must_use]
    pub const fn bits(self) -> usize {
        self.bytes() * 8
    }
}

impl fmt::Display for RegisterWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}b", self.bits())
    }
}

// ─── RegisterAlias ────────────────────────────────────────────────────────────

/// One alias entry: a register name together with its bit-width and byte offset
/// within the canonical (widest) register.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterAlias {
    /// Name of this alias (e.g. `"eax"`, `"al"`, `"xmm0"`).
    pub name: String,
    /// Bit-width of this alias.
    pub width: RegisterWidth,
    /// Byte offset within the canonical register where this alias starts.
    pub byte_offset: usize,
}

impl RegisterAlias {
    /// Create a new alias.
    #[must_use]
    pub fn new(name: impl Into<String>, width: RegisterWidth, byte_offset: usize) -> Self {
        Self {
            name: name.into(),
            width,
            byte_offset,
        }
    }

    /// Return `true` if `other` is contained within (a sub-alias of) `self`.
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        let self_end = self.byte_offset + self.width.bytes();
        let other_end = other.byte_offset + other.width.bytes();
        other.byte_offset >= self.byte_offset && other_end <= self_end
    }

    /// Return `true` if `other` overlaps with `self`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let self_end = self.byte_offset + self.width.bytes();
        let other_end = other.byte_offset + other.width.bytes();
        self.byte_offset < other_end && other.byte_offset < self_end
    }
}

impl fmt::Display for RegisterAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}@+{})", self.name, self.width, self.byte_offset)
    }
}

// ─── AliasGroup ───────────────────────────────────────────────────────────────

/// A group of registers that all alias the same physical storage.
///
/// The canonical register is the widest member (index 0 by convention).
#[derive(Debug, Clone)]
pub struct AliasGroup {
    /// The canonical (widest) register name.
    pub canonical: String,
    /// All aliases (including the canonical register itself).
    pub aliases: Vec<RegisterAlias>,
    /// Processor family tag (e.g. `"x86"`, `"arm"`).
    pub family: String,
}

impl AliasGroup {
    /// Create a new group with the given canonical register.
    #[must_use]
    pub fn new(canonical: impl Into<String>, family: impl Into<String>) -> Self {
        Self {
            canonical: canonical.into(),
            aliases: Vec::new(),
            family: family.into(),
        }
    }

    /// Add an alias to this group.
    pub fn add(&mut self, alias: RegisterAlias) {
        self.aliases.push(alias);
    }

    /// Return the canonical alias (widest register).
    #[must_use]
    pub fn canonical_alias(&self) -> Option<&RegisterAlias> {
        self.aliases.iter().find(|a| a.name == self.canonical)
    }

    /// Return all alias names.
    #[must_use]
    pub fn alias_names(&self) -> Vec<&str> {
        self.aliases.iter().map(|a| a.name.as_str()).collect()
    }

    /// Return `true` if `name` is a member of this group.
    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        self.aliases.iter().any(|a| a.name == name)
    }

    /// Return all aliases that overlap with `alias`.
    #[must_use]
    pub fn overlapping(&self, alias: &RegisterAlias) -> Vec<&RegisterAlias> {
        self.aliases
            .iter()
            .filter(|a| a.name != alias.name && a.overlaps(alias))
            .collect()
    }
}

// ─── LivenessEffect ───────────────────────────────────────────────────────────

/// Effect of writing a register on the liveness of its aliases.
#[derive(Debug, Clone)]
pub struct LivenessEffect {
    /// The register that was written.
    pub written_reg: String,
    /// Registers that are now fully defined (zero-extended or same width).
    pub defined: Vec<String>,
    /// Registers that are now partially defined (overlapping).
    pub partial: Vec<String>,
    /// Registers that are now undefined/invalid (wider registers containing
    /// the written sub-register, whose upper bits are now unknown).
    pub clobbered_partial: Vec<String>,
}

impl LivenessEffect {
    /// Return `true` if any registers were defined or clobbered.
    #[must_use]
    pub const fn has_effects(&self) -> bool {
        !self.defined.is_empty()
            || !self.partial.is_empty()
            || !self.clobbered_partial.is_empty()
    }
}

// ─── AliasMap ─────────────────────────────────────────────────────────────────

/// Complete register alias database.
#[derive(Debug, Default)]
pub struct AliasMap {
    /// All alias groups, indexed by canonical name.
    groups: HashMap<String, AliasGroup>,
    /// Reverse index: register name → canonical name.
    reverse: HashMap<String, String>,
}

impl AliasMap {
    /// Create an empty alias map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an alias map pre-populated with x86-64 and ARM registers.
    #[must_use]
    pub fn builtin() -> Self {
        let mut m = Self::new();
        m.add_x86_64_aliases();
        m.add_simd_aliases();
        m.add_arm32_aliases();
        m.add_arm64_aliases();
        m
    }

    /// Register an alias group.
    pub fn add_group(&mut self, group: AliasGroup) {
        for alias in &group.aliases {
            // Do not clobber an existing canonical mapping: the first family
            // that registers a name (e.g. ARM `d0` containing s0+s1) wins over
            // a later family that lists the same name as part of a wider
            // grouping (e.g. ARM64 `v0` containing d0,s0).
            self.reverse
                .entry(alias.name.clone())
                .or_insert_with(|| group.canonical.clone());
        }
        self.groups
            .entry(group.canonical.clone())
            .or_insert(group);
    }

    /// Look up the alias group for a register name.
    #[must_use]
    pub fn group_for(&self, reg: &str) -> Option<&AliasGroup> {
        let canonical = self.reverse.get(reg)?;
        self.groups.get(canonical)
    }

    /// Look up the canonical name for a register.
    #[must_use]
    pub fn canonical(&self, reg: &str) -> Option<&str> {
        self.reverse.get(reg).map(String::as_str)
    }

    /// Return all register names that alias `reg` (including itself).
    #[must_use]
    pub fn all_aliases(&self, reg: &str) -> Vec<String> {
        self.group_for(reg)
            .map(|g| g.alias_names().into_iter().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// Return all registers that writing `reg` will affect (overlapping aliases).
    #[must_use]
    pub fn affected_by_write(&self, reg: &str) -> Vec<String> {
        let Some(group) = self.group_for(reg) else { return vec![reg.to_string()]; };
        let Some(alias) = group.aliases.iter().find(|a| a.name == reg) else { return vec![reg.to_string()]; };
        group
            .overlapping(alias)
            .into_iter()
            .map(|a| a.name.clone())
            .collect()
    }

    /// Compute the liveness effect of writing `reg`.
    ///
    /// On x86-64, writing a 32-bit register zero-extends to 64 bits.
    #[must_use]
    pub fn liveness_effect(&self, reg: &str) -> LivenessEffect {
        let Some(group) = self.group_for(reg) else {
            return LivenessEffect {
                written_reg: reg.to_string(),
                defined: vec![reg.to_string()],
                partial: Vec::new(),
                clobbered_partial: Vec::new(),
            };
        };

        let Some(alias_ref) = group.aliases.iter().find(|a| a.name == reg) else {
            return LivenessEffect {
                written_reg: reg.to_string(),
                defined: vec![reg.to_string()],
                partial: Vec::new(),
                clobbered_partial: Vec::new(),
            };
        };
        let alias = alias_ref.clone();

        let mut defined = vec![reg.to_string()];
        let mut partial = Vec::new();
        let mut clobbered_partial = Vec::new();

        for a in &group.aliases {
            if a.name == reg {
                continue;
            }
            if alias.contains(a) {
                // Writing a wider register also defines all narrower sub-registers.
                defined.push(a.name.clone());
            } else if a.contains(&alias) {
                // Writing a sub-register partially defines the wider register.
                // On x86-64, writing a 32-bit alias zero-extends to 64.
                if group.family == "x86"
                    && alias.width == RegisterWidth::Bits32
                    && a.width == RegisterWidth::Bits64
                {
                    defined.push(a.name.clone());
                } else {
                    clobbered_partial.push(a.name.clone());
                }
            } else if alias.overlaps(a) {
                partial.push(a.name.clone());
            }
        }

        LivenessEffect {
            written_reg: reg.to_string(),
            defined,
            partial,
            clobbered_partial,
        }
    }

    /// Return the number of alias groups registered.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Return the total number of register names (across all groups).
    #[must_use]
    pub fn total_names(&self) -> usize {
        self.reverse.len()
    }

    // ── x86-64 GPRs ───────────────────────────────────────────────────────────

    fn add_x86_64_aliases(&mut self) {
        // rax / eax / ax / al / ah
        let gpr64 = [
            ("rax", "eax", "ax", "al", "ah"),
            ("rbx", "ebx", "bx", "bl", "bh"),
            ("rcx", "ecx", "cx", "cl", "ch"),
            ("rdx", "edx", "dx", "dl", "dh"),
        ];
        for (r64, r32, r16, r8l, r8h) in &gpr64 {
            let mut g = AliasGroup::new(*r64, "x86");
            g.add(RegisterAlias::new(*r64, RegisterWidth::Bits64, 0));
            g.add(RegisterAlias::new(*r32, RegisterWidth::Bits32, 0));
            g.add(RegisterAlias::new(*r16, RegisterWidth::Bits16, 0));
            g.add(RegisterAlias::new(*r8l, RegisterWidth::Bits8, 0));
            g.add(RegisterAlias::new(*r8h, RegisterWidth::Bits8, 1));
            self.add_group(g);
        }

        // rsi, rdi, rbp, rsp — no high-byte alias
        let simple = [
            ("rsi", "esi", "si", "sil"),
            ("rdi", "edi", "di", "dil"),
            ("rbp", "ebp", "bp", "bpl"),
            ("rsp", "esp", "sp", "spl"),
        ];
        for (r64, r32, r16, r8) in &simple {
            let mut g = AliasGroup::new(*r64, "x86");
            g.add(RegisterAlias::new(*r64, RegisterWidth::Bits64, 0));
            g.add(RegisterAlias::new(*r32, RegisterWidth::Bits32, 0));
            g.add(RegisterAlias::new(*r16, RegisterWidth::Bits16, 0));
            g.add(RegisterAlias::new(*r8, RegisterWidth::Bits8, 0));
            self.add_group(g);
        }

        // r8..r15
        for n in 8u8..=15 {
            let mut g = AliasGroup::new(format!("r{n}"), "x86");
            g.add(RegisterAlias::new(
                format!("r{n}"),
                RegisterWidth::Bits64,
                0,
            ));
            g.add(RegisterAlias::new(
                format!("r{n}d"),
                RegisterWidth::Bits32,
                0,
            ));
            g.add(RegisterAlias::new(
                format!("r{n}w"),
                RegisterWidth::Bits16,
                0,
            ));
            g.add(RegisterAlias::new(
                format!("r{n}b"),
                RegisterWidth::Bits8,
                0,
            ));
            self.add_group(g);
        }
    }

    // ── SIMD (XMM / YMM / ZMM) ───────────────────────────────────────────────

    fn add_simd_aliases(&mut self) {
        for n in 0u8..=31 {
            let zmm = format!("zmm{n}");
            let ymm = format!("ymm{n}");
            let xmm = format!("xmm{n}");
            let mut g = AliasGroup::new(zmm.clone(), "x86");
            g.add(RegisterAlias::new(&zmm, RegisterWidth::Bits512, 0));
            g.add(RegisterAlias::new(&ymm, RegisterWidth::Bits256, 0));
            g.add(RegisterAlias::new(&xmm, RegisterWidth::Bits128, 0));
            self.add_group(g);
        }
    }

    // ── ARM 32-bit aliases ────────────────────────────────────────────────────

    fn add_arm32_aliases(&mut self) {
        // r0..r15 with well-known aliases.
        let named = [
            (13u8, "sp"),
            (14, "lr"),
            (15, "pc"),
            (11, "fp"),
            (12, "ip"),
        ];
        let named_map: HashMap<u8, &str> = named.iter().copied().collect();

        for n in 0u8..=15 {
            let canonical = format!("r{n}");
            let mut g = AliasGroup::new(canonical.clone(), "arm");
            g.add(RegisterAlias::new(&canonical, RegisterWidth::Bits32, 0));
            if let Some(&alias) = named_map.get(&n) {
                g.add(RegisterAlias::new(alias, RegisterWidth::Bits32, 0));
            }
            self.add_group(g);
        }

        // VFP / NEON: d0..d31 (64-bit) each containing s0,s1 (32-bit each).
        for n in 0u8..=31 {
            let dn = format!("d{n}");
            let mut g = AliasGroup::new(dn.clone(), "arm");
            g.add(RegisterAlias::new(&dn, RegisterWidth::Bits64, 0));
            // Each D register contains two S registers.
            let s_low = n * 2;
            let s_high = s_low + 1;
            g.add(RegisterAlias::new(
                format!("s{s_low}"),
                RegisterWidth::Bits32,
                0,
            ));
            g.add(RegisterAlias::new(
                format!("s{s_high}"),
                RegisterWidth::Bits32,
                4,
            ));
            self.add_group(g);
        }
    }

    // ── ARM 64-bit aliases ────────────────────────────────────────────────────

    fn add_arm64_aliases(&mut self) {
        // x0..x30 and sp.
        for n in 0u8..=30 {
            let xn = format!("x{n}");
            let wn = format!("w{n}");
            let mut g = AliasGroup::new(xn.clone(), "arm64");
            g.add(RegisterAlias::new(&xn, RegisterWidth::Bits64, 0));
            g.add(RegisterAlias::new(&wn, RegisterWidth::Bits32, 0));
            self.add_group(g);
        }
        // sp / wsp
        {
            let mut g = AliasGroup::new("sp", "arm64");
            g.add(RegisterAlias::new("sp", RegisterWidth::Bits64, 0));
            g.add(RegisterAlias::new("wsp", RegisterWidth::Bits32, 0));
            self.add_group(g);
        }

        // v0..v31: q (128), d (64), s (32), h (16), b (8).
        for n in 0u8..=31 {
            let vn = format!("v{n}");
            let mut g = AliasGroup::new(vn.clone(), "arm64");
            g.add(RegisterAlias::new(&vn, RegisterWidth::Bits128, 0));
            g.add(RegisterAlias::new(
                format!("q{n}"),
                RegisterWidth::Bits128,
                0,
            ));
            g.add(RegisterAlias::new(format!("d{n}"), RegisterWidth::Bits64, 0));
            g.add(RegisterAlias::new(format!("s{n}"), RegisterWidth::Bits32, 0));
            g.add(RegisterAlias::new(format!("h{n}"), RegisterWidth::Bits16, 0));
            g.add(RegisterAlias::new(format!("b{n}"), RegisterWidth::Bits8, 0));
            self.add_group(g);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map() -> AliasMap {
        AliasMap::builtin()
    }

    #[test]
    fn test_register_width_bytes() {
        assert_eq!(RegisterWidth::Bits8.bytes(), 1);
        assert_eq!(RegisterWidth::Bits32.bytes(), 4);
        assert_eq!(RegisterWidth::Bits64.bytes(), 8);
        assert_eq!(RegisterWidth::Bits256.bytes(), 32);
    }

    #[test]
    fn test_register_alias_contains() {
        let wide = RegisterAlias::new("rax", RegisterWidth::Bits64, 0);
        let narrow = RegisterAlias::new("eax", RegisterWidth::Bits32, 0);
        assert!(wide.contains(&narrow));
        assert!(!narrow.contains(&wide));
    }

    #[test]
    fn test_register_alias_overlaps() {
        let ax = RegisterAlias::new("ax", RegisterWidth::Bits16, 0);
        let al = RegisterAlias::new("al", RegisterWidth::Bits8, 0);
        let ah = RegisterAlias::new("ah", RegisterWidth::Bits8, 1);
        assert!(ax.overlaps(&al));
        assert!(ax.overlaps(&ah));
        assert!(!al.overlaps(&ah));
    }

    #[test]
    fn test_alias_map_canonical() {
        let m = make_map();
        assert_eq!(m.canonical("eax"), Some("rax"));
        assert_eq!(m.canonical("al"), Some("rax"));
        assert_eq!(m.canonical("rdi"), Some("rdi"));
    }

    #[test]
    fn test_alias_map_all_aliases_rax() {
        let m = make_map();
        let aliases = m.all_aliases("eax");
        let names: Vec<&str> = aliases.iter().map(String::as_str).collect();
        assert!(names.contains(&"rax"));
        assert!(names.contains(&"eax"));
        assert!(names.contains(&"ax"));
        assert!(names.contains(&"al"));
        assert!(names.contains(&"ah"));
    }

    #[test]
    fn test_simd_alias_xmm_in_ymm() {
        let m = make_map();
        let aliases = m.all_aliases("xmm0");
        let names: Vec<&str> = aliases.iter().map(String::as_str).collect();
        assert!(names.contains(&"ymm0"));
        assert!(names.contains(&"zmm0"));
    }

    #[test]
    fn test_liveness_effect_eax_zero_extends() {
        let m = make_map();
        let effect = m.liveness_effect("eax");
        // Writing eax should zero-extend to rax on x86-64.
        assert!(effect.defined.contains(&"rax".to_string()));
        assert!(effect.defined.contains(&"eax".to_string()));
    }

    #[test]
    fn test_liveness_effect_al_partial() {
        let m = make_map();
        let effect = m.liveness_effect("al");
        // Writing al partially defines ax / eax / rax.
        assert!(effect.clobbered_partial.contains(&"ax".to_string())
            || effect.partial.contains(&"ax".to_string())
            || effect.clobbered_partial.contains(&"rax".to_string()));
    }

    #[test]
    fn test_arm64_aliases() {
        let m = make_map();
        let aliases = m.all_aliases("w0");
        let names: Vec<&str> = aliases.iter().map(String::as_str).collect();
        assert!(names.contains(&"x0"));
        assert!(names.contains(&"w0"));
    }

    #[test]
    fn test_arm_d_register_contains_s() {
        let m = make_map();
        let aliases = m.all_aliases("d0");
        let names: Vec<&str> = aliases.iter().map(String::as_str).collect();
        assert!(names.contains(&"s0"));
        assert!(names.contains(&"s1"));
    }

    #[test]
    fn test_affected_by_write_rdx() {
        let m = make_map();
        let affected = m.affected_by_write("edx");
        // edx overlaps ax, al, ah (if in the same group) — here just checks rax / ax.
        // For edx group: rdx, edx, dx, dl, dh all overlap.
        assert!(!affected.is_empty());
    }

    #[test]
    fn test_group_count_nonzero() {
        let m = make_map();
        assert!(m.group_count() > 50);
    }

    #[test]
    fn test_register_width_display() {
        assert_eq!(RegisterWidth::Bits64.to_string(), "64b");
        assert_eq!(RegisterWidth::Bits128.to_string(), "128b");
    }
}
