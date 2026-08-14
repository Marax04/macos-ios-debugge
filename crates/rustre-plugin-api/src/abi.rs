// rustre-plugin-api/src/abi.rs
// Plugin ABI versioning and binary compatibility checking.

use std::fmt;

// ─── ABI Version ─────────────────────────────────────────────────────────────

/// Semantic version for the plugin ABI.
/// The ABI is considered compatible when:
///   - major versions match exactly, AND
///   - the host's (major, minor, patch) >= plugin's required (major, minor, patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct AbiVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    _pad: u16,
}

impl AbiVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            _pad: 0,
        }
    }

    /// Current ABI version exported by the host.
    pub const CURRENT: Self = Self::new(0, 1, 0);

    /// Parse "M.m.p" notation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut iter = s.split('.');
        let major: u16 = iter.next()?.parse().ok()?;
        let minor: u16 = iter.next()?.parse().ok()?;
        let patch: u16 = iter.next()?.parse().ok()?;
        Some(Self::new(major, minor, patch))
    }

    /// Pack into a u64 for embedding in binary headers.
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        ((self.major as u64) << 32) | ((self.minor as u64) << 16) | (self.patch as u64)
    }

    /// Unpack from a u64.
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        Self::new(
            ((v >> 32) & 0xFFFF) as u16,
            ((v >> 16) & 0xFFFF) as u16,
            (v & 0xFFFF) as u16,
        )
    }

    /// Return `true` if `self` (host) is backward-compatible with `required` (plugin claim).
    ///
    /// Rules:
    ///   - Major must match exactly.  A bump signals a breaking change.
    ///   - Minor must be >= required minor.  A bump signals new API, no breakage.
    ///   - Patch does not affect compatibility.
    #[must_use]
    pub const fn is_compatible_with(self, required: Self) -> bool {
        self.major == required.major && self.minor >= required.minor
    }

    /// True if this represents a pre-release (major == 0).
    #[must_use]
    pub const fn is_pre_release(self) -> bool {
        self.major == 0
    }

    /// Increment major, reset minor and patch.
    /// Saturates at `u16::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_major(self) -> Self {
        Self::new(self.major.saturating_add(1), 0, 0)
    }
    /// Increment minor, reset patch.
    /// Saturates at `u16::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_minor(self) -> Self {
        Self::new(self.major, self.minor.saturating_add(1), 0)
    }
    /// Increment patch.
    /// Saturates at `u16::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_patch(self) -> Self {
        Self::new(self.major, self.minor, self.patch.saturating_add(1))
    }
}

impl fmt::Display for AbiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The current ABI version constant — re-exported at crate level for convenience.
pub const ABI_CURRENT: AbiVersion = AbiVersion::CURRENT;

// ─── ABI Descriptor ──────────────────────────────────────────────────────────

/// Magic bytes identifying a Rustre plugin ABI descriptor block.
pub const ABI_MAGIC: [u8; 8] = *b"RUSTREAB";

/// The fixed-size C-compatible ABI descriptor that every plugin must embed.
///
/// Layout (all values little-endian):
/// ```text
/// offset  size  field
///  0       8    magic ("RUSTREAB")
///  8       8    abi_version (packed u64)
///  16      8    min_host_version (packed u64)
///  24      4    plugin_flags
///  28      4    reserved
///  32     64    plugin_name (NUL-padded UTF-8)
///  96      4    name_len
/// 100      4    api_checksum (CRC32-like, see below)
/// 104     24    reserved2
/// 128          (total size: 128 bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct AbiDescriptor {
    /// Must equal `ABI_MAGIC`.
    pub magic: [u8; 8],
    /// ABI version this plugin was compiled against.
    pub abi_version: u64,
    /// Minimum host ABI version the plugin requires.
    pub min_host_version: u64,
    /// Plugin-level flags (bitfield, see `AbiPluginFlags`).
    pub plugin_flags: u32,
    pub reserved1: u32,
    /// Plugin name, NUL-padded to 64 bytes.
    pub plugin_name: [u8; 64],
    /// Number of valid bytes in `plugin_name`.
    pub name_len: u32,
    /// Simple API-level checksum (XOR of all other u32/u64 fields).
    pub api_checksum: u32,
    pub reserved2: [u8; 24],
}

impl AbiDescriptor {
    /// Size of the descriptor in bytes.
    pub const SIZE: usize = 128;

    /// Create a new descriptor for a plugin.
    #[must_use]
    pub fn new(name: &str, abi: AbiVersion, min_host: AbiVersion, flags: AbiPluginFlags) -> Self {
        let mut desc = Self {
            magic: ABI_MAGIC,
            abi_version: abi.to_u64(),
            min_host_version: min_host.to_u64(),
            plugin_flags: flags.bits(),
            reserved1: 0,
            plugin_name: [0u8; 64],
            name_len: 0,
            api_checksum: 0,
            reserved2: [0u8; 24],
        };
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(64);
        desc.plugin_name[..copy_len].copy_from_slice(&bytes[..copy_len]);
        desc.name_len = u32::try_from(copy_len).unwrap_or(u32::MAX);
        desc.api_checksum = desc.compute_checksum();
        desc
    }

    /// Decode a descriptor from a 128-byte buffer.
    #[must_use]
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let magic: [u8; 8] = buf[0..8].try_into().ok()?;
        if magic != ABI_MAGIC {
            return None;
        }
        let abi_version = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        let min_host = u64::from_le_bytes(buf[16..24].try_into().ok()?);
        let plugin_flags = u32::from_le_bytes(buf[24..28].try_into().ok()?);
        let reserved1 = u32::from_le_bytes(buf[28..32].try_into().ok()?);
        let mut plugin_name = [0u8; 64];
        plugin_name.copy_from_slice(&buf[32..96]);
        let name_len = u32::from_le_bytes(buf[96..100].try_into().ok()?);
        let api_checksum = u32::from_le_bytes(buf[100..104].try_into().ok()?);
        let mut reserved2 = [0u8; 24];
        reserved2.copy_from_slice(&buf[104..128]);

        Some(Self {
            magic,
            abi_version,
            min_host_version: min_host,
            plugin_flags,
            reserved1,
            plugin_name,
            name_len,
            api_checksum,
            reserved2,
        })
    }

    /// Serialize to a 128-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut buf = [0u8; 128];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..16].copy_from_slice(&self.abi_version.to_le_bytes());
        buf[16..24].copy_from_slice(&self.min_host_version.to_le_bytes());
        buf[24..28].copy_from_slice(&self.plugin_flags.to_le_bytes());
        buf[28..32].copy_from_slice(&self.reserved1.to_le_bytes());
        buf[32..96].copy_from_slice(&self.plugin_name);
        buf[96..100].copy_from_slice(&self.name_len.to_le_bytes());
        buf[100..104].copy_from_slice(&self.api_checksum.to_le_bytes());
        buf[104..128].copy_from_slice(&self.reserved2);
        buf
    }

    /// Verify the embedded checksum.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        self.api_checksum == self.compute_checksum()
    }

    fn compute_checksum(&self) -> u32 {
        // XOR-fold all non-checksum fields.
        let mut acc: u32 = 0;
        for b in self.magic {
            acc ^= u32::from(b);
        }
        acc ^= u32::try_from(self.abi_version & 0xFFFF_FFFF).unwrap_or(0)
            ^ u32::try_from(self.abi_version >> 32).unwrap_or(0);
        acc ^= u32::try_from(self.min_host_version & 0xFFFF_FFFF).unwrap_or(0)
            ^ u32::try_from(self.min_host_version >> 32).unwrap_or(0);
        acc ^= self.plugin_flags;
        for b in self.plugin_name {
            acc ^= u32::from(b);
        }
        acc ^= self.name_len;
        acc
    }

    /// Extract plugin name as a `String`.
    #[must_use]
    pub fn plugin_name_str(&self) -> String {
        let len = (self.name_len as usize).min(64);
        String::from_utf8_lossy(&self.plugin_name[..len]).to_string()
    }

    /// Decode the ABI version field.
    #[must_use]
    pub const fn abi_version_decoded(&self) -> AbiVersion {
        AbiVersion::from_u64(self.abi_version)
    }

    /// Decode the minimum host version field.
    #[must_use]
    pub const fn min_host_version_decoded(&self) -> AbiVersion {
        AbiVersion::from_u64(self.min_host_version)
    }

    /// True if magic bytes are valid.
    #[must_use]
    pub fn magic_valid(&self) -> bool {
        self.magic == ABI_MAGIC
    }
}

// ─── ABI Plugin Flags ────────────────────────────────────────────────────────

/// Flags embedded in the ABI descriptor to describe plugin properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbiPluginFlags(u32);

impl AbiPluginFlags {
    pub const NONE: Self = Self(0);
    /// Plugin is thread-safe and can be called concurrently.
    pub const THREAD_SAFE: Self = Self(1 << 0);
    /// Plugin exports a stable C ABI (extern "C" all entry points).
    pub const C_ABI: Self = Self(1 << 1);
    /// Plugin supports hot-reload via state migration.
    pub const HOT_RELOAD: Self = Self(1 << 2);
    /// Plugin has been signed.
    pub const SIGNED: Self = Self(1 << 3);
    /// Plugin requires the sandbox to be active.
    pub const REQUIRES_SANDBOX: Self = Self(1 << 4);
    /// Plugin is in debug/development mode.
    pub const DEBUG_MODE: Self = Self(1 << 5);

    #[must_use]
    pub const fn new(flags: u32) -> Self {
        Self(flags)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    #[must_use]
    pub const fn set(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    #[must_use]
    pub const fn clear(self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }
}

// ─── ABI Compatibility ───────────────────────────────────────────────────────

/// Result of an ABI compatibility check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiCompatibility {
    Compatible,
    HostTooOld {
        host: AbiVersion,
        required: AbiVersion,
    },
    MajorMismatch {
        host: AbiVersion,
        plugin: AbiVersion,
    },
    InvalidMagic,
    ChecksumMismatch,
    MalformedDescriptor(String),
}

impl AbiCompatibility {
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        *self == Self::Compatible
    }
}

impl fmt::Display for AbiCompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatible => write!(f, "ABI compatible"),
            Self::HostTooOld { host, required } => write!(
                f,
                "Host ABI {host} is too old; plugin requires >={required}"
            ),
            Self::MajorMismatch { host, plugin } => {
                write!(f, "ABI major mismatch: host={host}, plugin={plugin}")
            }
            Self::InvalidMagic => write!(f, "ABI descriptor has invalid magic bytes"),
            Self::ChecksumMismatch => write!(f, "ABI descriptor checksum mismatch"),
            Self::MalformedDescriptor(msg) => write!(f, "Malformed ABI descriptor: {msg}"),
        }
    }
}

// ─── check_abi_compatibility ──────────────────────────────────────────────────

/// Check whether `desc` is compatible with the given host ABI version.
#[must_use]
pub fn check_abi_compatibility(host: AbiVersion, desc: &AbiDescriptor) -> AbiCompatibility {
    if !desc.magic_valid() {
        return AbiCompatibility::InvalidMagic;
    }
    if !desc.verify_checksum() {
        return AbiCompatibility::ChecksumMismatch;
    }
    let required = desc.min_host_version_decoded();
    if host.major != required.major {
        return AbiCompatibility::MajorMismatch {
            host,
            plugin: desc.abi_version_decoded(),
        };
    }
    if !host.is_compatible_with(required) {
        return AbiCompatibility::HostTooOld { host, required };
    }
    AbiCompatibility::Compatible
}

// ─── PluginAbi Trait ─────────────────────────────────────────────────────────

/// Every plugin shared library must implement this trait.
///
/// # ABI Evolution Notes
/// - **Major version bump**: Any change to the calling convention, removal of
///   functions, or change in type layout. Plugins compiled against v1.x cannot
///   be loaded by a v2.x host and vice-versa.
/// - **Minor version bump**: New optional entry points added; old plugins remain
///   loadable. New entry points must have default implementations (e.g., no-op).
/// - **Patch version bump**: Bug fixes with no visible ABI change.  Fully
///   backward- and forward-compatible.
/// - **Pre-release (major==0)**: No stability guarantees; even patch bumps may
///   break compatibility.
pub trait PluginAbi {
    /// Return the descriptor embedded in this plugin.
    fn abi_descriptor(&self) -> &AbiDescriptor;

    /// Return the ABI version this plugin was built against.
    fn abi_version(&self) -> AbiVersion {
        self.abi_descriptor().abi_version_decoded()
    }

    /// Minimum host ABI this plugin is willing to run against.
    fn min_host_version(&self) -> AbiVersion {
        self.abi_descriptor().min_host_version_decoded()
    }

    /// Check compatibility with a given host version.
    fn check_compatibility(&self, host: AbiVersion) -> AbiCompatibility {
        check_abi_compatibility(host, self.abi_descriptor())
    }
}

// ─── ABI Registry ────────────────────────────────────────────────────────────

/// Tracks loaded plugin descriptors for versioning diagnostics.
#[derive(Debug, Default)]
pub struct AbiRegistry {
    entries: Vec<(String, AbiDescriptor)>,
}

impl AbiRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a descriptor under a plugin path.
    pub fn register(&mut self, path: String, desc: AbiDescriptor) {
        self.entries.push((path, desc));
    }

    /// Find by plugin name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&AbiDescriptor> {
        self.entries
            .iter()
            .find(|(_, d)| d.plugin_name_str() == name)
            .map(|(_, d)| d)
    }

    /// Return all entries where the host is too old.
    #[must_use]
    pub fn incompatible_entries(&self, host: AbiVersion) -> Vec<(&str, AbiCompatibility)> {
        self.entries
            .iter()
            .map(|(p, d)| (p.as_str(), check_abi_compatibility(host, d)))
            .filter(|(_, c)| !c.is_compatible())
            .collect()
    }

    /// Return all compatible entries.
    #[must_use]
    pub fn compatible_entries(&self, host: AbiVersion) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, d)| check_abi_compatibility(host, d).is_compatible())
            .map(|(p, _)| p.as_str())
            .collect()
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AbiVersion ───────────────────────────────────────────────────────

    #[test]
    fn test_abi_version_display() {
        let v = AbiVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_abi_version_parse() {
        let v = AbiVersion::parse("2.5.10").unwrap();
        assert_eq!(v, AbiVersion::new(2, 5, 10));
    }

    #[test]
    fn test_abi_version_parse_invalid() {
        assert!(AbiVersion::parse("not_a_version").is_none());
        assert!(AbiVersion::parse("1.2").is_none());
    }

    #[test]
    fn test_abi_version_to_from_u64() {
        let v = AbiVersion::new(3, 7, 12);
        assert_eq!(AbiVersion::from_u64(v.to_u64()), v);
    }

    #[test]
    fn test_abi_version_ordering() {
        assert!(AbiVersion::new(1, 0, 0) > AbiVersion::new(0, 9, 9));
        assert!(AbiVersion::new(0, 2, 0) > AbiVersion::new(0, 1, 9));
        assert!(AbiVersion::new(0, 1, 5) > AbiVersion::new(0, 1, 4));
    }

    #[test]
    fn test_abi_version_compatible_same() {
        let host = AbiVersion::new(1, 2, 0);
        let req = AbiVersion::new(1, 2, 0);
        assert!(host.is_compatible_with(req));
    }

    #[test]
    fn test_abi_version_compatible_newer_minor() {
        let host = AbiVersion::new(1, 3, 0);
        let req = AbiVersion::new(1, 2, 0);
        assert!(host.is_compatible_with(req));
    }

    #[test]
    fn test_abi_version_incompatible_major() {
        let host = AbiVersion::new(2, 0, 0);
        let req = AbiVersion::new(1, 0, 0);
        assert!(!host.is_compatible_with(req));
    }

    #[test]
    fn test_abi_version_incompatible_minor() {
        let host = AbiVersion::new(1, 1, 0);
        let req = AbiVersion::new(1, 2, 0);
        assert!(!host.is_compatible_with(req));
    }

    #[test]
    fn test_abi_version_pre_release() {
        assert!(AbiVersion::new(0, 1, 0).is_pre_release());
        assert!(!AbiVersion::new(1, 0, 0).is_pre_release());
    }

    #[test]
    fn test_abi_version_bump() {
        let v = AbiVersion::new(1, 2, 3);
        assert_eq!(v.bump_major(), AbiVersion::new(2, 0, 0));
        assert_eq!(v.bump_minor(), AbiVersion::new(1, 3, 0));
        assert_eq!(v.bump_patch(), AbiVersion::new(1, 2, 4));
    }

    #[test]
    fn test_abi_current_defined() {
        assert_eq!(ABI_CURRENT, AbiVersion::new(0, 1, 0));
    }

    // ── AbiDescriptor ────────────────────────────────────────────────────

    fn make_desc() -> AbiDescriptor {
        AbiDescriptor::new(
            "my_plugin",
            AbiVersion::new(0, 1, 0),
            AbiVersion::new(0, 1, 0),
            AbiPluginFlags::NONE,
        )
    }

    #[test]
    fn test_descriptor_roundtrip() {
        let d = make_desc();
        let bytes = d.to_bytes();
        let d2 = AbiDescriptor::from_bytes(&bytes).unwrap();
        assert_eq!(d.plugin_name_str(), d2.plugin_name_str());
        assert_eq!(d.abi_version, d2.abi_version);
    }

    #[test]
    fn test_descriptor_magic() {
        let d = make_desc();
        assert!(d.magic_valid());
        assert_eq!(d.magic, ABI_MAGIC);
    }

    #[test]
    fn test_descriptor_checksum_valid() {
        let d = make_desc();
        assert!(d.verify_checksum());
    }

    #[test]
    fn test_descriptor_checksum_tampered() {
        let mut d = make_desc();
        d.plugin_flags = 0xDEAD_BEEF; // tamper
        // Checksum was computed before tampering, so verify should fail
        assert!(!d.verify_checksum());
    }

    #[test]
    fn test_descriptor_plugin_name_str() {
        let d = make_desc();
        assert_eq!(d.plugin_name_str(), "my_plugin");
    }

    #[test]
    fn test_descriptor_long_name_truncated() {
        let long_name = "a".repeat(200);
        let d = AbiDescriptor::new(
            &long_name,
            AbiVersion::new(0, 1, 0),
            AbiVersion::new(0, 1, 0),
            AbiPluginFlags::NONE,
        );
        assert_eq!(d.plugin_name_str().len(), 64);
    }

    #[test]
    fn test_descriptor_from_bytes_bad_magic() {
        let mut bytes = [0u8; 128];
        bytes[0] = b'X'; // bad magic
        assert!(AbiDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_descriptor_from_bytes_too_short() {
        let bytes = [0u8; 64];
        assert!(AbiDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_descriptor_size() {
        assert_eq!(AbiDescriptor::SIZE, 128);
        let d = make_desc();
        assert_eq!(d.to_bytes().len(), 128);
    }

    // ── AbiPluginFlags ───────────────────────────────────────────────────

    #[test]
    fn test_flags_has() {
        let f = AbiPluginFlags::THREAD_SAFE.set(AbiPluginFlags::HOT_RELOAD);
        assert!(f.has(AbiPluginFlags::THREAD_SAFE));
        assert!(f.has(AbiPluginFlags::HOT_RELOAD));
        assert!(!f.has(AbiPluginFlags::SIGNED));
    }

    #[test]
    fn test_flags_clear() {
        let f = AbiPluginFlags::THREAD_SAFE
            .set(AbiPluginFlags::HOT_RELOAD)
            .clear(AbiPluginFlags::THREAD_SAFE);
        assert!(!f.has(AbiPluginFlags::THREAD_SAFE));
        assert!(f.has(AbiPluginFlags::HOT_RELOAD));
    }

    #[test]
    fn test_flags_bits_roundtrip() {
        let bits: u32 = AbiPluginFlags::C_ABI.0 | AbiPluginFlags::SIGNED.0;
        let f = AbiPluginFlags::new(bits);
        assert_eq!(f.bits(), bits);
    }

    // ── check_abi_compatibility ──────────────────────────────────────────

    #[test]
    fn test_check_compatible() {
        let host = AbiVersion::new(0, 1, 0);
        let desc = make_desc();
        assert_eq!(
            check_abi_compatibility(host, &desc),
            AbiCompatibility::Compatible
        );
    }

    #[test]
    fn test_check_host_too_old() {
        let host = AbiVersion::new(0, 0, 5);
        let desc = AbiDescriptor::new(
            "plugin",
            AbiVersion::new(0, 1, 0),
            AbiVersion::new(0, 1, 0),
            AbiPluginFlags::NONE,
        );
        let result = check_abi_compatibility(host, &desc);
        assert!(matches!(result, AbiCompatibility::HostTooOld { .. }));
    }

    #[test]
    fn test_check_major_mismatch() {
        let host = AbiVersion::new(1, 0, 0);
        let desc = AbiDescriptor::new(
            "plugin",
            AbiVersion::new(0, 1, 0),
            AbiVersion::new(0, 1, 0),
            AbiPluginFlags::NONE,
        );
        let result = check_abi_compatibility(host, &desc);
        assert!(matches!(result, AbiCompatibility::MajorMismatch { .. }));
    }

    #[test]
    fn test_check_invalid_magic() {
        let mut desc = make_desc();
        desc.magic[0] = b'X';
        let result = check_abi_compatibility(AbiVersion::CURRENT, &desc);
        assert_eq!(result, AbiCompatibility::InvalidMagic);
    }

    #[test]
    fn test_check_checksum_mismatch() {
        let mut desc = make_desc();
        desc.plugin_flags = 0xFFFF_FFFF; // tamper without recomputing checksum
        let result = check_abi_compatibility(AbiVersion::CURRENT, &desc);
        assert_eq!(result, AbiCompatibility::ChecksumMismatch);
    }

    #[test]
    fn test_compatibility_is_compatible() {
        assert!(AbiCompatibility::Compatible.is_compatible());
        assert!(!AbiCompatibility::InvalidMagic.is_compatible());
    }

    // ── AbiCompatibility Display ─────────────────────────────────────────

    #[test]
    fn test_compat_display_compatible() {
        assert_eq!(AbiCompatibility::Compatible.to_string(), "ABI compatible");
    }

    #[test]
    fn test_compat_display_host_old() {
        let c = AbiCompatibility::HostTooOld {
            host: AbiVersion::new(0, 0, 1),
            required: AbiVersion::new(0, 1, 0),
        };
        assert!(c.to_string().contains("too old"));
    }

    // ── AbiRegistry ──────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_find() {
        let mut reg = AbiRegistry::new();
        let desc = make_desc();
        reg.register("/plugins/my_plugin.so".to_string(), desc);
        assert!(reg.find_by_name("my_plugin").is_some());
        assert!(reg.find_by_name("unknown").is_none());
    }

    #[test]
    fn test_registry_compatible_entries() {
        let mut reg = AbiRegistry::new();
        let compatible = AbiDescriptor::new(
            "good",
            AbiVersion::CURRENT,
            AbiVersion::CURRENT,
            AbiPluginFlags::NONE,
        );
        let incompatible = {
            AbiDescriptor::new(
                "bad",
                AbiVersion::new(1, 0, 0),
                AbiVersion::new(1, 0, 0),
                AbiPluginFlags::NONE,
            )
        };
        reg.register("good.so".to_string(), compatible);
        reg.register("bad.so".to_string(), incompatible);
        let compat = reg.compatible_entries(AbiVersion::CURRENT);
        assert_eq!(compat, vec!["good.so"]);
    }

    #[test]
    fn test_registry_count() {
        let mut reg = AbiRegistry::new();
        assert_eq!(reg.count(), 0);
        reg.register("a.so".to_string(), make_desc());
        reg.register("b.so".to_string(), make_desc());
        assert_eq!(reg.count(), 2);
    }
}
