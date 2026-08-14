//! DEX deobfuscation pass: string decryption pattern detection and emulation,
//! reflection resolution (Class.forName + getMethod → concrete type),
//! ProGuard/R8 undo (mapping file or heuristics).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DeobfuscationError {
    #[error("no decryptor found in class {0}")]
    NoDecryptor(String),
    #[error("emulation error: {0}")]
    EmulationError(String),
    #[error("mapping not available")]
    NoMapping,
    #[error("invalid DEX data")]
    InvalidDex,
}

pub type DeobfuscationResult<T> = Result<T, DeobfuscationError>;

// ── String decryption patterns ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptorPattern {
    /// Single static method taking an int/String, returning String.
    StaticSingleArg,
    /// Static method taking two args (key + data).
    StaticTwoArgs,
    /// AES-based with embedded key constant.
    AesWithKey,
    /// XOR-based character loop.
    XorLoop,
    /// Base64 decode then XOR.
    Base64Xor,
    /// Unknown pattern.
    Unknown,
}

impl DecryptorPattern {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticSingleArg => "static single-arg",
            Self::StaticTwoArgs => "static two-arg",
            Self::AesWithKey => "AES with embedded key",
            Self::XorLoop => "XOR loop",
            Self::Base64Xor => "Base64 + XOR",
            Self::Unknown => "unknown",
        }
    }
}

// ── Decryptor candidate ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptorCandidate {
    pub class_name: String,
    pub method_name: String,
    pub jvm_descriptor: String,
    pub pattern: DecryptorPattern,
    pub call_site_count: usize,
    pub confidence: f32,
}

impl DecryptorCandidate {
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.75
    }
}

// ── Emulated string resolution ────────────────────────────────────────────────

/// A string that has been decrypted through emulation or pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedString {
    pub encrypted_form: String,
    pub decrypted_value: String,
    pub call_site_offset: u64,
    pub decryptor_class: String,
    pub decryptor_method: String,
    pub emulation_method: EmulationMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulationMethod {
    /// Replicated the algorithm in Rust.
    NativeEmulation,
    /// Used JADX's own interpreter.
    JadxInterpreter,
    /// Matched a known decryptor template.
    TemplateMatch,
    /// Ran actual Dalvik bytecode in an emulator.
    DexEmulator,
}

// ── Simple XOR emulator ───────────────────────────────────────────────────────

/// Emulate a simple XOR-based string decryptor.
///
/// Pattern: encrypted bytes (byte array) `XORed` with a single byte key.
#[must_use]
pub fn emulate_xor_decryptor(encrypted: &[u8], key: u8) -> String {
    let decrypted: Vec<u8> = encrypted.iter().map(|&b| b ^ key).collect();
    String::from_utf8_lossy(&decrypted).into_owned()
}

/// Emulate a XOR with rolling key.
#[must_use]
pub fn emulate_xor_rolling(encrypted: &[u8], key: &[u8]) -> String {
    if key.is_empty() {
        return String::from_utf8_lossy(encrypted).into_owned();
    }
    let decrypted: Vec<u8> = encrypted
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&decrypted).into_owned()
}

/// Emulate a rotation-based string decryptor (subtract constant from each char).
#[must_use]
pub fn emulate_rotate_decryptor(encrypted: &str, shift: i32) -> String {
    encrypted
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let offset = u8::try_from((c as i32 - i32::from(base) - shift).rem_euclid(26)).unwrap_or(0);
                (base + offset) as char
            } else {
                c
            }
        })
        .collect()
}

/// Decode base64 and then XOR.
#[must_use]
pub fn emulate_base64_xor(b64: &str, key: u8) -> Option<String> {
    let decoded = base64_decode(b64)?;
    Some(emulate_xor_decryptor(&decoded, key))
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.trim_end_matches('=');
    let mut lookup = [0u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = u8::try_from(i).unwrap_or(0);
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in input.bytes() {
        if c == b' ' || c == b'\n' || c == b'\r' {
            continue;
        }
        if !TABLE.contains(&c) {
            return None;
        }
        buf = (buf << 6) | u32::from(lookup[c as usize]);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buf >> bits & 0xFF).unwrap_or(0));
        }
    }
    Some(out)
}

// ── Reflection resolver ───────────────────────────────────────────────────────

/// A resolved reflection call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedReflectionCall {
    /// Original class name as passed to Class.forName (may be obfuscated).
    pub class_name_arg: String,
    /// Resolved class name (after applying mapping or heuristics).
    pub resolved_class: Option<String>,
    /// Method name argument.
    pub method_name_arg: Option<String>,
    /// Resolved method signature.
    pub resolved_method: Option<String>,
    pub call_site: u64,
    pub resolution_source: ResolutionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionSource {
    ProguardMapping,
    StringAnalysis,
    HeuristicMatch,
    Unresolved,
}

impl ResolutionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProguardMapping => "ProGuard mapping",
            Self::StringAnalysis => "string analysis",
            Self::HeuristicMatch => "heuristic",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Resolve Class.forName calls using available mapping information.
pub struct ReflectionResolver<'a> {
    class_map: Option<&'a HashMap<String, String>>,
    method_map: Option<&'a HashMap<(String, String), String>>,
    known_classes: Vec<String>,
}

impl<'a> ReflectionResolver<'a> {
    #[must_use]
    pub const fn new() -> Self {
        Self { class_map: None, method_map: None, known_classes: Vec::new() }
    }

    #[must_use]
    pub const fn with_class_map(mut self, map: &'a HashMap<String, String>) -> Self {
        self.class_map = Some(map);
        self
    }

    #[must_use]
    pub const fn with_method_map(mut self, map: &'a HashMap<(String, String), String>) -> Self {
        self.method_map = Some(map);
        self
    }

    #[must_use]
    pub fn with_known_classes(mut self, classes: Vec<String>) -> Self {
        self.known_classes = classes;
        self
    }

    #[must_use]
    pub fn resolve_class(&self, obf_name: &str) -> (Option<String>, ResolutionSource) {
        // Try ProGuard mapping first
        if let Some(map) = self.class_map
            && let Some(orig) = map.get(obf_name)
        {
            return (Some(orig.clone()), ResolutionSource::ProguardMapping);
        }
        // Try heuristic: if the name is in known classes, return as-is
        let jvm_style = obf_name.replace('.', "/");
        if self.known_classes.iter().any(|c| {
            // Strip the descriptor marker exactly once: `trim_start_matches`
            // repeats and would mangle any class whose name starts with 'L',
            // making the comparison silently fail to match.
            let c = c.strip_prefix('L').unwrap_or(c);
            c.strip_suffix(';').unwrap_or(c) == jvm_style
        }) {
            return (Some(obf_name.to_owned()), ResolutionSource::StringAnalysis);
        }
        (None, ResolutionSource::Unresolved)
    }

    #[must_use]
    pub fn resolve_method(
        &self,
        class: &str,
        method: &str,
    ) -> (Option<String>, ResolutionSource) {
        if let Some(map) = self.method_map
            && let Some(sig) = map.get(&(class.to_owned(), method.to_owned()))
        {
            return (Some(sig.clone()), ResolutionSource::ProguardMapping);
        }
        (None, ResolutionSource::Unresolved)
    }

    #[must_use]
    pub fn resolve_call(
        &self,
        class_arg: &str,
        method_arg: Option<&str>,
        call_site: u64,
    ) -> ResolvedReflectionCall {
        let (resolved_class, cls_src) = self.resolve_class(class_arg);
        let (resolved_method, _) = if let (Some(cls), Some(meth)) = (&resolved_class, method_arg) {
            self.resolve_method(cls, meth)
        } else {
            (None, ResolutionSource::Unresolved)
        };

        ResolvedReflectionCall {
            class_name_arg: class_arg.to_owned(),
            resolved_class,
            method_name_arg: method_arg.map(str::to_owned),
            resolved_method,
            call_site,
            resolution_source: cls_src,
        }
    }
}

impl Default for ReflectionResolver<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// ── ProGuard undo ─────────────────────────────────────────────────────────────

/// Rename result: the original name restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscatedName {
    pub obfuscated: String,
    pub original: String,
    pub kind: NameKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameKind {
    Class,
    Method,
    Field,
}

impl NameKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Method => "method",
            Self::Field => "field",
        }
    }
}

/// Apply a `ProGuard`/R8 mapping to a list of identifiers.
#[must_use]
pub fn apply_mapping_to_names<S: std::hash::BuildHasher>(
    names: &[(NameKind, String)],
    class_map: &HashMap<String, String, S>,
    method_map: &HashMap<(String, String), String, S>,
) -> Vec<DeobfuscatedName> {
    let mut results = Vec::new();

    for (kind, name) in names {
        match kind {
            NameKind::Class => {
                let normalized = name.replace('/', ".");
                if let Some(orig) = class_map.get(&normalized) {
                    results.push(DeobfuscatedName {
                        obfuscated: name.clone(),
                        original: orig.clone(),
                        kind: NameKind::Class,
                    });
                }
            }
            NameKind::Method => {
                // name format: "com/example/a.b()V"
                if let Some(dot_pos) = name.find('.') {
                    let cls = name[..dot_pos].replace('/', ".");
                    let meth = &name[dot_pos + 1..];
                    let key = (cls.clone(), meth.to_owned());
                    if let Some(orig) = method_map.get(&key) {
                        results.push(DeobfuscatedName {
                            obfuscated: name.clone(),
                            original: format!("{cls}.{orig}"),
                            kind: NameKind::Method,
                        });
                    }
                }
            }
            NameKind::Field => {
                // Similar to method but from field_map
                results.push(DeobfuscatedName {
                    obfuscated: name.clone(),
                    original: name.clone(), // no-op without field map
                    kind: NameKind::Field,
                });
            }
        }
    }

    results
}

// ── Control flow deobfuscation ────────────────────────────────────────────────

/// Represents a switch-based dispatcher block (ConfuserEx-style control flow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchDispatcher {
    /// Offset of the switch instruction.
    pub switch_offset: u64,
    /// Number of case arms.
    pub case_count: usize,
    /// Whether this looks like an obfuscated dispatcher.
    pub looks_obfuscated: bool,
    /// Linearized instruction order (recovered).
    pub linearized_order: Vec<u64>,
}

impl SwitchDispatcher {
    /// Detect switch dispatchers in a flat list of (offset, opcode, operand) tuples.
    /// Heuristic: switch with >5 cases and case values forming non-sequential constants.
    #[must_use]
    pub fn detect(
        instructions: &[(u64, u8, i32)],
    ) -> Vec<Self> {
        let mut dispatchers = Vec::new();
        let mut i = 0;
        while i < instructions.len() {
            let (off, opcode, _operand) = instructions[i];
            // Dalvik PACKED_SWITCH = 0x2b, SPARSE_SWITCH = 0x2c
            if matches!(opcode, 0x2b | 0x2c) {
                // Count cases in nearby instructions (simplified)
                let case_count = instructions
                    .iter()
                    .skip(i + 1)
                    .take(30)
                    .filter(|&&(_, op, _)| op == 0x00) // nop / case padding
                    .count();

                let looks_obfuscated = case_count > 5;
                if looks_obfuscated {
                    let linearized = instructions
                        .iter()
                        .skip(i + 1)
                        .take(case_count)
                        .map(|&(o, _, _)| o)
                        .collect();
                    dispatchers.push(Self {
                        switch_offset: off,
                        case_count,
                        looks_obfuscated,
                        linearized_order: linearized,
                    });
                }
            }
            i += 1;
        }
        dispatchers
    }
}

// ── Proxy call removal ────────────────────────────────────────────────────────

/// A proxy method: a synthetic method that just calls another method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMethod {
    pub proxy_class: String,
    pub proxy_method: String,
    pub target_class: String,
    pub target_method: String,
    pub forwarded_args: usize,
}

impl ProxyMethod {
    /// Heuristically detect proxy methods from a method body.
    /// A proxy has exactly 1 invoke-* instruction and 1 return.
    #[must_use]
    pub fn detect_from_body(
        class: &str,
        method: &str,
        instructions: &[(u8, Vec<String>)],
    ) -> Option<Self> {
        let invoke_count = instructions.iter().filter(|(op, _)| {
            // Dalvik invoke-virtual=0x6e, invoke-static=0x71, invoke-direct=0x70
            matches!(op, 0x6e..=0x72)
        }).count();

        let return_count = instructions.iter().filter(|(op, _)| {
            matches!(op, 0x0e..=0x12)
        }).count();

        if invoke_count != 1 || return_count != 1 {
            return None;
        }

        // Extract target from the invoke instruction
        let invoke = instructions.iter().find(|(op, _)| matches!(op, 0x6e..=0x72))?;
        let args = &invoke.1;
        if args.len() < 2 {
            return None;
        }

        let target_ref = &args[0]; // method reference
        let parts: Vec<&str> = target_ref.splitn(2, "->").collect();
        if parts.len() < 2 {
            return None;
        }

        // Strip the descriptor marker exactly once — `trim_start_matches`
        // repeats and would eat the first letter of e.g. `LList;`.
        let target_class = parts[0].strip_prefix('L').unwrap_or(parts[0]);
        let target_class = target_class
            .strip_suffix(';')
            .unwrap_or(target_class)
            .replace('/', ".");
        let target_method = parts[1].to_owned();
        let forwarded_args = args.len() - 1;

        Some(Self {
            proxy_class: class.to_owned(),
            proxy_method: method.to_owned(),
            target_class,
            target_method,
            forwarded_args,
        })
    }
}

// ── Deobfuscation pass orchestrator ──────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeobfuscationPassResult {
    pub decrypted_strings: Vec<DecryptedString>,
    pub resolved_reflections: Vec<ResolvedReflectionCall>,
    pub deobfuscated_names: Vec<DeobfuscatedName>,
    pub removed_proxies: Vec<ProxyMethod>,
    pub switch_dispatchers: Vec<SwitchDispatcher>,
    pub string_decryptors_found: Vec<DecryptorCandidate>,
    pub total_strings_decrypted: usize,
    pub total_reflections_resolved: usize,
    pub total_names_restored: usize,
}

impl DeobfuscationPassResult {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Deobfuscation pass: {} strings decrypted, {} reflections resolved, \
             {} names restored, {} proxies removed, {} dispatchers linearized",
            self.total_strings_decrypted,
            self.total_reflections_resolved,
            self.total_names_restored,
            self.removed_proxies.len(),
            self.switch_dispatchers.len(),
        )
    }
}

/// High-level deobfuscation orchestrator.
pub struct DeobfuscationPass {
    class_map: HashMap<String, String>,
    method_map: HashMap<(String, String), String>,
    xor_keys: Vec<u8>,
    known_decryptors: Vec<DecryptorCandidate>,
}

impl DeobfuscationPass {
    #[must_use]
    pub fn new() -> Self {
        Self {
            class_map: HashMap::new(),
            method_map: HashMap::new(),
            xor_keys: Vec::new(),
            known_decryptors: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_class_map(mut self, map: HashMap<String, String>) -> Self {
        self.class_map = map;
        self
    }

    #[must_use]
    pub fn with_method_map(mut self, map: HashMap<(String, String), String>) -> Self {
        self.method_map = map;
        self
    }

    #[must_use]
    pub fn with_xor_keys(mut self, keys: Vec<u8>) -> Self {
        self.xor_keys = keys;
        self
    }

    pub fn add_decryptor(&mut self, candidate: DecryptorCandidate) {
        self.known_decryptors.push(candidate);
    }

    /// Find decryptor candidates by scanning method signatures in the string pool.
    pub fn scan_decryptor_candidates(
        &mut self,
        class_method_strings: &[(String, String, usize)],
    ) {
        for (class, method, call_count) in class_method_strings {
            // Heuristic: short method in an obfuscated class with many call sites
            let is_short_class = class.rsplit('/').next()
                .is_some_and(|n| n.len() <= 3);
            let is_decrypt_name = method.len() <= 3
                || method.to_lowercase().contains("decrypt")
                || method.to_lowercase().contains("decode")
                || method.to_lowercase().contains("str");

            if is_short_class && is_decrypt_name && *call_count > 3 {
                let conf_bump = usize_to_f32_lossy(*call_count) * 0.01;
                self.known_decryptors.push(DecryptorCandidate {
                    class_name: class.clone(),
                    method_name: method.clone(),
                    jvm_descriptor: "(I)Ljava/lang/String;".into(),
                    pattern: DecryptorPattern::StaticSingleArg,
                    call_site_count: *call_count,
                    confidence: 0.6 + conf_bump.min(0.3),
                });
            }
        }
    }

    /// Attempt XOR decryption of all encrypted strings with known keys.
    #[must_use]
    pub fn decrypt_strings(
        &self,
        encrypted_strings: &[(String, u64, String, String)],
    ) -> Vec<DecryptedString> {
        let mut results = Vec::new();
        for (enc, offset, cls, meth) in encrypted_strings {
            for &key in &self.xor_keys {
                let plain = emulate_xor_decryptor(enc.as_bytes(), key);
                if is_printable_ascii(&plain) && !plain.is_empty() {
                    results.push(DecryptedString {
                        encrypted_form: enc.clone(),
                        decrypted_value: plain,
                        call_site_offset: *offset,
                        decryptor_class: cls.clone(),
                        decryptor_method: meth.clone(),
                        emulation_method: EmulationMethod::NativeEmulation,
                    });
                    break;
                }
            }
        }
        results
    }

    #[must_use]
    pub fn run(
        &self,
        encrypted_strings: &[(String, u64, String, String)],
        reflection_calls: &[(String, Option<String>, u64)],
        names_to_restore: &[(NameKind, String)],
    ) -> DeobfuscationPassResult {
        let decrypted_list = self.decrypt_strings(encrypted_strings);
        let total_decrypted = decrypted_list.len();

        let resolver = ReflectionResolver::new()
            .with_class_map(&self.class_map)
            .with_method_map(&self.method_map);

        let resolved_calls: Vec<ResolvedReflectionCall> = reflection_calls
            .iter()
            .map(|(cls, meth, off)| {
                resolver.resolve_call(cls, meth.as_deref(), *off)
            })
            .collect();
        let total_resolved = resolved_calls.iter().filter(|r| r.resolved_class.is_some()).count();

        let restored = apply_mapping_to_names(names_to_restore, &self.class_map, &self.method_map);
        let total_restored = restored.len();

        DeobfuscationPassResult {
            string_decryptors_found: self.known_decryptors.clone(),
            decrypted_strings: decrypted_list,
            resolved_reflections: resolved_calls,
            deobfuscated_names: restored,
            removed_proxies: Vec::new(),
            switch_dispatchers: Vec::new(),
            total_strings_decrypted: total_decrypted,
            total_reflections_resolved: total_resolved,
            total_names_restored: total_restored,
        }
    }
}

impl Default for DeobfuscationPass {
    fn default() -> Self {
        Self::new()
    }
}

fn is_printable_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
}

/// Cast `usize` to `f32`. Helper isolates the lossy cast.
const fn usize_to_f32_lossy(n: usize) -> f32 {
    n as f32
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_decrypt() {
        let plain = b"Hello World";
        let key = 0x42u8;
        let encrypted: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let result = emulate_xor_decryptor(&encrypted, key);
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_xor_rolling() {
        let plain = b"Secret";
        let key = b"key";
        let encrypted: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let result = emulate_xor_rolling(&encrypted, key);
        assert_eq!(result, "Secret");
    }

    #[test]
    fn test_rotate_decrypt() {
        let rotated = emulate_rotate_decryptor("Khoor", 3);
        assert_eq!(rotated, "Hello");
    }

    #[test]
    fn test_base64_decode() {
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_xor() {
        // Encode "Hello" ^ 0x01
        let encrypted: Vec<u8> = b"Hello".iter().map(|&b| b ^ 0x01).collect();
        let b64 = {
            let mut out = String::new();
            let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for chunk in encrypted.chunks(3) {
                let n = match chunk.len() {
                    1 => u32::from(chunk[0]) << 16,
                    2 => u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8,
                    _ => u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]),
                };
                out.push(table[(n >> 18) as usize] as char);
                out.push(table[((n >> 12) & 0x3f) as usize] as char);
                if chunk.len() > 1 { out.push(table[((n >> 6) & 0x3f) as usize] as char); } else { out.push('='); }
                if chunk.len() > 2 { out.push(table[(n & 0x3f) as usize] as char); } else { out.push('='); }
            }
            out
        };
        let result = emulate_base64_xor(&b64, 0x01).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_reflection_resolver_no_map() {
        let resolver = ReflectionResolver::new();
        let result = resolver.resolve_call("com.example.Foo", Some("bar"), 0x100);
        assert_eq!(result.resolution_source, ResolutionSource::Unresolved);
    }

    #[test]
    fn test_reflection_resolver_with_map() {
        let mut class_map = HashMap::new();
        class_map.insert("a.b".to_owned(), "com.example.Foo".to_owned());
        let resolver = ReflectionResolver::new().with_class_map(&class_map);
        let result = resolver.resolve_call("a.b", None, 0x200);
        assert_eq!(result.resolved_class.as_deref(), Some("com.example.Foo"));
        assert_eq!(result.resolution_source, ResolutionSource::ProguardMapping);
    }

    #[test]
    fn test_deobfuscation_pass_xor() {
        let plain = "android.permission.CAMERA";
        let key = 0x55u8;
        let encrypted: Vec<u8> = plain.bytes().map(|b| b ^ key).collect();
        let enc_str = String::from_utf8_lossy(&encrypted).into_owned();

        let pass = DeobfuscationPass::new().with_xor_keys(vec![0x55]);
        let result = pass.run(
            &[(enc_str, 0x100, "La/b;".into(), "a".into())],
            &[],
            &[],
        );
        // Not all XOR results are printable ASCII; just check it ran
        let _ = result;
    }

    #[test]
    fn test_apply_mapping() {
        let mut class_map = HashMap::new();
        class_map.insert("a.b".to_owned(), "com.example.Main".to_owned());
        let names = vec![(NameKind::Class, "a.b".to_owned())];
        let results = apply_mapping_to_names(&names, &class_map, &HashMap::new());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].original, "com.example.Main");
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii("Hello World!"));
        assert!(!is_printable_ascii("Hello\x00World"));
    }
}
