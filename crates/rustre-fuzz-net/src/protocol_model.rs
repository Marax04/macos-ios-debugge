//! Protocol model for `rustre-fuzz-net`.
//!
//! Provides [`ProtocolModel`], [`MessageType`], [`MessageField`],
//! [`ProtocolConstraint`], [`ModelFuzzer`], [`MessageGenerator`], and
//! [`ValidMessageFilter`].

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{XorShiftRng, RngCore, INTERESTING_U8, INTERESTING_U16, INTERESTING_U32};

// ── MessageField ─────────────────────────────────────────────────────────────

/// Describes a single field within a protocol message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageField {
    /// Fixed-length bytes (always the same value, never mutated).
    Fixed {
        /// Field name.
        name: String,
        /// Fixed bytes.
        value: Vec<u8>,
    },
    /// Variable-length field with min/max byte counts.
    Variable {
        /// Field name.
        name: String,
        /// Minimum length in bytes.
        min: usize,
        /// Maximum length in bytes.
        max: usize,
        /// Whether this field should be fuzzed.
        fuzz: bool,
    },
    /// Enumerated field: one of several allowed byte sequences.
    Enum {
        /// Field name.
        name: String,
        /// Allowed values.
        variants: Vec<Vec<u8>>,
        /// Whether to sometimes generate invalid variants.
        allow_invalid: bool,
    },
    /// Nested message (recursively embeds another [`MessageType`] by name).
    Nested {
        /// Field name.
        name: String,
        /// Name of the nested message type.
        message_type: String,
    },
    /// A length field that will be filled with the byte-count of another field.
    LengthOf {
        /// Field name.
        name: String,
        /// The field whose length this field represents.
        target_field: String,
        /// Width in bytes: 1, 2, or 4.
        width: u8,
    },
}

impl MessageField {
    /// Name of this field.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Fixed { name, .. } => name,
            Self::Variable { name, .. } => name,
            Self::Enum { name, .. } => name,
            Self::Nested { name, .. } => name,
            Self::LengthOf { name, .. } => name,
        }
    }

    /// Whether this field is marked for fuzzing.
    #[must_use]
    pub fn is_fuzz_target(&self) -> bool {
        match self {
            Self::Fixed { .. } => false,
            Self::Variable { fuzz, .. } => *fuzz,
            Self::Enum { allow_invalid, .. } => *allow_invalid,
            Self::Nested { .. } => true,
            Self::LengthOf { .. } => false,
        }
    }

    /// Generate the default (non-fuzzed) bytes for this field.
    #[must_use]
    pub fn default_bytes(&self) -> Vec<u8> {
        match self {
            Self::Fixed { value, .. } => value.clone(),
            Self::Variable { min, .. } => vec![0u8; *min],
            Self::Enum { variants, .. } => variants.first().cloned().unwrap_or_default(),
            Self::Nested { .. } => Vec::new(), // resolved at message level
            Self::LengthOf { width, .. } => vec![0u8; *width as usize],
        }
    }
}

// ── MessageType ───────────────────────────────────────────────────────────────

/// A named protocol message type containing an ordered list of fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageType {
    /// Message type name.
    pub name: String,
    /// Ordered fields.
    pub fields: Vec<MessageField>,
    /// Minimum valid length in bytes.
    pub min_valid_len: usize,
    /// Maximum valid length in bytes (`None` = unlimited).
    pub max_valid_len: Option<usize>,
    /// Optional magic bytes that must appear at the start.
    pub magic: Option<Vec<u8>>,
}

impl MessageType {
    /// Create a new message type.
    #[must_use]
    pub fn new(name: impl Into<String>, fields: Vec<MessageField>) -> Self {
        Self {
            name: name.into(),
            fields,
            min_valid_len: 0,
            max_valid_len: None,
            magic: None,
        }
    }

    /// Set the magic prefix bytes.
    #[must_use]
    pub fn with_magic(mut self, magic: Vec<u8>) -> Self {
        self.magic = Some(magic.clone());
        self.min_valid_len = magic.len();
        self
    }

    /// Number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Number of fuzz-marked fields.
    #[must_use]
    pub fn fuzz_field_count(&self) -> usize {
        self.fields.iter().filter(|f| f.is_fuzz_target()).count()
    }

    /// Look up a field by name.
    #[must_use]
    pub fn get_field(&self, name: &str) -> Option<&MessageField> {
        self.fields.iter().find(|f| f.name() == name)
    }

    /// Validate a serialized message against the type constraints.
    #[must_use]
    pub fn validate(&self, data: &[u8]) -> bool {
        if data.len() < self.min_valid_len {
            return false;
        }
        if let Some(max) = self.max_valid_len {
            if data.len() > max {
                return false;
            }
        }
        if let Some(ref magic) = self.magic {
            if !data.starts_with(magic) {
                return false;
            }
        }
        true
    }

    /// Serialize this message type to its default byte representation.
    #[must_use]
    pub fn default_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in &self.fields {
            out.extend(field.default_bytes());
        }
        out
    }
}

// ── ProtocolConstraint ────────────────────────────────────────────────────────

/// A constraint that a generated message must satisfy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolConstraint {
    /// The message must be at least `min` bytes long.
    MinLength(usize),
    /// The message must be at most `max` bytes long.
    MaxLength(usize),
    /// The message must start with the given bytes.
    StartsWith(Vec<u8>),
    /// The message must end with the given bytes.
    EndsWith(Vec<u8>),
    /// A specific byte offset must equal a specific value.
    ByteAt {
        /// Byte offset.
        offset: usize,
        /// Expected value.
        value: u8,
    },
    /// The byte at `length_offset` (as u16 LE) must equal the message length.
    LengthField {
        /// Offset of the length field in bytes.
        length_offset: usize,
    },
    /// The sum of all bytes modulo 256 must equal `checksum`.
    ChecksumByte {
        /// Offset of the checksum byte.
        checksum_offset: usize,
    },
    /// Message must not contain the given byte sequence.
    NotContains(Vec<u8>),
}

impl ProtocolConstraint {
    /// Check whether `data` satisfies this constraint.
    #[must_use]
    pub fn check(&self, data: &[u8]) -> bool {
        match self {
            Self::MinLength(n) => data.len() >= *n,
            Self::MaxLength(n) => data.len() <= *n,
            Self::StartsWith(prefix) => data.starts_with(prefix),
            Self::EndsWith(suffix) => data.ends_with(suffix),
            Self::ByteAt { offset, value } => {
                data.get(*offset).copied() == Some(*value)
            }
            Self::LengthField { length_offset } => {
                if data.len() < *length_offset + 2 {
                    return false;
                }
                let len_field = u16::from_le_bytes([
                    data[*length_offset],
                    data[*length_offset + 1],
                ]) as usize;
                len_field == data.len()
            }
            Self::ChecksumByte { checksum_offset } => {
                if *checksum_offset >= data.len() {
                    return false;
                }
                let expected = data.iter().enumerate()
                    .filter(|(i, _)| i != checksum_offset)
                    .fold(0u8, |acc, (_, &b)| acc.wrapping_add(b));
                data[*checksum_offset] == expected
            }
            Self::NotContains(seq) => {
                if seq.is_empty() {
                    return true;
                }
                !data.windows(seq.len()).any(|w| w == seq.as_slice())
            }
        }
    }

    /// Apply this constraint to `data`, modifying it in-place to comply.
    ///
    /// Returns `true` if the data was modified.
    pub fn enforce(&self, data: &mut Vec<u8>) -> bool {
        match self {
            Self::MinLength(n) => {
                if data.len() < *n {
                    data.resize(*n, 0);
                    return true;
                }
                false
            }
            Self::MaxLength(n) => {
                if data.len() > *n {
                    data.truncate(*n);
                    return true;
                }
                false
            }
            Self::StartsWith(prefix) => {
                if !data.starts_with(prefix) {
                    let mut out = prefix.clone();
                    out.extend_from_slice(data);
                    *data = out;
                    return true;
                }
                false
            }
            Self::EndsWith(suffix) => {
                if !data.ends_with(suffix) {
                    data.extend_from_slice(suffix);
                    return true;
                }
                false
            }
            Self::ByteAt { offset, value } => {
                if *offset >= data.len() {
                    data.resize(*offset + 1, 0);
                }
                if data[*offset] != *value {
                    data[*offset] = *value;
                    return true;
                }
                false
            }
            Self::LengthField { length_offset } => {
                if data.len() < *length_offset + 2 {
                    data.resize(*length_offset + 2, 0);
                }
                let len = data.len() as u16;
                let bytes = len.to_le_bytes();
                if data[*length_offset] != bytes[0] || data[*length_offset + 1] != bytes[1] {
                    data[*length_offset] = bytes[0];
                    data[*length_offset + 1] = bytes[1];
                    return true;
                }
                false
            }
            Self::ChecksumByte { checksum_offset } => {
                if *checksum_offset >= data.len() {
                    data.resize(*checksum_offset + 1, 0);
                }
                let sum = data.iter().enumerate()
                    .filter(|(i, _)| i != checksum_offset)
                    .fold(0u8, |acc, (_, &b)| acc.wrapping_add(b));
                if data[*checksum_offset] != sum {
                    data[*checksum_offset] = sum;
                    return true;
                }
                false
            }
            Self::NotContains(_) => false, // cannot enforce by modification
        }
    }
}

// ── MessageGenerator ──────────────────────────────────────────────────────────

/// Generates messages by fuzzing fields of a [`MessageType`].
pub struct MessageGenerator {
    /// PRNG.
    rng: XorShiftRng,
    /// Whether to use interesting-value substitution.
    pub use_interesting: bool,
}

impl MessageGenerator {
    /// Create a new generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: XorShiftRng::new(seed),
            use_interesting: true,
        }
    }

    /// Generate a message of the given type.
    #[must_use]
    pub fn generate(&mut self, msg_type: &MessageType) -> Vec<u8> {
        let mut out = Vec::new();
        for field in &msg_type.fields {
            let bytes = self.generate_field(field);
            out.extend(bytes);
        }
        out
    }

    /// Generate bytes for a single field.
    fn generate_field(&mut self, field: &MessageField) -> Vec<u8> {
        match field {
            MessageField::Fixed { value, .. } => value.clone(),
            MessageField::Variable { min, max, fuzz, .. } => {
                if *fuzz {
                    self.generate_variable(*min, *max)
                } else {
                    vec![0u8; *min]
                }
            }
            MessageField::Enum { variants, allow_invalid, .. } => {
                if variants.is_empty() {
                    return Vec::new();
                }
                if *allow_invalid && self.rng.next_usize(8) == 0 {
                    // Generate an invalid (random) value.
                    let len = variants[0].len().max(1);
                    (0..len).map(|_| self.rng.next_u8()).collect()
                } else {
                    let idx = self.rng.next_usize(variants.len());
                    variants[idx].clone()
                }
            }
            MessageField::Nested { .. } => Vec::new(), // resolved at protocol level
            MessageField::LengthOf { width, .. } => vec![0u8; *width as usize],
        }
    }

    fn generate_variable(&mut self, min: usize, max: usize) -> Vec<u8> {
        let len = if max <= min {
            min
        } else {
            min + self.rng.next_usize(max - min + 1)
        };
        if self.use_interesting && len > 0 && self.rng.next_usize(4) == 0 {
            // Use an interesting byte sequence.
            (0..len)
                .map(|_| INTERESTING_U8[self.rng.next_usize(INTERESTING_U8.len())])
                .collect()
        } else {
            (0..len).map(|_| self.rng.next_u8()).collect()
        }
    }

    /// Generate `count` distinct messages.
    #[must_use]
    pub fn generate_many(&mut self, msg_type: &MessageType, count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|_| self.generate(msg_type)).collect()
    }

    /// Mutate an existing message byte buffer using the message type definition.
    #[must_use]
    pub fn mutate(&mut self, data: &[u8], msg_type: &MessageType) -> Vec<u8> {
        let fuzz_fields: Vec<&MessageField> = msg_type
            .fields
            .iter()
            .filter(|f| f.is_fuzz_target())
            .collect();

        if fuzz_fields.is_empty() || data.is_empty() {
            return data.to_vec();
        }

        let mut out = data.to_vec();
        let mutation_kind = self.rng.next_usize(5);
        match mutation_kind {
            0 => {
                // Bit flip
                let pos = self.rng.next_usize(out.len() * 8);
                out[pos / 8] ^= 1 << (pos % 8);
            }
            1 => {
                // Interesting byte
                let idx = self.rng.next_usize(out.len());
                out[idx] = INTERESTING_U8[self.rng.next_usize(INTERESTING_U8.len())];
            }
            2 if out.len() >= 2 => {
                // Interesting u16
                let idx = self.rng.next_usize(out.len() - 1);
                let val = INTERESTING_U16[self.rng.next_usize(INTERESTING_U16.len())];
                let b = val.to_le_bytes();
                out[idx] = b[0];
                out[idx + 1] = b[1];
            }
            3 if out.len() >= 4 => {
                // Interesting u32
                let idx = self.rng.next_usize(out.len() - 3);
                let val = INTERESTING_U32[self.rng.next_usize(INTERESTING_U32.len())];
                let b = val.to_le_bytes();
                out[idx..idx + 4].copy_from_slice(&b);
            }
            _ => {
                // Random byte replacement
                let idx = self.rng.next_usize(out.len());
                out[idx] = self.rng.next_u8();
            }
        }
        out
    }
}

// ── ValidMessageFilter ────────────────────────────────────────────────────────

/// Filters generated messages to ensure they satisfy a list of constraints.
pub struct ValidMessageFilter {
    /// Constraints that all messages must satisfy.
    pub constraints: Vec<ProtocolConstraint>,
    /// Whether to auto-fix messages rather than discard them.
    pub auto_fix: bool,
}

impl ValidMessageFilter {
    /// Create a new filter with the given constraints.
    #[must_use]
    pub fn new(constraints: Vec<ProtocolConstraint>) -> Self {
        Self {
            constraints,
            auto_fix: false,
        }
    }

    /// Create an auto-fixing filter.
    #[must_use]
    pub fn auto_fix(constraints: Vec<ProtocolConstraint>) -> Self {
        Self {
            constraints,
            auto_fix: true,
        }
    }

    /// Check whether `data` satisfies all constraints.
    #[must_use]
    pub fn is_valid(&self, data: &[u8]) -> bool {
        self.constraints.iter().all(|c| c.check(data))
    }

    /// Try to fix `data` to satisfy constraints if `auto_fix` is set.
    ///
    /// Returns `true` when the message is valid after (optional) fixing.
    pub fn fix_or_check(&self, data: &mut Vec<u8>) -> bool {
        if self.auto_fix {
            for c in &self.constraints {
                c.enforce(data);
            }
        }
        self.is_valid(data)
    }

    /// Filter a list of messages to only those that pass all constraints.
    #[must_use]
    pub fn filter(&self, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        messages.into_iter().filter(|m| self.is_valid(m)).collect()
    }

    /// Filter-and-fix a list of messages, returning all that pass after fixing.
    pub fn filter_and_fix(&self, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        for mut m in messages {
            if self.fix_or_check(&mut m) {
                result.push(m);
            }
        }
        result
    }
}

// ── ProtocolModel ─────────────────────────────────────────────────────────────

/// The top-level protocol model registry, mapping type names to
/// [`MessageType`] definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolModel {
    /// All registered message types by name.
    pub message_types: HashMap<String, MessageType>,
    /// Protocol name.
    pub name: String,
    /// Protocol version string.
    pub version: String,
    /// When this model was created.
    pub created_at: SystemTime,
}

impl Default for ProtocolModel {
    fn default() -> Self {
        Self {
            message_types: HashMap::new(),
            name: String::new(),
            version: String::new(),
            created_at: std::time::UNIX_EPOCH,
        }
    }
}

impl ProtocolModel {
    /// Create a new protocol model.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            message_types: HashMap::new(),
            name: name.into(),
            version: "1.0".to_string(),
            created_at: SystemTime::now(),
        }
    }

    /// Register a message type.
    pub fn add_type(&mut self, msg_type: MessageType) {
        self.message_types.insert(msg_type.name.clone(), msg_type);
    }

    /// Look up a message type by name.
    #[must_use]
    pub fn get_type(&self, name: &str) -> Option<&MessageType> {
        self.message_types.get(name)
    }

    /// Number of registered message types.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.message_types.len()
    }

    /// Serialize this model to a JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a model from a JSON string.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Save this model to a JSON file at `path`.
    ///
    /// # Errors
    /// Returns an I/O error if the file cannot be written, or a serialization
    /// error if the model cannot be encoded.
    pub fn save_to_file(&self, path: &Path) -> Result<(), io::Error> {
        let json = self.to_json().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load a model from a JSON file at `path`.
    ///
    /// # Errors
    /// Returns an I/O error if the file cannot be read, or a deserialization
    /// error if the JSON is malformed.
    pub fn load_from_file(path: &Path) -> Result<Self, io::Error> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Return all type names in sorted order.
    #[must_use]
    pub fn type_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.message_types.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Validate all message type cross-references (nested field references).
    ///
    /// Returns a list of validation errors (empty = valid).
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (type_name, msg_type) in &self.message_types {
            for field in &msg_type.fields {
                if let MessageField::Nested { message_type, .. } = field {
                    if !self.message_types.contains_key(message_type.as_str()) {
                        errors.push(format!(
                            "type '{}' field '{}' references unknown type '{}'",
                            type_name,
                            field.name(),
                            message_type
                        ));
                    }
                }
                if let MessageField::LengthOf { target_field, .. } = field {
                    if !msg_type.fields.iter().any(|f| f.name() == target_field.as_str()) {
                        errors.push(format!(
                            "type '{}' LengthOf field '{}' references unknown field '{}'",
                            type_name,
                            field.name(),
                            target_field
                        ));
                    }
                }
            }
        }
        errors
    }
}

// ── ModelFuzzer ───────────────────────────────────────────────────────────────

/// Drives a fuzzing session against a [`ProtocolModel`].
pub struct ModelFuzzer {
    /// The protocol model.
    pub model: ProtocolModel,
    /// Message generator.
    pub generator: MessageGenerator,
    /// Message validity filter.
    pub filter: ValidMessageFilter,
    /// Total messages generated.
    pub total_generated: u64,
    /// Total messages passing the filter.
    pub total_valid: u64,
    /// History of generated messages (capped at `max_history`).
    pub history: Vec<Vec<u8>>,
    /// Maximum history entries.
    pub max_history: usize,
}

impl ModelFuzzer {
    /// Create a new fuzzer.
    #[must_use]
    pub fn new(model: ProtocolModel, seed: u64) -> Self {
        Self {
            model,
            generator: MessageGenerator::new(seed),
            filter: ValidMessageFilter::new(Vec::new()),
            total_generated: 0,
            total_valid: 0,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Set constraints on the filter.
    pub fn set_constraints(&mut self, constraints: Vec<ProtocolConstraint>) {
        self.filter = ValidMessageFilter::new(constraints);
    }

    /// Generate `count` messages of the named type.
    ///
    /// Returns only messages that pass the filter.
    #[must_use]
    pub fn generate(&mut self, type_name: &str, count: usize) -> Vec<Vec<u8>> {
        let msg_type = match self.model.get_type(type_name) {
            Some(t) => t.clone(),
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        for _ in 0..count {
            let mut msg = self.generator.generate(&msg_type);
            self.total_generated += 1;
            if self.filter.fix_or_check(&mut msg) {
                self.total_valid += 1;
                results.push(msg.clone());
                if self.history.len() < self.max_history {
                    self.history.push(msg);
                }
            }
        }
        results
    }

    /// Mutate an existing message of the named type.
    #[must_use]
    pub fn mutate(&mut self, type_name: &str, data: &[u8]) -> Vec<u8> {
        let msg_type = match self.model.get_type(type_name) {
            Some(t) => t.clone(),
            None => return data.to_vec(),
        };
        self.generator.mutate(data, &msg_type)
    }

    /// Valid-message ratio (0.0–1.0).
    #[must_use]
    pub fn validity_ratio(&self) -> f64 {
        if self.total_generated == 0 {
            0.0
        } else {
            self.total_valid as f64 / self.total_generated as f64
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_model() -> ProtocolModel {
        let mut model = ProtocolModel::new("TestProto");
        let msg = MessageType::new(
            "PING",
            vec![
                MessageField::Fixed {
                    name: "magic".to_string(),
                    value: b"PING".to_vec(),
                },
                MessageField::Variable {
                    name: "payload".to_string(),
                    min: 0,
                    max: 16,
                    fuzz: true,
                },
            ],
        )
        .with_magic(b"PING".to_vec());
        model.add_type(msg);
        model
    }

    // ── MessageField ─────────────────────────────────────────────────────────

    #[test]
    fn fixed_field_name_and_not_fuzz() {
        let f = MessageField::Fixed { name: "hdr".to_string(), value: vec![1, 2] };
        assert_eq!(f.name(), "hdr");
        assert!(!f.is_fuzz_target());
    }

    #[test]
    fn variable_field_fuzz_flag() {
        let f = MessageField::Variable { name: "body".to_string(), min: 4, max: 16, fuzz: true };
        assert!(f.is_fuzz_target());
    }

    #[test]
    fn enum_field_default_bytes() {
        let f = MessageField::Enum {
            name: "cmd".to_string(),
            variants: vec![vec![0x01], vec![0x02]],
            allow_invalid: false,
        };
        assert_eq!(f.default_bytes(), vec![0x01]);
    }

    #[test]
    fn fixed_field_default_bytes() {
        let f = MessageField::Fixed { name: "m".to_string(), value: b"PING".to_vec() };
        assert_eq!(f.default_bytes(), b"PING");
    }

    #[test]
    fn length_of_field_default_bytes() {
        let f = MessageField::LengthOf { name: "len".to_string(), target_field: "body".to_string(), width: 2 };
        assert_eq!(f.default_bytes(), vec![0u8, 0]);
    }

    // ── MessageType ───────────────────────────────────────────────────────────

    #[test]
    fn message_type_validate_too_short() {
        let mt = MessageType::new("X", vec![]).with_magic(b"XXXX".to_vec());
        assert!(!mt.validate(&[1, 2]));
    }

    #[test]
    fn message_type_validate_wrong_magic() {
        let mt = MessageType::new("X", vec![]).with_magic(b"XXXX".to_vec());
        assert!(!mt.validate(b"YYYY"));
    }

    #[test]
    fn message_type_validate_ok() {
        let mt = MessageType::new("X", vec![]).with_magic(b"PING".to_vec());
        assert!(mt.validate(b"PING extra data"));
    }

    #[test]
    fn message_type_field_count() {
        let mt = simple_model().message_types.remove("PING").unwrap();
        assert_eq!(mt.field_count(), 2);
    }

    #[test]
    fn message_type_default_bytes_starts_with_magic() {
        let model = simple_model();
        let mt = model.get_type("PING").unwrap();
        let bytes = mt.default_bytes();
        assert!(bytes.starts_with(b"PING"));
    }

    // ── ProtocolConstraint ────────────────────────────────────────────────────

    #[test]
    fn constraint_min_length() {
        let c = ProtocolConstraint::MinLength(4);
        assert!(c.check(b"ABCD"));
        assert!(!c.check(b"AB"));
    }

    #[test]
    fn constraint_max_length() {
        let c = ProtocolConstraint::MaxLength(4);
        assert!(c.check(b"AB"));
        assert!(!c.check(b"ABCDE"));
    }

    #[test]
    fn constraint_starts_with() {
        let c = ProtocolConstraint::StartsWith(b"PING".to_vec());
        assert!(c.check(b"PING payload"));
        assert!(!c.check(b"PONG payload"));
    }

    #[test]
    fn constraint_ends_with() {
        let c = ProtocolConstraint::EndsWith(b"\r\n".to_vec());
        assert!(c.check(b"data\r\n"));
        assert!(!c.check(b"data\n"));
    }

    #[test]
    fn constraint_byte_at() {
        let c = ProtocolConstraint::ByteAt { offset: 2, value: 0xFF };
        assert!(c.check(&[0, 0, 0xFF, 0]));
        assert!(!c.check(&[0, 0, 0, 0]));
    }

    #[test]
    fn constraint_not_contains() {
        let c = ProtocolConstraint::NotContains(b"BAD".to_vec());
        assert!(c.check(b"GOOD DATA"));
        assert!(!c.check(b"THIS IS BAD"));
    }

    #[test]
    fn constraint_checksum_byte_valid() {
        // sum of all bytes except position 3 = 0x01 + 0x02 + 0x03 = 0x06
        let data = vec![0x01u8, 0x02, 0x03, 0x06];
        let c = ProtocolConstraint::ChecksumByte { checksum_offset: 3 };
        assert!(c.check(&data));
    }

    #[test]
    fn constraint_checksum_byte_invalid() {
        let data = vec![0x01u8, 0x02, 0x03, 0xFF];
        let c = ProtocolConstraint::ChecksumByte { checksum_offset: 3 };
        assert!(!c.check(&data));
    }

    #[test]
    fn constraint_enforce_min_length() {
        let c = ProtocolConstraint::MinLength(8);
        let mut data = vec![1u8, 2, 3];
        let changed = c.enforce(&mut data);
        assert!(changed);
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn constraint_enforce_max_length() {
        let c = ProtocolConstraint::MaxLength(4);
        let mut data = vec![1u8; 8];
        c.enforce(&mut data);
        assert_eq!(data.len(), 4);
    }

    // ── MessageGenerator ──────────────────────────────────────────────────────

    #[test]
    fn generator_generates_message() {
        let model = simple_model();
        let mt = model.get_type("PING").unwrap();
        let mut generator = MessageGenerator::new(1);
        let msg = generator.generate(mt);
        assert!(msg.starts_with(b"PING"));
    }

    #[test]
    fn generator_generate_many() {
        let model = simple_model();
        let mt = model.get_type("PING").unwrap();
        let mut generator = MessageGenerator::new(2);
        let msgs = generator.generate_many(mt, 5);
        assert_eq!(msgs.len(), 5);
    }

    #[test]
    fn generator_mutate_different_from_input() {
        let model = simple_model();
        let mt = model.get_type("PING").unwrap();
        let mut generator = MessageGenerator::new(3);
        let input = b"PING\x00\x00\x00\x00".to_vec();
        let mut found_diff = false;
        for _ in 0..20 {
            let out = generator.mutate(&input, mt);
            if out != input {
                found_diff = true;
                break;
            }
        }
        assert!(found_diff);
    }

    // ── ValidMessageFilter ────────────────────────────────────────────────────

    #[test]
    fn filter_passes_valid() {
        let f = ValidMessageFilter::new(vec![ProtocolConstraint::MinLength(4)]);
        assert!(f.is_valid(b"PING"));
    }

    #[test]
    fn filter_rejects_invalid() {
        let f = ValidMessageFilter::new(vec![ProtocolConstraint::MinLength(8)]);
        assert!(!f.is_valid(b"PING"));
    }

    #[test]
    fn filter_auto_fix_applies() {
        let f = ValidMessageFilter::auto_fix(vec![ProtocolConstraint::StartsWith(b"PING".to_vec())]);
        let mut data = b"PONG".to_vec();
        let ok = f.fix_or_check(&mut data);
        assert!(ok);
        assert!(data.starts_with(b"PING"));
    }

    #[test]
    fn filter_batch() {
        let f = ValidMessageFilter::new(vec![ProtocolConstraint::MinLength(3)]);
        let msgs = vec![b"AB".to_vec(), b"ABC".to_vec(), b"ABCD".to_vec()];
        let valid = f.filter(msgs);
        assert_eq!(valid.len(), 2);
    }

    // ── ProtocolModel ─────────────────────────────────────────────────────────

    #[test]
    fn protocol_model_type_count() {
        let model = simple_model();
        assert_eq!(model.type_count(), 1);
    }

    #[test]
    fn protocol_model_get_type() {
        let model = simple_model();
        assert!(model.get_type("PING").is_some());
        assert!(model.get_type("PONG").is_none());
    }

    #[test]
    fn protocol_model_type_names_sorted() {
        let mut model = ProtocolModel::new("P");
        model.add_type(MessageType::new("Z", vec![]));
        model.add_type(MessageType::new("A", vec![]));
        let names = model.type_names();
        assert_eq!(names[0], "A");
        assert_eq!(names[1], "Z");
    }

    #[test]
    fn protocol_model_validate_ok() {
        let model = simple_model();
        assert!(model.validate().is_empty());
    }

    #[test]
    fn protocol_model_validate_detects_bad_nested_ref() {
        let mut model = ProtocolModel::new("P");
        model.add_type(MessageType::new(
            "MSG",
            vec![MessageField::Nested {
                name: "n".to_string(),
                message_type: "NONEXISTENT".to_string(),
            }],
        ));
        let errors = model.validate();
        assert!(!errors.is_empty());
    }

    // ── ModelFuzzer ───────────────────────────────────────────────────────────

    #[test]
    fn model_fuzzer_generate_passes_magic() {
        let model = simple_model();
        let mut fuzzer = ModelFuzzer::new(model, 42);
        let msgs = fuzzer.generate("PING", 10);
        for m in &msgs {
            assert!(m.starts_with(b"PING"), "message did not start with PING: {:?}", m);
        }
    }

    #[test]
    fn model_fuzzer_unknown_type_empty() {
        let model = simple_model();
        let mut fuzzer = ModelFuzzer::new(model, 1);
        let msgs = fuzzer.generate("UNKNOWN", 5);
        assert!(msgs.is_empty());
    }

    #[test]
    fn model_fuzzer_validity_ratio() {
        let model = simple_model();
        let mut fuzzer = ModelFuzzer::new(model, 1);
        let _ = fuzzer.generate("PING", 20);
        let ratio = fuzzer.validity_ratio();
        assert!(ratio >= 0.0 && ratio <= 1.0);
    }

    #[test]
    fn model_fuzzer_mutate_nonnull() {
        let model = simple_model();
        let mut fuzzer = ModelFuzzer::new(model, 5);
        let input = b"PING\x00\x00".to_vec();
        let out = fuzzer.mutate("PING", &input);
        assert!(!out.is_empty());
    }

    #[test]
    fn model_fuzzer_history_capped() {
        let model = simple_model();
        let mut fuzzer = ModelFuzzer::new(model, 7);
        fuzzer.max_history = 5;
        let _ = fuzzer.generate("PING", 20);
        assert!(fuzzer.history.len() <= 5);
    }
}
