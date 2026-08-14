//! `resource_editor` — Edit .NET manifest resources: add/remove/replace
//! embedded resources, `ResourceEditor`, `ResourceEntry`, serialize back to
//! binary (the manifest resource data stream).

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// ─── ResourceKind ─────────────────────────────────────────────────────────────

/// The kind/origin of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind {
    /// Embedded directly in the assembly.
    Embedded,
    /// Linked from an external file.
    Linked,
    /// Stored in another assembly.
    Assembly,
}

impl ResourceKind {
    /// The ECMA-335 Implementation coded-index tag.
    #[must_use]
    pub const fn implementation_tag(self) -> u32 {
        match self {
            // no Implementation row
            Self::Embedded | Self::Linked => 0x00,
            Self::Assembly => 0x01,
        }
    }
}

// ─── ResourceFlags ────────────────────────────────────────────────────────────

/// Visibility flags for a manifest resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceFlags {
    /// Public resource.
    Public,
    /// Private resource.
    Private,
}

impl ResourceFlags {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Public => 0x00000001,
            Self::Private => 0x00000002,
        }
    }
}

// ─── ResourceEntry ────────────────────────────────────────────────────────────

/// A single manifest resource entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Resource name (UTF-8).
    pub name: String,
    /// Visibility flags.
    pub flags: ResourceFlags,
    /// Kind of resource (embedded vs linked vs assembly).
    pub kind: ResourceKind,
    /// Embedded data (empty for linked/assembly resources).
    pub data: Vec<u8>,
    /// For linked resources: the file name.
    pub linked_file: Option<String>,
    /// Whether this entry has been modified since loading.
    pub dirty: bool,
}

impl ResourceEntry {
    /// Create an embedded public resource.
    #[must_use]
    pub fn embedded(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            flags: ResourceFlags::Public,
            kind: ResourceKind::Embedded,
            data,
            linked_file: None,
            dirty: false,
        }
    }

    /// Create an embedded private resource.
    #[must_use]
    pub fn embedded_private(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            flags: ResourceFlags::Private,
            kind: ResourceKind::Embedded,
            data,
            linked_file: None,
            dirty: false,
        }
    }

    /// Create a linked resource entry.
    #[must_use]
    pub fn linked(name: impl Into<String>, file: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: ResourceFlags::Public,
            kind: ResourceKind::Linked,
            data: Vec::new(),
            linked_file: Some(file.into()),
            dirty: false,
        }
    }

    /// Size of the embedded data in bytes.
    #[must_use]
    pub const fn data_size(&self) -> usize {
        self.data.len()
    }

    /// Serialise as a length-prefixed blob (4-byte LE length + data).
    #[must_use]
    pub fn to_length_prefixed_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialise from a length-prefixed blob.
    ///
    /// # Errors
    /// Returns an error if the blob is too short.
    pub fn from_length_prefixed_blob(
        name: impl Into<String>,
        blob: &[u8],
    ) -> Result<Self> {
        if blob.len() < 4 {
            return Err(anyhow!("resource blob too short: {} bytes", blob.len()));
        }
        let len = u32::from_le_bytes(blob[..4].try_into()?) as usize;
        if blob.len() < 4 + len {
            return Err(anyhow!(
                "resource blob truncated: expected {} bytes after header, got {}",
                len,
                blob.len() - 4
            ));
        }
        Ok(Self::embedded(name, blob[4..4 + len].to_vec()))
    }

    /// Attempt to detect the MIME type of the embedded data.
    #[must_use]
    pub fn detect_mime(&self) -> &'static str {
        let d = &self.data;
        if d.starts_with(b"\x89PNG") {
            "image/png"
        } else if d.starts_with(b"\xff\xd8\xff") {
            "image/jpeg"
        } else if d.starts_with(b"PK\x03\x04") {
            "application/zip"
        } else if d.starts_with(b"GIF8") {
            "image/gif"
        } else if d.starts_with(b"BM") {
            "image/bmp"
        } else if d.starts_with(b"RIFF") && d.len() >= 12 && &d[8..12] == b"WAVE" {
            "audio/wav"
        } else if d.starts_with(b"<?xml") || d.starts_with(b"<") {
            "text/xml"
        } else if d.is_empty() {
            "application/octet-stream"
        } else {
            "application/octet-stream"
        }
    }

    /// Compute the Adler-32 checksum of the data.
    #[must_use]
    pub fn checksum_adler32(&self) -> u32 {
        adler32(&self.data)
    }
}

// ─── ResourceDiff ─────────────────────────────────────────────────────────────

/// A record of what changed about a resource during editing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceChange {
    Added { name: String, size: usize },
    Removed { name: String },
    Replaced { name: String, old_size: usize, new_size: usize },
    FlagsChanged { name: String, old_flags: u32, new_flags: u32 },
}

// ─── ResourceSerializer ───────────────────────────────────────────────────────

/// Serialises a collection of resource entries into the binary format expected
/// by the .NET metadata #BLOB / #Strings streams and `ManifestResource` table.
pub struct ResourceSerializer;

impl ResourceSerializer {
    /// Serialise a list of [`ResourceEntry`]s into a compact binary stream.
    ///
    /// Format:
    /// - 4 bytes: number of resources (LE)
    /// - For each resource:
    ///   - 4 bytes: flags (LE)
    ///   - 2 bytes: name length (LE)
    ///   - N bytes: name (UTF-8)
    ///   - 4 bytes: data length (LE)
    ///   - M bytes: data
    #[must_use]
    pub fn serialize(entries: &[ResourceEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            out.extend_from_slice(&entry.flags.bits().to_le_bytes());
            let name_bytes = entry.name.as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&entry.data);
        }
        out
    }

    /// Deserialise from the binary stream produced by [`serialize`].
    ///
    /// # Errors
    /// Returns an error if the stream is malformed.
    pub fn deserialize(data: &[u8]) -> Result<Vec<ResourceEntry>> {
        if data.len() < 4 {
            return Err(anyhow!("stream too short"));
        }
        let count = u32::from_le_bytes(data[..4].try_into()?) as usize;
        let mut pos = 4;
        // dos-memory-exhaustion: `count` comes from untrusted input; cap the
        // pre-allocation so a malicious stream with count=u32::MAX cannot exhaust
        // memory before the parsing loop validates every entry.
        let mut entries = Vec::with_capacity(count.min(1024));

        for _ in 0..count {
            if pos + 4 > data.len() {
                return Err(anyhow!("stream truncated at flags"));
            }
            let flags_raw = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
            pos += 4;

            let flags = if flags_raw & 0x01 != 0 {
                ResourceFlags::Public
            } else {
                ResourceFlags::Private
            };

            if pos + 2 > data.len() {
                return Err(anyhow!("stream truncated at name length"));
            }
            let name_len = u16::from_le_bytes(data[pos..pos + 2].try_into()?) as usize;
            pos += 2;

            if pos + name_len > data.len() {
                return Err(anyhow!("stream truncated at name"));
            }
            let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
            pos += name_len;

            if pos + 4 > data.len() {
                return Err(anyhow!("stream truncated at data length"));
            }
            let data_len = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as usize;
            pos += 4;

            if pos + data_len > data.len() {
                return Err(anyhow!("stream truncated at data"));
            }
            let resource_data = data[pos..pos + data_len].to_vec();
            pos += data_len;

            entries.push(ResourceEntry {
                name,
                flags,
                kind: ResourceKind::Embedded,
                data: resource_data,
                linked_file: None,
                dirty: false,
            });
        }

        Ok(entries)
    }
}

// ─── ResourceEditor ──────────────────────────────────────────────────────────

/// Editor for .NET manifest resources.
///
/// Provides add/remove/replace/rename operations and can serialise the
/// modified resource set back to binary.
pub struct ResourceEditor {
    /// Resources ordered by original index.
    resources: Vec<ResourceEntry>,
    /// Quick name lookup.
    name_map: HashMap<String, usize>,
    /// Change log.
    changes: Vec<ResourceChange>,
}

impl ResourceEditor {
    /// Create an empty editor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            name_map: HashMap::new(),
            changes: Vec::new(),
        }
    }

    /// Load resources from a binary stream produced by [`ResourceSerializer::serialize`].
    ///
    /// # Errors
    /// Returns an error if the stream is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let entries = ResourceSerializer::deserialize(data)?;
        let mut ed = Self::new();
        for entry in entries {
            ed.add_internal(entry);
        }
        Ok(ed)
    }

    /// Load a single embedded resource from a raw data blob.
    ///
    /// # Errors
    /// Returns an error if a resource with the same name already exists.
    pub fn load_entry(&mut self, entry: ResourceEntry) -> Result<()> {
        if self.name_map.contains_key(&entry.name) {
            return Err(anyhow!("resource '{}' already exists", entry.name));
        }
        self.add_internal(entry);
        Ok(())
    }

    fn add_internal(&mut self, entry: ResourceEntry) {
        let idx = self.resources.len();
        self.name_map.insert(entry.name.clone(), idx);
        self.resources.push(entry);
    }

    // ── CRUD operations ───────────────────────────────────────────────────────

    /// Add a new resource.
    ///
    /// # Errors
    /// Returns an error if a resource with the same name already exists.
    pub fn add(&mut self, entry: ResourceEntry) -> Result<()> {
        if self.name_map.contains_key(&entry.name) {
            return Err(anyhow!("resource '{}' already exists", entry.name));
        }
        let name = entry.name.clone();
        let size = entry.data.len();
        self.add_internal(entry);
        self.changes.push(ResourceChange::Added { name, size });
        Ok(())
    }

    /// Remove a resource by name.
    ///
    /// # Errors
    /// Returns an error if the resource does not exist.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let idx = self
            .name_map
            .remove(name)
            .ok_or_else(|| anyhow!("resource '{name}' not found"))?;
        let entry = self.resources.remove(idx);
        // Rebuild name map
        self.name_map.clear();
        for (i, r) in self.resources.iter().enumerate() {
            self.name_map.insert(r.name.clone(), i);
        }
        self.changes.push(ResourceChange::Removed { name: entry.name });
        Ok(())
    }

    /// Replace the data for an existing resource.
    ///
    /// # Errors
    /// Returns an error if the resource does not exist.
    pub fn replace(&mut self, name: &str, new_data: Vec<u8>) -> Result<()> {
        let idx = *self
            .name_map
            .get(name)
            .ok_or_else(|| anyhow!("resource '{name}' not found"))?;
        let entry = &mut self.resources[idx];
        let old_size = entry.data.len();
        let new_size = new_data.len();
        entry.data = new_data;
        entry.dirty = true;
        self.changes.push(ResourceChange::Replaced {
            name: name.to_owned(),
            old_size,
            new_size,
        });
        Ok(())
    }

    /// Rename a resource.
    ///
    /// # Errors
    /// Returns an error if the old name does not exist or the new name is already taken.
    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        if self.name_map.contains_key(new_name) {
            return Err(anyhow!("resource '{new_name}' already exists"));
        }
        let idx = self
            .name_map
            .remove(old_name)
            .ok_or_else(|| anyhow!("resource '{old_name}' not found"))?;
        self.resources[idx].name = new_name.to_owned();
        self.resources[idx].dirty = true;
        self.name_map.insert(new_name.to_owned(), idx);
        Ok(())
    }

    /// Set the visibility flags for a resource.
    ///
    /// # Errors
    /// Returns an error if the resource does not exist.
    pub fn set_flags(&mut self, name: &str, flags: ResourceFlags) -> Result<()> {
        let idx = *self
            .name_map
            .get(name)
            .ok_or_else(|| anyhow!("resource '{name}' not found"))?;
        let entry = &mut self.resources[idx];
        let old = entry.flags.bits();
        entry.flags = flags;
        entry.dirty = true;
        self.changes.push(ResourceChange::FlagsChanged {
            name: name.to_owned(),
            old_flags: old,
            new_flags: flags.bits(),
        });
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Look up a resource by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ResourceEntry> {
        let idx = *self.name_map.get(name)?;
        self.resources.get(idx)
    }

    /// All resource entries in order.
    #[must_use]
    pub fn entries(&self) -> &[ResourceEntry] {
        &self.resources
    }

    /// Number of resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// Returns `true` if there are no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// All resource names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.resources.iter().map(|r| r.name.as_str()).collect()
    }

    /// Returns `true` if a resource with the given name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.name_map.contains_key(name)
    }

    /// Total size of all embedded data.
    #[must_use]
    pub fn total_data_size(&self) -> usize {
        self.resources.iter().map(|r| r.data.len()).sum()
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Serialise all resources to the binary stream format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        ResourceSerializer::serialize(&self.resources)
    }

    /// Change log since the editor was created.
    #[must_use]
    pub fn changes(&self) -> &[ResourceChange] {
        &self.changes
    }

    /// Whether any resource has been modified.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Mark all resources as clean.
    pub fn clear_dirty(&mut self) {
        for r in &mut self.resources {
            r.dirty = false;
        }
        self.changes.clear();
    }

    // ── Bulk operations ───────────────────────────────────────────────────────

    /// Remove all resources matching a predicate.
    pub fn retain<F: Fn(&ResourceEntry) -> bool>(&mut self, predicate: F) {
        let to_remove: Vec<String> = self
            .resources
            .iter()
            .filter(|r| !predicate(r))
            .map(|r| r.name.clone())
            .collect();
        for name in to_remove {
            let _ = self.remove(&name);
        }
    }

    /// Sort resources by name.
    pub fn sort_by_name(&mut self) {
        self.resources.sort_by(|a, b| a.name.cmp(&b.name));
        self.name_map.clear();
        for (i, r) in self.resources.iter().enumerate() {
            self.name_map.insert(r.name.clone(), i);
        }
    }

    /// Find resources whose data starts with `magic`.
    #[must_use]
    pub fn find_by_magic(&self, magic: &[u8]) -> Vec<&ResourceEntry> {
        self.resources
            .iter()
            .filter(|r| r.data.starts_with(magic))
            .collect()
    }

    /// Find resources whose detected MIME type matches.
    #[must_use]
    pub fn find_by_mime(&self, mime: &str) -> Vec<&ResourceEntry> {
        self.resources
            .iter()
            .filter(|r| r.detect_mime() == mime)
            .collect()
    }
}

impl Default for ResourceEditor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Adler-32 ─────────────────────────────────────────────────────────────────

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

// ─── ResourceEntryBuilder ─────────────────────────────────────────────────────

/// Fluent builder for [`ResourceEntry`].
pub struct ResourceEntryBuilder {
    name: String,
    flags: ResourceFlags,
    kind: ResourceKind,
    data: Vec<u8>,
    linked_file: Option<String>,
}

impl ResourceEntryBuilder {
    /// Start building a resource with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: ResourceFlags::Public,
            kind: ResourceKind::Embedded,
            data: Vec::new(),
            linked_file: None,
        }
    }

    /// Set data.
    #[must_use]
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set private visibility.
    #[must_use]
    pub const fn private(mut self) -> Self {
        self.flags = ResourceFlags::Private;
        self
    }

    /// Set public visibility.
    #[must_use]
    pub const fn public(mut self) -> Self {
        self.flags = ResourceFlags::Public;
        self
    }

    /// Set as linked resource.
    #[must_use]
    pub fn linked(mut self, file: impl Into<String>) -> Self {
        self.kind = ResourceKind::Linked;
        self.linked_file = Some(file.into());
        self
    }

    /// Finalise into a [`ResourceEntry`].
    #[must_use]
    pub fn build(self) -> ResourceEntry {
        ResourceEntry {
            name: self.name,
            flags: self.flags,
            kind: self.kind,
            data: self.data,
            linked_file: self.linked_file,
            dirty: false,
        }
    }
}
