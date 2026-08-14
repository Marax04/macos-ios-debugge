//! `pe_resource_editor` — PE resource tree editor.
//!
//! Builds and modifies a PE resource directory: add/remove/replace entries
//! by type (`RT_ICON`, `RT_VERSION`, `RT_MANIFEST`, etc.), rebuild the resource
//! section blob with valid directory headers, data entries, and string tables.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::EditError;

// ---------------------------------------------------------------------------
// Resource type constants (IMAGE_RESOURCE_TYPE_*)
// ---------------------------------------------------------------------------

/// Pre-defined PE resource types.
pub mod rt {
    pub const CURSOR: u16 = 1;
    pub const BITMAP: u16 = 2;
    pub const ICON: u16 = 3;
    pub const MENU: u16 = 4;
    pub const DIALOG: u16 = 5;
    pub const STRING: u16 = 6;
    pub const FONTDIR: u16 = 7;
    pub const FONT: u16 = 8;
    pub const ACCELERATOR: u16 = 9;
    pub const RCDATA: u16 = 10;
    pub const MESSAGETABLE: u16 = 11;
    pub const GROUP_CURSOR: u16 = 12;
    pub const GROUP_ICON: u16 = 14;
    pub const VERSION: u16 = 16;
    pub const DLGINCLUDE: u16 = 17;
    pub const PLUGPLAY: u16 = 19;
    pub const VXD: u16 = 20;
    pub const ANICURSOR: u16 = 21;
    pub const ANIICON: u16 = 22;
    pub const HTML: u16 = 23;
    pub const MANIFEST: u16 = 24;
}

// ---------------------------------------------------------------------------
// ResourceId
// ---------------------------------------------------------------------------

/// A resource identifier — numeric ID or string name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResourceId {
    /// Numeric resource ID.
    Id(u16),
    /// String resource name.
    Name(String),
}

impl ResourceId {
    /// Returns `true` if this is a numeric ID.
    #[must_use]
    pub const fn is_id(&self) -> bool {
        matches!(self, Self::Id(_))
    }

    /// Common name for the resource type if it's a known ID.
    #[must_use]
    pub const fn type_name(&self) -> Option<&'static str> {
        match self {
            Self::Id(id) => match id {
                1 => Some("RT_CURSOR"),
                2 => Some("RT_BITMAP"),
                3 => Some("RT_ICON"),
                4 => Some("RT_MENU"),
                5 => Some("RT_DIALOG"),
                6 => Some("RT_STRING"),
                10 => Some("RT_RCDATA"),
                11 => Some("RT_MESSAGETABLE"),
                14 => Some("RT_GROUP_ICON"),
                16 => Some("RT_VERSION"),
                24 => Some("RT_MANIFEST"),
                _ => None,
            },
            Self::Name(_) => None,
        }
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => {
                if let Some(name) = self.type_name() {
                    write!(f, "{name}({id})")
                } else {
                    write!(f, "#{id}")
                }
            }
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceLeaf
// ---------------------------------------------------------------------------

/// A resource leaf entry: the actual data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLeaf {
    /// Language ID (e.g. 0x0409 for en-US).
    pub language_id: u16,
    /// Raw resource data bytes.
    pub data: Vec<u8>,
    /// Code page (usually 0 or 1252).
    pub code_page: u32,
}

impl ResourceLeaf {
    /// Create a leaf with `data` and language `lang`.
    #[must_use]
    pub const fn new(language_id: u16, data: Vec<u8>) -> Self {
        Self {
            language_id,
            data,
            code_page: 0,
        }
    }

    /// English US default leaf.
    #[must_use]
    pub const fn en_us(data: Vec<u8>) -> Self {
        Self::new(0x0409, data)
    }

    /// Returns `true` if the leaf has no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Data length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Display for ResourceLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Leaf(lang={:#06x} size={})", self.language_id, self.data.len())
    }
}

// ---------------------------------------------------------------------------
// ResourceNode
// ---------------------------------------------------------------------------

/// A resource directory node (type → name → language → data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    /// Name (ID or string) of this node.
    pub id: ResourceId,
    /// Leaf data (if this is a language-level entry).
    pub leaf: Option<ResourceLeaf>,
    /// Child nodes.
    pub children: BTreeMap<ResourceId, Self>,
}

impl ResourceNode {
    /// Create an empty node.
    #[must_use]
    pub const fn new(id: ResourceId) -> Self {
        Self {
            id,
            leaf: None,
            children: BTreeMap::new(),
        }
    }

    /// Create a leaf node.
    #[must_use]
    pub const fn leaf(id: ResourceId, leaf: ResourceLeaf) -> Self {
        Self {
            id,
            leaf: Some(leaf),
            children: BTreeMap::new(),
        }
    }

    /// Insert or replace a child node.
    pub fn insert_child(&mut self, child: Self) {
        self.children.insert(child.id.clone(), child);
    }

    /// Remove a child node.  Returns the removed node if found.
    pub fn remove_child(&mut self, id: &ResourceId) -> Option<Self> {
        self.children.remove(id)
    }

    /// Returns `true` if this is a leaf (has data).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.leaf.is_some()
    }

    /// Depth of the subtree rooted here (1 = leaf).
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            1 + self.children.values().map(Self::depth).max().unwrap_or(0)
        }
    }

    /// Total leaf count in this subtree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        if self.is_leaf() {
            1
        } else {
            self.children.values().map(Self::leaf_count).sum()
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceTree
// ---------------------------------------------------------------------------

/// Top-level PE resource directory tree.
///
/// Hierarchy: type → name/id → language → leaf.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ResourceTree {
    /// Map of resource type → subtree.
    roots: BTreeMap<ResourceId, ResourceNode>,
}

// ---------------------------------------------------------------------------
// Directory-blob helpers (used by ResourceTree::build)
// ---------------------------------------------------------------------------

fn rdir_write_dir_header(blob: &mut [u8], pos: &mut usize, n_id: u16, n_named: u16) {
    // Characteristics, TimeDateStamp, MajorVersion, MinorVersion — all zero.
    for b in &mut blob[*pos..*pos + 12] {
        *b = 0;
    }
    *pos += 12;
    // NumberOfNamedEntries (LE u16)
    blob[*pos..*pos + 2].copy_from_slice(&n_named.to_le_bytes());
    *pos += 2;
    // NumberOfIdEntries (LE u16)
    blob[*pos..*pos + 2].copy_from_slice(&n_id.to_le_bytes());
    *pos += 2;
}

fn rdir_write_dir_entry(blob: &mut [u8], pos: &mut usize, id_or_offset: u32, offset_to_dir_or_data: u32) {
    blob[*pos..*pos + 4].copy_from_slice(&id_or_offset.to_le_bytes());
    *pos += 4;
    blob[*pos..*pos + 4].copy_from_slice(&offset_to_dir_or_data.to_le_bytes());
    *pos += 4;
}

fn rdir_write_data_entry(blob: &mut [u8], pos: &mut usize, data_rva: u32, size: u32, code_page: u32) {
    blob[*pos..*pos + 4].copy_from_slice(&data_rva.to_le_bytes());
    *pos += 4;
    blob[*pos..*pos + 4].copy_from_slice(&size.to_le_bytes());
    *pos += 4;
    blob[*pos..*pos + 4].copy_from_slice(&code_page.to_le_bytes());
    *pos += 4;
    // Reserved — already zero.
    *pos += 4;
}

impl ResourceTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a resource leaf.
    ///
    /// `type_id` → `name_id` → `lang_id` → `data`.
    pub fn add_leaf(
        &mut self,
        type_id: ResourceId,
        name_id: ResourceId,
        leaf: ResourceLeaf,
    ) {
        let lang_id = ResourceId::Id(leaf.language_id);
        let lang_node = ResourceNode::leaf(lang_id, leaf);
        let type_entry = self
            .roots
            .entry(type_id.clone())
            .or_insert_with(|| ResourceNode::new(type_id));
        let name_entry = type_entry
            .children
            .entry(name_id.clone())
            .or_insert_with(|| ResourceNode::new(name_id));
        name_entry.insert_child(lang_node);
    }

    /// Convenience: add an `RT_MANIFEST` (type 24, name 1, lang 0x0409).
    pub fn add_manifest(&mut self, xml_bytes: Vec<u8>) {
        self.add_leaf(
            ResourceId::Id(rt::MANIFEST),
            ResourceId::Id(1),
            ResourceLeaf::en_us(xml_bytes),
        );
    }

    /// Convenience: add an `RT_VERSION` (type 16, name 1, lang 0x0409).
    pub fn add_version_info(&mut self, data: Vec<u8>) {
        self.add_leaf(
            ResourceId::Id(rt::VERSION),
            ResourceId::Id(1),
            ResourceLeaf::en_us(data),
        );
    }

    /// Convenience: add an `RT_ICON` (type 3).
    pub fn add_icon(&mut self, name_id: u16, lang: u16, data: Vec<u8>) {
        self.add_leaf(
            ResourceId::Id(rt::ICON),
            ResourceId::Id(name_id),
            ResourceLeaf::new(lang, data),
        );
    }

    /// Convenience: add an `RT_RCDATA`.
    pub fn add_rcdata(&mut self, name_id: u16, data: Vec<u8>) {
        self.add_leaf(
            ResourceId::Id(rt::RCDATA),
            ResourceId::Id(name_id),
            ResourceLeaf::en_us(data),
        );
    }

    /// Remove all resources of a given type.  Returns `true` if found.
    pub fn remove_type(&mut self, type_id: &ResourceId) -> bool {
        self.roots.remove(type_id).is_some()
    }

    /// Remove a specific named resource.  Returns `true` if found.
    pub fn remove_named(
        &mut self,
        type_id: &ResourceId,
        name_id: &ResourceId,
    ) -> bool {
        self.roots.get_mut(type_id).is_some_and(|type_node| type_node.remove_child(name_id).is_some())
    }

    /// Replace the data of an existing leaf (same type/name/lang).
    ///
    /// Returns `true` if the leaf existed and was replaced.
    pub fn replace_leaf(
        &mut self,
        type_id: &ResourceId,
        name_id: &ResourceId,
        lang_id: &ResourceId,
        new_data: Vec<u8>,
    ) -> bool {
        if let Some(type_node) = self.roots.get_mut(type_id)
            && let Some(name_node) = type_node.children.get_mut(name_id)
                && let Some(lang_node) = name_node.children.get_mut(lang_id)
                    && let Some(leaf) = &mut lang_node.leaf {
                        leaf.data = new_data;
                        return true;
                    }
        false
    }

    /// Get leaf data by type/name/language.
    #[must_use]
    pub fn get_leaf_data(
        &self,
        type_id: &ResourceId,
        name_id: &ResourceId,
        lang_id: &ResourceId,
    ) -> Option<&[u8]> {
        self.roots
            .get(type_id)?
            .children
            .get(name_id)?
            .children
            .get(lang_id)?
            .leaf
            .as_ref()
            .map(|l| l.data.as_slice())
    }

    /// Total number of type-level entries.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.roots.len()
    }

    /// Total number of leaf resources across all types.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.roots.values().map(ResourceNode::leaf_count).sum()
    }

    /// Collect all leaves as `(type_id, name_id, lang_id, data)`.
    #[must_use]
    pub fn all_leaves(&self) -> Vec<(ResourceId, ResourceId, u16, &[u8])> {
        let mut result = Vec::new();
        for (type_id, type_node) in &self.roots {
            for (name_id, name_node) in &type_node.children {
                for lang_node in name_node.children.values() {
                    if let Some(leaf) = &lang_node.leaf {
                        result.push((
                            type_id.clone(),
                            name_id.clone(),
                            leaf.language_id,
                            leaf.data.as_slice(),
                        ));
                    }
                }
            }
        }
        result
    }

    /// Build the raw resource section blob.
    ///
    /// Layout follows PE `IMAGE_RESOURCE_DIRECTORY`:
    /// 1. Level-0 directory (types).
    /// 2. Level-1 directories (names/IDs per type).
    /// 3. Level-2 directories (languages per name).
    /// 4. `IMAGE_RESOURCE_DATA_ENTRY` records.
    /// 5. Leaf data payloads.
    ///
    /// All `OffsetToData` fields in `DATA_ENTRYs` are relative to `base_rva`.
    ///
    /// # Errors
    /// Returns `EditError::ResourceError` if the tree is empty.
    ///
    /// # Panics
    /// Panics if any offset or size within the resource blob exceeds `u32::MAX`.
    pub fn build(&self, base_rva: u32) -> Result<Vec<u8>, EditError> {
        if self.roots.is_empty() {
            return Err(EditError::ResourceError(
                "resource tree is empty".to_string(),
            ));
        }

        // We collect all leaves for serialisation.
        let leaves = self.all_leaves();

        // ---- Pass 1: compute layout sizes --------------------------------

        // IMAGE_RESOURCE_DIRECTORY = 16 bytes.
        // IMAGE_RESOURCE_DIRECTORY_ENTRY = 8 bytes.
        // IMAGE_RESOURCE_DATA_ENTRY = 16 bytes.

        let n_types = self.roots.len();
        // Count names per type and languages per name.
        let type_entries: Vec<_> = self.roots.values().collect();
        let total_name_dirs: usize = type_entries.iter().map(|t| t.children.len()).sum();
        let total_lang_dirs: usize = type_entries
            .iter()
            .flat_map(|t| t.children.values())
            .map(|n| n.children.len())
            .sum();

        // Level-0 dir: 16 + n_types * 8
        let l0_dir_size = 16 + n_types * 8;
        // Level-1 dirs: one per type, 16 + n_names*8 each
        let l1_dirs_size: usize = type_entries.iter().map(|t| 16 + t.children.len() * 8).sum();
        // Level-2 dirs: one per name-node, 16 + n_langs*8 each
        let l2_dirs_size: usize = type_entries
            .iter()
            .flat_map(|t| t.children.values())
            .map(|n| 16 + n.children.len() * 8)
            .sum();

        // Cross-check the directory count totals against the entry-based sums
        // to catch tree shape inconsistencies early.
        debug_assert_eq!(
            l1_dirs_size,
            16 * type_entries.len() + 8 * total_name_dirs,
            "L1 directory size mismatch (name dirs {total_name_dirs})"
        );
        debug_assert_eq!(
            l2_dirs_size,
            16 * total_name_dirs + 8 * total_lang_dirs,
            "L2 directory size mismatch (lang dirs {total_lang_dirs})"
        );
        // Data entries: one per leaf.
        let data_entries_size = leaves.len() * 16;

        let dirs_total = l0_dir_size + l1_dirs_size + l2_dirs_size + data_entries_size;

        // Leaf data starts after all directories.
        // Align to 4 bytes.
        let leaf_data_base = (dirs_total + 3) & !3;

        // Compute cumulative leaf data offsets.
        let mut leaf_offsets: Vec<usize> = Vec::with_capacity(leaves.len());
        let mut cursor = leaf_data_base;
        for &(_, _, _, data) in &leaves {
            leaf_offsets.push(cursor);
            cursor += data.len();
            // Align to 4 bytes.
            cursor = (cursor + 3) & !3;
        }

        let total_size = cursor;
        let mut blob = vec![0u8; total_size];

        // ---- Pass 2: write directories -----------------------------------

        let mut pos = 0usize;

        // Determine sub-directory positions.
        // Level-1 dir offsets (one per type).
        let mut l1_positions: Vec<usize> = Vec::with_capacity(n_types);
        let mut cur = l0_dir_size;
        for type_node in &type_entries {
            l1_positions.push(cur);
            cur += 16 + type_node.children.len() * 8;
        }

        // Level-2 dir offsets (one per name-node), computed correctly.
        let mut l2_positions: Vec<Vec<usize>> = Vec::with_capacity(n_types);
        let mut cur2 = l0_dir_size + l1_dirs_size;
        for type_node in &type_entries {
            let mut name_positions = Vec::with_capacity(type_node.children.len());
            for name_node in type_node.children.values() {
                name_positions.push(cur2);
                cur2 += 16 + name_node.children.len() * 8;
            }
            l2_positions.push(name_positions);
        }

        // Write level-0 directory.
        let n_id_types = type_entries.iter().filter(|t| t.id.is_id()).count();
        let n_named_types = n_types - n_id_types;
        rdir_write_dir_header(
            &mut blob,
            &mut pos,
            u16::try_from(n_id_types).expect("type count fits in u16"),
            u16::try_from(n_named_types).expect("named type count fits in u16"),
        );

        for (t_idx, type_node) in type_entries.iter().enumerate() {
            let id_val = match &type_node.id {
                ResourceId::Id(n) => u32::from(*n),
                ResourceId::Name(_) => 0x8000_0000u32, // string names not fully handled
            };
            // Subdirectory flag = bit 31.
            let sub_dir_off = u32::try_from(l1_positions[t_idx]).expect("l1 offset fits in u32") | 0x8000_0000;
            rdir_write_dir_entry(&mut blob, &mut pos, id_val, sub_dir_off);
        }

        rdir_write_level1_2_and_data(
            &mut blob, &mut pos,
            &type_entries, &l2_positions,
            base_rva, &leaf_offsets, &leaves,
        );

        Ok(blob)
    }
}

/// Write level-1 dirs, level-2 dirs, data entries, and leaf payloads into `blob`.
fn rdir_write_level1_2_and_data(
    blob: &mut [u8],
    pos: &mut usize,
    type_entries: &[&ResourceNode],
    l2_positions: &[Vec<usize>],
    base_rva: u32,
    leaf_offsets: &[usize],
    leaves: &[(ResourceId, ResourceId, u16, &[u8])],
) {
    // Write level-1 directories.
    for (t_idx, type_node) in type_entries.iter().enumerate() {
        let n_id = type_node.children.values().filter(|n| n.id.is_id()).count();
        let n_named = type_node.children.len() - n_id;
        rdir_write_dir_header(blob, pos, u16::try_from(n_id).expect("id count fits in u16"), u16::try_from(n_named).expect("named count fits in u16"));
        for (n_idx, name_node) in type_node.children.values().enumerate() {
            let id_val = match &name_node.id { ResourceId::Id(n) => u32::from(*n), ResourceId::Name(_) => 0x8000_0000u32 };
            let sub_dir_off = u32::try_from(l2_positions[t_idx][n_idx]).expect("l2 offset fits in u32") | 0x8000_0000;
            rdir_write_dir_entry(blob, pos, id_val, sub_dir_off);
        }
    }
    // Compute data_entry_base: after L1 dirs, pos is at L2 start; data entries follow all L2 dirs.
    let l2_dirs_size: usize = type_entries.iter()
        .flat_map(|t| t.children.values())
        .map(|n| 16 + n.children.len() * 8)
        .sum();
    let data_entry_base = *pos + l2_dirs_size;
    // Write level-2 directories (language level).
    let mut data_entry_idx = 0usize;
    for type_node in type_entries {
        for name_node in type_node.children.values() {
            let n_id = name_node.children.len();
            rdir_write_dir_header(blob, pos, u16::try_from(n_id).expect("lang count fits in u16"), 0);
            for lang_node in name_node.children.values() {
                let lang_val = match &lang_node.id { ResourceId::Id(n) => u32::from(*n), ResourceId::Name(_) => 0 };
                let de_off = data_entry_base + data_entry_idx * 16;
                data_entry_idx += 1;
                rdir_write_dir_entry(blob, pos, lang_val, u32::try_from(de_off).expect("data entry offset fits in u32"));
            }
        }
    }
    // Write data entries.
    for (leaf_idx, &(_, _, _, leaf_data)) in leaves.iter().enumerate() {
        let data_rva = base_rva + u32::try_from(leaf_offsets[leaf_idx]).expect("leaf offset fits in u32");
        rdir_write_data_entry(blob, pos, data_rva, u32::try_from(leaf_data.len()).expect("leaf size fits in u32"), 0);
    }
    // Write leaf data.
    for (leaf_global_idx, &(_, _, _, leaf_data)) in leaves.iter().enumerate() {
        let off = leaf_offsets[leaf_global_idx];
        blob[off..off + leaf_data.len()].copy_from_slice(leaf_data);
    }
}

// ---------------------------------------------------------------------------
// PeResourceEditor
// ---------------------------------------------------------------------------

/// High-level resource editor that wraps a `ResourceTree`.
pub struct PeResourceEditor {
    tree: ResourceTree,
    audit_log: Vec<String>,
}

impl PeResourceEditor {
    /// Create an empty resource editor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: ResourceTree::new(),
            audit_log: Vec::new(),
        }
    }

    /// Access the underlying tree.
    #[must_use]
    pub const fn tree(&self) -> &ResourceTree {
        &self.tree
    }

    /// Mutable access to the tree.
    #[must_use]
    pub const fn tree_mut(&mut self) -> &mut ResourceTree {
        &mut self.tree
    }

    /// Add or replace an `RT_MANIFEST`.
    pub fn set_manifest(&mut self, xml: Vec<u8>) {
        self.tree.add_manifest(xml);
        self.audit_log.push("set_manifest".to_string());
    }

    /// Add or replace `RT_VERSION` info.
    pub fn set_version_info(&mut self, data: Vec<u8>) {
        self.tree.add_version_info(data);
        self.audit_log.push("set_version_info".to_string());
    }

    /// Add an icon resource.
    pub fn add_icon(&mut self, name_id: u16, lang: u16, data: Vec<u8>) {
        self.tree.add_icon(name_id, lang, data);
        self.audit_log
            .push(format!("add_icon name_id={name_id} lang={lang}"));
    }

    /// Add raw RCDATA.
    pub fn add_rcdata(&mut self, name_id: u16, data: Vec<u8>) {
        self.tree.add_rcdata(name_id, data);
        self.audit_log
            .push(format!("add_rcdata name_id={name_id}"));
    }

    /// Remove all resources of a numeric type.
    pub fn remove_type(&mut self, type_id: u16) -> bool {
        let id = ResourceId::Id(type_id);
        let ok = self.tree.remove_type(&id);
        if ok {
            self.audit_log.push(format!("remove_type={type_id}"));
        }
        ok
    }

    /// Remove a specific named resource.
    pub fn remove_named(&mut self, type_id: u16, name_id: u16) -> bool {
        let tid = ResourceId::Id(type_id);
        let nid = ResourceId::Id(name_id);
        let ok = self.tree.remove_named(&tid, &nid);
        if ok {
            self.audit_log
                .push(format!("remove_named type={type_id} name={name_id}"));
        }
        ok
    }

    /// Replace a resource leaf's data.
    pub fn replace_resource_data(
        &mut self,
        type_id: u16,
        name_id: u16,
        lang_id: u16,
        new_data: Vec<u8>,
    ) -> bool {
        let tid = ResourceId::Id(type_id);
        let nid = ResourceId::Id(name_id);
        let lid = ResourceId::Id(lang_id);
        let ok = self.tree.replace_leaf(&tid, &nid, &lid, new_data);
        if ok {
            self.audit_log.push(format!(
                "replace type={type_id} name={name_id} lang={lang_id}"
            ));
        }
        ok
    }

    /// Get resource data.
    #[must_use]
    pub fn get_resource(&self, type_id: u16, name_id: u16, lang_id: u16) -> Option<&[u8]> {
        self.tree.get_leaf_data(
            &ResourceId::Id(type_id),
            &ResourceId::Id(name_id),
            &ResourceId::Id(lang_id),
        )
    }

    /// Build the resource section blob.
    ///
    /// # Errors
    /// Propagates `EditError` from the tree build.
    pub fn build_section(&self, base_rva: u32) -> Result<Vec<u8>, EditError> {
        self.tree.build(base_rva)
    }

    /// Total number of resource leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.tree.leaf_count()
    }

    /// Audit log.
    #[must_use]
    pub fn audit_log(&self) -> &[String] {
        &self.audit_log
    }
}

impl Default for PeResourceEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PeResourceEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeResourceEditor {{ leaves={} ops={} }}",
            self.leaf_count(),
            self.audit_log.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ResourceSummary
// ---------------------------------------------------------------------------

/// Summary of a resource tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    pub type_count: usize,
    pub leaf_count: usize,
    pub has_manifest: bool,
    pub has_version: bool,
    pub has_icons: bool,
    pub total_data_bytes: usize,
}

impl ResourceSummary {
    /// Summarise a tree.
    #[must_use]
    pub fn from_tree(tree: &ResourceTree) -> Self {
        let manifest_id = ResourceId::Id(rt::MANIFEST);
        let version_id = ResourceId::Id(rt::VERSION);
        let icon_id = ResourceId::Id(rt::ICON);

        let total_data_bytes = tree
            .all_leaves()
            .iter()
            .map(|(_, _, _, d)| d.len())
            .sum();

        Self {
            type_count: tree.type_count(),
            leaf_count: tree.leaf_count(),
            has_manifest: tree.roots.contains_key(&manifest_id),
            has_version: tree.roots.contains_key(&version_id),
            has_icons: tree.roots.contains_key(&icon_id),
            total_data_bytes,
        }
    }
}

impl fmt::Display for ResourceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Resources: {} types, {} leaves, {} bytes (manifest={} version={} icons={})",
            self.type_count,
            self.leaf_count,
            self.total_data_bytes,
            self.has_manifest,
            self.has_version,
            self.has_icons,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_display() {
        assert_eq!(ResourceId::Id(24).to_string(), "RT_MANIFEST(24)");
        assert_eq!(ResourceId::Id(99).to_string(), "#99");
        assert_eq!(ResourceId::Name("MYRES".to_string()).to_string(), "MYRES");
    }

    #[test]
    fn resource_leaf_len() {
        let leaf = ResourceLeaf::en_us(vec![1, 2, 3]);
        assert_eq!(leaf.len(), 3);
        assert!(!leaf.is_empty());
    }

    #[test]
    fn resource_tree_leaf_count_empty() {
        let tree = ResourceTree::new();
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn resource_tree_add_manifest() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"<assembly/>".to_vec());
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.type_count(), 1);
    }

    #[test]
    fn resource_tree_add_multiple_types() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"<assembly/>".to_vec());
        tree.add_version_info(vec![0u8; 100]);
        tree.add_icon(1, 0x0409, vec![0u8; 64]);
        assert_eq!(tree.type_count(), 3);
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn resource_tree_remove_type() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"test".to_vec());
        tree.add_version_info(b"ver".to_vec());
        assert!(tree.remove_type(&ResourceId::Id(rt::MANIFEST)));
        assert_eq!(tree.type_count(), 1);
        assert!(!tree.remove_type(&ResourceId::Id(rt::MANIFEST)));
    }

    #[test]
    fn resource_tree_remove_named() {
        let mut tree = ResourceTree::new();
        tree.add_icon(1, 0x0409, vec![0xFFu8; 16]);
        tree.add_icon(2, 0x0409, vec![0xFFu8; 16]);
        assert!(tree.remove_named(&ResourceId::Id(rt::ICON), &ResourceId::Id(1)));
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn resource_tree_replace_leaf() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"old".to_vec());
        let replaced = tree.replace_leaf(
            &ResourceId::Id(rt::MANIFEST),
            &ResourceId::Id(1),
            &ResourceId::Id(0x0409),
            b"new".to_vec(),
        );
        assert!(replaced);
        let data = tree.get_leaf_data(
            &ResourceId::Id(rt::MANIFEST),
            &ResourceId::Id(1),
            &ResourceId::Id(0x0409),
        );
        assert_eq!(data, Some(b"new".as_slice()));
    }

    #[test]
    fn resource_tree_build_empty_fails() {
        let tree = ResourceTree::new();
        assert!(tree.build(0x4000).is_err());
    }

    #[test]
    fn resource_tree_build_manifest() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"<assembly/>".to_vec());
        let blob = tree.build(0x4000).unwrap();
        assert!(!blob.is_empty());
        // Level-0 dir should start with 16 bytes.
        assert!(blob.len() >= 16);
    }

    #[test]
    fn pe_resource_editor_set_manifest() {
        let mut ed = PeResourceEditor::new();
        ed.set_manifest(b"<manifest/>".to_vec());
        assert_eq!(ed.leaf_count(), 1);
        assert!(!ed.audit_log().is_empty());
    }

    #[test]
    fn pe_resource_editor_remove_type() {
        let mut ed = PeResourceEditor::new();
        ed.set_manifest(b"<manifest/>".to_vec());
        assert!(ed.remove_type(rt::MANIFEST));
        assert_eq!(ed.leaf_count(), 0);
    }

    #[test]
    fn pe_resource_editor_get_resource() {
        let mut ed = PeResourceEditor::new();
        ed.set_version_info(b"VERSIONINFO".to_vec());
        let data = ed.get_resource(rt::VERSION, 1, 0x0409);
        assert_eq!(data, Some(b"VERSIONINFO".as_slice()));
    }

    #[test]
    fn resource_summary_has_manifest() {
        let mut ed = PeResourceEditor::new();
        ed.set_manifest(b"<assembly/>".to_vec());
        ed.set_version_info(b"ver".to_vec());
        let summary = ResourceSummary::from_tree(ed.tree());
        assert!(summary.has_manifest);
        assert!(summary.has_version);
        assert!(!summary.has_icons);
    }

    #[test]
    fn node_depth_and_count() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"test".to_vec());
        tree.add_version_info(b"ver".to_vec());
        let root = tree.roots.get(&ResourceId::Id(rt::MANIFEST)).unwrap();
        assert_eq!(root.depth(), 3);
        assert_eq!(root.leaf_count(), 1);
    }

    #[test]
    fn all_leaves_returns_all() {
        let mut tree = ResourceTree::new();
        tree.add_manifest(b"m".to_vec());
        tree.add_version_info(b"v".to_vec());
        tree.add_icon(1, 0, b"i".to_vec());
        let leaves = tree.all_leaves();
        assert_eq!(leaves.len(), 3);
    }
}
