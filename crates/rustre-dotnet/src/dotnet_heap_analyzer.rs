// dotnet_heap_analyzer.rs — .NET managed heap analyzer
// Models GC generations, object headers, method tables, object fields,
// GC roots, heap segments, and heap statistics.

use std::collections::HashMap;
use std::fmt;

use ahash::AHashMap;

// ─── GC Generation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GcGeneration {
    Gen0,
    Gen1,
    Gen2,
    LOH,  // Large Object Heap (>= 85000 bytes)
    POH,  // Pinned Object Heap
}

impl GcGeneration {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Gen0),
            1 => Some(Self::Gen1),
            2 => Some(Self::Gen2),
            3 => Some(Self::LOH),
            4 => Some(Self::POH),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn is_ephemeral(self) -> bool {
        matches!(self, Self::Gen0 | Self::Gen1)
    }
}

impl fmt::Display for GcGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gen0 => write!(f, "Gen0"),
            Self::Gen1 => write!(f, "Gen1"),
            Self::Gen2 => write!(f, "Gen2"),
            Self::LOH  => write!(f, "LOH"),
            Self::POH  => write!(f, "POH"),
        }
    }
}

// ─── MethodTable Flags ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MethodTableFlags(pub u32);

impl MethodTableFlags {
    pub const ARRAY_CLASS:          u32 = 0x0001_0000;
    pub const IS_VALUE_TYPE:        u32 = 0x0004_0000;
    pub const HAS_FINALIZER:        u32 = 0x0010_0000;
    pub const IS_INTERFACE:         u32 = 0x0008_0000;
    pub const CONTAINS_POINTERS:    u32 = 0x0100_0000;
    pub const IS_ABSTRACT:          u32 = 0x0002_0000;

    #[must_use] 
    pub const fn is_array(self)            -> bool { (self.0 & Self::ARRAY_CLASS)       != 0 }
    #[must_use] 
    pub const fn is_value_type(self)       -> bool { (self.0 & Self::IS_VALUE_TYPE)     != 0 }
    #[must_use] 
    pub const fn has_finalizer(self)       -> bool { (self.0 & Self::HAS_FINALIZER)     != 0 }
    #[must_use] 
    pub const fn is_interface(self)        -> bool { (self.0 & Self::IS_INTERFACE)      != 0 }
    #[must_use] 
    pub const fn contains_pointers(self)   -> bool { (self.0 & Self::CONTAINS_POINTERS) != 0 }
    #[must_use] 
    pub const fn is_abstract(self)         -> bool { (self.0 & Self::IS_ABSTRACT)       != 0 }
}

// ─── MethodTable ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MethodTable {
    pub address:       u64,
    pub ee_class_ptr:  u64,
    pub parent_mt_ptr: u64,
    pub module_ptr:    u64,
    pub flags:         MethodTableFlags,
    pub base_size:     u32,
    pub component_size:u16,
    pub num_interfaces:u16,
    pub num_methods:   u16,
    pub num_fields:    u16,
    pub type_name:     String,
    pub namespace:     String,
}

impl MethodTable {
    #[must_use] 
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.type_name.clone()
        } else {
            format!("{}.{}", self.namespace, self.type_name)
        }
    }

    #[must_use] 
    pub fn element_size(&self) -> u32 {
        if self.flags.is_array() {
            u32::from(self.component_size)
        } else {
            self.base_size
        }
    }
}

// ─── ObjectHeader ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ObjectHeader {
    /// Sync block index or hash code depending on mode bits
    pub sync_block_index: u32,
    pub method_table_ptr: u64,
}

impl ObjectHeader {
    pub const BIT_SYNCBLK_INFLATE: u32 = 0x0800_0000;
    pub const BIT_HASH_CODE:       u32 = 0x0400_0000;
    pub const BIT_GC_RESERVED:     u32 = 0x8000_0000;

    #[must_use] 
    pub const fn has_sync_block(self) -> bool {
        (self.sync_block_index & Self::BIT_SYNCBLK_INFLATE) != 0
    }

    #[must_use] 
    pub const fn has_hash_code(self) -> bool {
        (self.sync_block_index & Self::BIT_HASH_CODE) != 0
    }

    #[must_use] 
    pub const fn index(self) -> u32 {
        self.sync_block_index & 0x00FF_FFFF
    }
}

// ─── CorElementType ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CorElementType {
    End       = 0x00,
    Void      = 0x01,
    Boolean   = 0x02,
    Char      = 0x03,
    I1        = 0x04,
    U1        = 0x05,
    I2        = 0x06,
    U2        = 0x07,
    I4        = 0x08,
    U4        = 0x09,
    I8        = 0x0A,
    U8        = 0x0B,
    R4        = 0x0C,
    R8        = 0x0D,
    String    = 0x0E,
    Ptr       = 0x0F,
    ByRef     = 0x10,
    ValueType = 0x11,
    Class     = 0x12,
    Var       = 0x13,
    Array     = 0x14,
    GenericInst = 0x15,
    TypedByRef  = 0x16,
    I         = 0x18,
    U         = 0x19,
    FnPtr     = 0x1B,
    Object    = 0x1C,
    SzArray   = 0x1D,
    MVar      = 0x1E,
    CModReq   = 0x1F,
    CModOpt   = 0x20,
    Internal  = 0x21,
    Max       = 0x22,
    Modifier  = 0x40,
    Sentinel  = 0x41,
    Pinned    = 0x45,
}

impl CorElementType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::End),
            0x01 => Some(Self::Void),
            0x02 => Some(Self::Boolean),
            0x03 => Some(Self::Char),
            0x04 => Some(Self::I1),
            0x05 => Some(Self::U1),
            0x06 => Some(Self::I2),
            0x07 => Some(Self::U2),
            0x08 => Some(Self::I4),
            0x09 => Some(Self::U4),
            0x0A => Some(Self::I8),
            0x0B => Some(Self::U8),
            0x0C => Some(Self::R4),
            0x0D => Some(Self::R8),
            0x0E => Some(Self::String),
            0x0F => Some(Self::Ptr),
            0x10 => Some(Self::ByRef),
            0x11 => Some(Self::ValueType),
            0x12 => Some(Self::Class),
            0x13 => Some(Self::Var),
            0x14 => Some(Self::Array),
            0x15 => Some(Self::GenericInst),
            0x16 => Some(Self::TypedByRef),
            0x18 => Some(Self::I),
            0x19 => Some(Self::U),
            0x1B => Some(Self::FnPtr),
            0x1C => Some(Self::Object),
            0x1D => Some(Self::SzArray),
            0x1E => Some(Self::MVar),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn is_primitive(self) -> bool {
        matches!(self,
            Self::Boolean | Self::Char | Self::I1 | Self::U1 | Self::I2 | Self::U2
            | Self::I4 | Self::U4 | Self::I8 | Self::U8 | Self::R4 | Self::R8
            | Self::I | Self::U
        )
    }

    #[must_use] 
    pub const fn primitive_size(self) -> Option<usize> {
        match self {
            Self::Boolean | Self::I1 | Self::U1 => Some(1),
            Self::I2 | Self::U2                 => Some(2),
            Self::I4 | Self::U4 | Self::R4      => Some(4),
            Self::I8 | Self::U8 | Self::R8      => Some(8),
            _ => None,
        }
    }
}

impl fmt::Display for CorElementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Void => "void", Self::Boolean => "bool", Self::Char => "char",
            Self::I1 => "sbyte", Self::U1 => "byte", Self::I2 => "short",
            Self::U2 => "ushort", Self::I4 => "int", Self::U4 => "uint",
            Self::I8 => "long", Self::U8 => "ulong", Self::R4 => "float",
            Self::R8 => "double", Self::String => "string", Self::Object => "object",
            Self::I => "nint", Self::U => "nuint",
            Self::Class | Self::ValueType => "type",
            Self::Array | Self::SzArray => "array",
            Self::Ptr => "ptr", Self::ByRef => "ref",
            _ => "?",
        };
        write!(f, "{s}")
    }
}

// ─── FieldValue ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum FieldValue {
    Bool(bool),
    I1(i8), U1(u8),
    I2(i16), U2(u16),
    I4(i32), U4(u32),
    I8(i64), U8(u64),
    R4(f32), R8(f64),
    Char(char),
    ObjectRef(u64),
    NativeInt(i64),
    NativeUInt(u64),
    Bytes(Vec<u8>),
    Null,
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b)       => write!(f, "{b}"),
            Self::I1(v)         => write!(f, "{v}i8"),
            Self::U1(v)         => write!(f, "{v}u8"),
            Self::I2(v)         => write!(f, "{v}i16"),
            Self::U2(v)         => write!(f, "{v}u16"),
            Self::I4(v)         => write!(f, "{v}"),
            Self::U4(v)         => write!(f, "{v}u"),
            Self::I8(v)         => write!(f, "{v}L"),
            Self::U8(v)         => write!(f, "{v}UL"),
            Self::R4(v)         => write!(f, "{v}f"),
            Self::R8(v)         => write!(f, "{v}"),
            Self::Char(c)       => write!(f, "'{c}'"),
            Self::ObjectRef(p)  => write!(f, "0x{p:016X}"),
            Self::NativeInt(v)  => write!(f, "{v} (nint)"),
            Self::NativeUInt(v) => write!(f, "{v} (nuint)"),
            Self::Bytes(b)      => write!(f, "[{} bytes]", b.len()),
            Self::Null          => write!(f, "null"),
        }
    }
}

// ─── ObjectField ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ObjectField {
    pub name:       String,
    pub offset:     u32,
    pub field_type: CorElementType,
    pub value:      FieldValue,
    pub is_static:  bool,
}

// ─── HeapObject ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HeapObject {
    pub address:    u64,
    pub header:     ObjectHeader,
    pub mt:         MethodTable,
    pub size:       u64,
    pub generation: GcGeneration,
    pub fields:     Vec<ObjectField>,
}

impl HeapObject {
    #[must_use] 
    pub fn type_name(&self) -> String { self.mt.full_name() }
    #[must_use] 
    pub fn is_string(&self) -> bool   { self.mt.full_name() == "System.String" }
    #[must_use] 
    pub const fn is_array(&self)  -> bool   { self.mt.flags.is_array() }
    #[must_use] 
    pub const fn is_large(&self)  -> bool   { matches!(self.generation, GcGeneration::LOH) }

    /// Try to read the string value from a System.String object.
    #[must_use] 
    pub fn string_value(&self) -> Option<String> {
        if !self.is_string() { return None; }
        // Conventionally the first field of System.String is _stringLength (I4),
        // followed by _firstChar (Char-based). We reconstruct from char fields.
        let chars: String = self.fields.iter()
            .filter(|f| f.field_type == CorElementType::Char)
            .filter_map(|f| if let FieldValue::Char(c) = f.value { Some(c) } else { None })
            .collect();
        if chars.is_empty() { None } else { Some(chars) }
    }

    #[must_use] 
    pub fn reference_fields(&self) -> Vec<&ObjectField> {
        self.fields.iter()
            .filter(|f| matches!(f.field_type, CorElementType::Class | CorElementType::Object
                | CorElementType::String | CorElementType::SzArray | CorElementType::Array))
            .collect()
    }
}

// ─── RootKind ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootKind {
    Stack,
    Handle,
    Finalizer,
    Static,
    AsyncPinHandle,
    WeakHandle,
}

impl fmt::Display for RootKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack         => write!(f, "Stack"),
            Self::Handle        => write!(f, "Handle"),
            Self::Finalizer     => write!(f, "Finalizer"),
            Self::Static        => write!(f, "Static"),
            Self::AsyncPinHandle=> write!(f, "AsyncPinHandle"),
            Self::WeakHandle    => write!(f, "WeakHandle"),
        }
    }
}

// ─── GcRoot ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GcRoot {
    pub address:        u64,
    pub kind:           RootKind,
    pub object_address: u64,
    pub name:           Option<String>,
    pub thread_id:      Option<u32>,
}

// ─── HeapSegment ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HeapSegment {
    pub start:       u64,
    pub current:     u64,
    pub end:         u64,
    pub committed:   u64,
    pub generation:  GcGeneration,
    pub heap_index:  u32,  // for server GC, which heap this belongs to
}

impl HeapSegment {
    #[must_use] 
    pub const fn used_bytes(&self) -> u64 {
        self.current.saturating_sub(self.start)
    }
    #[must_use] 
    pub const fn free_bytes(&self) -> u64 {
        self.end.saturating_sub(self.current)
    }
    #[must_use] 
    pub const fn committed_bytes(&self) -> u64 {
        self.committed.saturating_sub(self.start)
    }
    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.current
    }
    #[must_use] 
    pub fn fragmentation_ratio(&self) -> f64 {
        let total = self.end.saturating_sub(self.start);
        if total == 0 { return 0.0; }
        let free = self.free_bytes();
        // Scale to u32 range to avoid precision loss in u64→f64 conversion
        let shift = (64u32.saturating_sub(total.leading_zeros())).saturating_sub(31);
        let total_s = u32::try_from(total >> shift).unwrap_or(u32::MAX);
        let free_s = u32::try_from((free >> shift).min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        f64::from(free_s) / f64::from(total_s.max(1))
    }
}

// ─── HeapStats ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HeapStats {
    pub total_objects:       HashMap<GcGenerationKey, u64>,
    pub total_bytes:         HashMap<GcGenerationKey, u64>,
    pub largest_object:      Option<(u64, u64)>,  // (address, size)
    pub fragmentation_ratio: f64,
    pub num_strings:         u64,
    pub num_finalizable:     u64,
    pub num_pinned:          u64,
    pub type_histogram:      AHashMap<String, (u64, u64)>,  // type_name → (count, total_bytes)
}

// Wrapper to allow GcGeneration as HashMap key with serde-like semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GcGenerationKey(pub GcGeneration);

impl From<GcGeneration> for GcGenerationKey {
    fn from(g: GcGeneration) -> Self { Self(g) }
}

impl HeapStats {
    #[must_use] 
    pub fn total_object_count(&self) -> u64 {
        self.total_objects.values().sum()
    }
    #[must_use] 
    pub fn total_byte_count(&self) -> u64 {
        self.total_bytes.values().sum()
    }
    #[must_use] 
    pub fn top_types_by_size(&self, n: usize) -> Vec<(&str, u64, u64)> {
        let mut entries: Vec<(&str, u64, u64)> = self.type_histogram.iter()
            .map(|(k, (cnt, bytes))| (k.as_str(), *cnt, *bytes))
            .collect();
        entries.sort_by(|a, b| b.2.cmp(&a.2));
        entries.truncate(n);
        entries
    }
}

// ─── HeapAnalyzer ────────────────────────────────────────────────────────────

pub struct HeapAnalyzer {
    pub objects:  Vec<HeapObject>,
    pub roots:    Vec<GcRoot>,
    pub segments: Vec<HeapSegment>,
}

impl HeapAnalyzer {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            objects: Vec::new(),
            roots:   Vec::new(),
            segments: Vec::new(),
        }
    }

    pub fn add_object(&mut self, obj: HeapObject) {
        self.objects.push(obj);
    }

    pub fn add_root(&mut self, root: GcRoot) {
        self.roots.push(root);
    }

    pub fn add_segment(&mut self, seg: HeapSegment) {
        self.segments.push(seg);
    }

    /// Find objects whose type matches the given fully-qualified name.
    #[must_use] 
    pub fn find_objects_of_type(&self, type_name: &str) -> Vec<&HeapObject> {
        self.objects.iter()
            .filter(|o| o.type_name() == type_name)
            .collect()
    }

    /// Find all System.String objects and return (address, `string_value`).
    #[must_use] 
    pub fn find_string_objects(&self) -> Vec<(u64, Option<String>)> {
        self.objects.iter()
            .filter(|o| o.is_string())
            .map(|o| (o.address, o.string_value()))
            .collect()
    }

    /// Find all GC roots that point to a given object address.
    #[must_use] 
    pub fn find_roots_for_object(&self, object_addr: u64) -> Vec<&GcRoot> {
        self.roots.iter()
            .filter(|r| r.object_address == object_addr)
            .collect()
    }

    /// Determine the GC generation of an object given its address.
    #[must_use] 
    pub fn generation_of(&self, addr: u64) -> Option<GcGeneration> {
        for seg in &self.segments {
            if seg.contains(addr) {
                return Some(seg.generation);
            }
        }
        None
    }

    /// Compute aggregate heap statistics.
    #[must_use] 
    pub fn compute_stats(&self) -> HeapStats {
        let mut stats = HeapStats::default();

        for obj in &self.objects {
            let key = GcGenerationKey(obj.generation);
            *stats.total_objects.entry(key).or_insert(0) += 1;
            *stats.total_bytes.entry(key).or_insert(0) += obj.size;

            let (cnt, bytes) = stats.type_histogram
                .entry(obj.type_name())
                .or_insert((0, 0));
            *cnt += 1;
            *bytes += obj.size;

            if obj.is_string() { stats.num_strings += 1; }
            if obj.mt.flags.has_finalizer() { stats.num_finalizable += 1; }
            if matches!(obj.generation, GcGeneration::POH) { stats.num_pinned += 1; }

            match stats.largest_object {
                None => { stats.largest_object = Some((obj.address, obj.size)); }
                Some((_, prev_size)) if obj.size > prev_size => {
                    stats.largest_object = Some((obj.address, obj.size));
                }
                _ => {}
            }
        }

        // Aggregate fragmentation across segments
        let total_seg_size: u64 = self.segments.iter()
            .map(|s| s.end.saturating_sub(s.start))
            .sum();
        let total_free: u64 = self.segments.iter()
            .map(HeapSegment::free_bytes)
            .sum();
        if total_seg_size > 0 {
            {
                // Scale to u32 range to avoid precision loss in u64→f64 conversion
                let shift = (64u32.saturating_sub(total_seg_size.leading_zeros())).saturating_sub(31);
                let denom = u32::try_from(total_seg_size >> shift).unwrap_or(u32::MAX);
                let numer = u32::try_from((total_free >> shift).min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
                stats.fragmentation_ratio = f64::from(numer) / f64::from(denom.max(1));
            }
        }

        stats
    }

    /// Walk the object graph from a root address (BFS), returning all reachable
    /// object addresses up to `depth_limit` levels.
    #[must_use] 
    pub fn reachable_from(&self, root_addr: u64, depth_limit: usize) -> Vec<u64> {
        let addr_index: HashMap<u64, &HeapObject> = self.objects.iter()
            .map(|o| (o.address, o))
            .collect();

        let mut visited: Vec<u64> = Vec::new();
        let mut frontier: Vec<u64> = vec![root_addr];
        let mut depth = 0usize;

        while !frontier.is_empty() && depth < depth_limit {
            let mut next: Vec<u64> = Vec::new();
            for addr in &frontier {
                if visited.contains(addr) { continue; }
                visited.push(*addr);
                if let Some(obj) = addr_index.get(addr) {
                    for fld in obj.reference_fields() {
                        if let FieldValue::ObjectRef(ref_addr) = fld.value
                            && ref_addr != 0 && !visited.contains(&ref_addr) {
                                next.push(ref_addr);
                            }
                    }
                }
            }
            frontier = next;
            depth += 1;
        }
        visited
    }

    /// Find objects that are only reachable through the finalizer queue.
    #[must_use] 
    pub fn finalizer_reachable(&self) -> Vec<&HeapObject> {
        let finalizer_roots: Vec<u64> = self.roots.iter()
            .filter(|r| r.kind == RootKind::Finalizer)
            .map(|r| r.object_address)
            .collect();
        self.objects.iter()
            .filter(|o| finalizer_roots.contains(&o.address))
            .collect()
    }

    /// Find objects with no GC root (neither direct nor transitive). These are
    /// candidates for collection in the next GC cycle.
    #[must_use] 
    pub fn unreachable_objects(&self) -> Vec<&HeapObject> {
        let all_rooted: std::collections::HashSet<u64> = self.roots.iter()
            .map(|r| r.object_address)
            .collect();
        self.objects.iter()
            .filter(|o| !all_rooted.contains(&o.address))
            .collect()
    }

    /// Segment that contains the given address.
    #[must_use] 
    pub fn segment_for(&self, addr: u64) -> Option<&HeapSegment> {
        self.segments.iter().find(|s| s.contains(addr))
    }

    /// Objects in the given generation.
    #[must_use] 
    pub fn objects_in_generation(&self, generation: GcGeneration) -> Vec<&HeapObject> {
        self.objects.iter().filter(|o| o.generation == generation).collect()
    }

    /// Check if an address looks like a valid object (has a known method table).
    #[must_use] 
    pub fn is_valid_object_address(&self, addr: u64) -> bool {
        self.objects.iter().any(|o| o.address == addr)
    }

    /// Compute the retention size of an object (size of itself + all objects
    /// it exclusively retains).
    #[must_use] 
    pub fn retention_size(&self, addr: u64, depth: usize) -> u64 {
        let reachable = self.reachable_from(addr, depth);
        self.objects.iter()
            .filter(|o| reachable.contains(&o.address))
            .map(|o| o.size)
            .sum()
    }
}

impl Default for HeapAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Builder helpers ─────────────────────────────────────────────────────────

#[must_use] 
pub fn build_method_table(
    address: u64,
    type_name: &str,
    namespace: &str,
    base_size: u32,
    flags: u32,
) -> MethodTable {
    MethodTable {
        address,
        ee_class_ptr:  address + 0x40,
        parent_mt_ptr: 0,
        module_ptr:    0,
        flags:         MethodTableFlags(flags),
        base_size,
        component_size: 0,
        num_interfaces: 0,
        num_methods:    4,
        num_fields:     0,
        type_name:      type_name.to_string(),
        namespace:      namespace.to_string(),
    }
}

#[must_use] 
pub const fn build_object(
    address: u64,
    mt: MethodTable,
    size: u64,
    generation: GcGeneration,
) -> HeapObject {
    HeapObject {
        address,
        header: ObjectHeader {
            sync_block_index: 0,
            method_table_ptr: mt.address,
        },
        mt,
        size,
        generation,
        fields: Vec::new(),
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_analyzer() -> HeapAnalyzer {
        let mut a = HeapAnalyzer::new();

        let mt_str = build_method_table(0x1000, "String", "System", 24, 0);
        let mt_int = build_method_table(0x2000, "Int32",  "System", 12, MethodTableFlags::IS_VALUE_TYPE);

        let mut obj_str = build_object(0xAAA0, mt_str, 32, GcGeneration::Gen0);
        obj_str.fields.push(ObjectField {
            name: "_firstChar".to_string(),
            offset: 12,
            field_type: CorElementType::Char,
            value: FieldValue::Char('H'),
            is_static: false,
        });

        let obj_int = build_object(0xBBB0, mt_int, 12, GcGeneration::Gen1);
        a.add_object(obj_str);
        a.add_object(obj_int);
        a.add_segment(HeapSegment {
            start: 0xA000,
            current: 0xB000,
            end: 0xC000,
            committed: 0xC000,
            generation: GcGeneration::Gen0,
            heap_index: 0,
        });
        a.add_root(GcRoot {
            address: 0x10,
            kind: RootKind::Stack,
            object_address: 0xAAA0,
            name: Some("local0".to_string()),
            thread_id: Some(1),
        });
        a
    }

    #[test]
    fn test_find_objects_of_type() {
        let a = sample_analyzer();
        let strings = a.find_objects_of_type("System.String");
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].address, 0xAAA0);
    }

    #[test]
    fn test_find_objects_not_found() {
        let a = sample_analyzer();
        let r = a.find_objects_of_type("System.Object");
        assert!(r.is_empty());
    }

    #[test]
    fn test_find_string_objects() {
        let a = sample_analyzer();
        let strings = a.find_string_objects();
        assert_eq!(strings.len(), 1);
        let (addr, val) = &strings[0];
        assert_eq!(*addr, 0xAAA0);
        assert_eq!(val.as_deref(), Some("H"));
    }

    #[test]
    fn test_find_roots_for_object() {
        let a = sample_analyzer();
        let roots = a.find_roots_for_object(0xAAA0);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].kind, RootKind::Stack);
    }

    #[test]
    fn test_find_roots_none() {
        let a = sample_analyzer();
        let roots = a.find_roots_for_object(0xBBB0);
        assert!(roots.is_empty());
    }

    #[test]
    fn test_generation_of() {
        let a = sample_analyzer();
        // 0xAAA0 is inside segment 0xA000..0xB000 (Gen0)
        let generation = a.generation_of(0xAAA0);
        assert_eq!(generation, Some(GcGeneration::Gen0));
    }

    #[test]
    fn test_generation_of_outside() {
        let a = sample_analyzer();
        let generation = a.generation_of(0xFFFF0);
        assert!(generation.is_none());
    }

    #[test]
    fn test_compute_stats_object_count() {
        let a = sample_analyzer();
        let stats = a.compute_stats();
        assert_eq!(stats.total_object_count(), 2);
    }

    #[test]
    fn test_compute_stats_string_count() {
        let a = sample_analyzer();
        let stats = a.compute_stats();
        assert_eq!(stats.num_strings, 1);
    }

    #[test]
    fn test_heap_segment_used_bytes() {
        let seg = HeapSegment {
            start: 0, current: 100, end: 200, committed: 200,
            generation: GcGeneration::Gen0, heap_index: 0,
        };
        assert_eq!(seg.used_bytes(), 100);
        assert_eq!(seg.free_bytes(), 100);
    }

    #[test]
    fn test_heap_segment_fragmentation() {
        let seg = HeapSegment {
            start: 0, current: 50, end: 100, committed: 100,
            generation: GcGeneration::Gen1, heap_index: 0,
        };
        let ratio = seg.fragmentation_ratio();
        assert!((ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_cor_element_type_primitive() {
        assert!(CorElementType::I4.is_primitive());
        assert!(!CorElementType::String.is_primitive());
    }

    #[test]
    fn test_cor_element_type_size() {
        assert_eq!(CorElementType::I4.primitive_size(), Some(4));
        assert_eq!(CorElementType::I8.primitive_size(), Some(8));
        assert_eq!(CorElementType::Char.primitive_size(), None);
    }

    #[test]
    fn test_method_table_flags_value_type() {
        let flags = MethodTableFlags(MethodTableFlags::IS_VALUE_TYPE);
        assert!(flags.is_value_type());
        assert!(!flags.is_array());
    }

    #[test]
    fn test_object_header_index() {
        let hdr = ObjectHeader {
            sync_block_index: 0x0800_0005,
            method_table_ptr: 0,
        };
        assert!(hdr.has_sync_block());
        assert_eq!(hdr.index(), 5);
    }

    #[test]
    fn test_unreachable_objects() {
        let a = sample_analyzer();
        // 0xBBB0 has no root
        let unreach = a.unreachable_objects();
        assert_eq!(unreach.len(), 1);
        assert_eq!(unreach[0].address, 0xBBB0);
    }

    #[test]
    fn test_gc_generation_ephemeral() {
        assert!(GcGeneration::Gen0.is_ephemeral());
        assert!(GcGeneration::Gen1.is_ephemeral());
        assert!(!GcGeneration::Gen2.is_ephemeral());
        assert!(!GcGeneration::LOH.is_ephemeral());
    }

    #[test]
    fn test_method_table_full_name() {
        let mt = build_method_table(0, "String", "System", 24, 0);
        assert_eq!(mt.full_name(), "System.String");
    }

    #[test]
    fn test_field_value_display() {
        let v = FieldValue::I4(42);
        assert_eq!(format!("{v}"), "42");
        let v2 = FieldValue::Null;
        assert_eq!(format!("{v2}"), "null");
    }
}
