// rustre-syscalls-windows/src/nt_object_manager.rs
//
// NT object manager simulation: resolve object names, enumerate handles,
// look up object types, and model the NT namespace hierarchy.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the NT object manager layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjMgrError {
    /// The object was not found by name.
    NotFound(String),
    /// A duplicate object name was inserted at the same path.
    AlreadyExists(String),
    /// The handle value is invalid or has been closed.
    InvalidHandle(u32),
    /// The path is syntactically invalid.
    InvalidPath(String),
    /// Access was denied.
    AccessDenied(String),
}

impl fmt::Display for ObjMgrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "object not found: {n}"),
            Self::AlreadyExists(n) => write!(f, "object already exists: {n}"),
            Self::InvalidHandle(h) => write!(f, "invalid handle: {h:#x}"),
            Self::InvalidPath(p) => write!(f, "invalid path: {p}"),
            Self::AccessDenied(p) => write!(f, "access denied: {p}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, ObjMgrError>;

// ─── ObjectType ───────────────────────────────────────────────────────────────

/// NT kernel object types (subset of the real type table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Directory,
    SymbolicLink,
    File,
    Process,
    Thread,
    Section,
    Event,
    Semaphore,
    Mutant,
    Key,
    Token,
    Job,
    Timer,
    IoCompletion,
    Port,
    WindowStation,
    Desktop,
    Driver,
    Device,
    Unknown,
}

impl ObjectType {
    /// NT type name string as returned by `NtQueryObject`.
    #[must_use]
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::Directory => "Directory",
            Self::SymbolicLink => "SymbolicLink",
            Self::File => "File",
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::Section => "Section",
            Self::Event => "Event",
            Self::Semaphore => "Semaphore",
            Self::Mutant => "Mutant",
            Self::Key => "Key",
            Self::Token => "Token",
            Self::Job => "Job",
            Self::Timer => "Timer",
            Self::IoCompletion => "IoCompletion",
            Self::Port => "ALPC Port",
            Self::WindowStation => "WindowStation",
            Self::Desktop => "Desktop",
            Self::Driver => "Driver",
            Self::Device => "Device",
            Self::Unknown => "Unknown",
        }
    }

    /// Parse a type from its string name.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "Directory" => Self::Directory,
            "SymbolicLink" => Self::SymbolicLink,
            "File" => Self::File,
            "Process" => Self::Process,
            "Thread" => Self::Thread,
            "Section" => Self::Section,
            "Event" => Self::Event,
            "Semaphore" => Self::Semaphore,
            "Mutant" => Self::Mutant,
            "Key" => Self::Key,
            "Token" => Self::Token,
            "Job" => Self::Job,
            "Timer" => Self::Timer,
            "IoCompletion" => Self::IoCompletion,
            "ALPC Port" => Self::Port,
            "WindowStation" => Self::WindowStation,
            "Desktop" => Self::Desktop,
            "Driver" => Self::Driver,
            "Device" => Self::Device,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

// ─── AccessMask ──────────────────────────────────────────────────────────────

/// Access mask for NT objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessMask(pub u32);

impl AccessMask {
    pub const GENERIC_READ: Self = Self(0x8000_0000);
    pub const GENERIC_WRITE: Self = Self(0x4000_0000);
    pub const GENERIC_EXECUTE: Self = Self(0x2000_0000);
    pub const GENERIC_ALL: Self = Self(0x1000_0000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    pub const WRITE_OWNER: Self = Self(0x0008_0000);
    pub const STANDARD_RIGHTS_ALL: Self = Self(0x001F_0000);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl fmt::Display for AccessMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccessMask({:#010x})", self.0)
    }
}

// ─── NtObject ────────────────────────────────────────────────────────────────

/// A single NT kernel object in the object manager namespace.
#[derive(Debug, Clone)]
pub struct NtObject {
    /// Absolute NT path (e.g. `\\Device\\HarddiskVolume1`).
    pub path: String,
    /// Object type.
    pub object_type: ObjectType,
    /// Reference count (number of open handles).
    pub ref_count: u32,
    /// For `SymbolicLink` objects, the target path.
    pub symlink_target: Option<String>,
    /// Arbitrary metadata (e.g. file size, process PID).
    pub attributes: HashMap<String, u64>,
    /// Security descriptor (`ACCESS_MASK` for the owner).
    pub owner_access: AccessMask,
}

impl NtObject {
    /// Create a new object with the given path and type.
    #[must_use]
    pub fn new(path: impl Into<String>, object_type: ObjectType) -> Self {
        Self {
            path: path.into(),
            object_type,
            ref_count: 0,
            symlink_target: None,
            attributes: HashMap::new(),
            owner_access: AccessMask::STANDARD_RIGHTS_ALL,
        }
    }

    /// Create a symbolic link object pointing to `target`.
    #[must_use]
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        let mut obj = Self::new(path, ObjectType::SymbolicLink);
        obj.symlink_target = Some(target.into());
        obj
    }

    /// Return the object name (last component of the path).
    #[must_use]
    pub fn name(&self) -> &str {
        self.path.rsplit('\\').next().unwrap_or(&self.path)
    }

    /// Return the parent directory path (everything before the last `\`).
    #[must_use]
    pub fn parent_path(&self) -> &str {
        match self.path.rfind('\\') {
            Some(pos) if pos > 0 => &self.path[..pos],
            _ => "\\",
        }
    }

    /// Set an attribute value.
    pub fn set_attr(&mut self, key: impl Into<String>, value: u64) {
        self.attributes.insert(key.into(), value);
    }

    /// Get an attribute value.
    #[must_use]
    pub fn get_attr(&self, key: &str) -> Option<u64> {
        self.attributes.get(key).copied()
    }
}

impl fmt::Display for NtObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtObject({}, {})", self.path, self.object_type)
    }
}

// ─── Handle table ─────────────────────────────────────────────────────────────

/// An open handle entry in the per-process handle table.
#[derive(Debug, Clone)]
pub struct HandleEntry {
    /// Handle value.
    pub handle: u32,
    /// NT object path this handle refers to.
    pub object_path: String,
    /// Granted access mask.
    pub access: AccessMask,
    /// Whether this handle is inheritable.
    pub inherit: bool,
    /// Whether this handle is protected from being closed.
    pub protect_from_close: bool,
}

// ─── NtObjectManager ─────────────────────────────────────────────────────────

/// Simulated NT object manager.
///
/// Maintains an in-memory namespace tree of NT objects, a per-session handle
/// table, and symbolic link resolution.
pub struct NtObjectManager {
    /// Namespace: path → object.
    namespace: HashMap<String, NtObject>,
    /// Handle table: handle value → entry.
    handles: HashMap<u32, HandleEntry>,
    next_handle: AtomicU32,
    /// Current directory for relative paths.
    pub current_directory: String,
}

impl NtObjectManager {
    /// Create a new object manager populated with the standard NT namespace.
    #[must_use]
    pub fn new() -> Self {
        let mut mgr = Self {
            namespace: HashMap::new(),
            handles: HashMap::new(),
            next_handle: AtomicU32::new(4),
            current_directory: "\\".to_string(),
        };
        mgr.populate_standard_namespace();
        mgr
    }

    /// Populate the object manager with a realistic subset of the NT namespace.
    fn populate_standard_namespace(&mut self) {
        // Root directory objects
        let root_dirs = [
            "\\",
            "\\Device",
            "\\Driver",
            "\\BaseNamedObjects",
            "\\Sessions",
            "\\Windows",
            "\\KernelObjects",
            "\\GLOBAL??",
            "\\ObjectTypes",
            "\\FileSystem",
        ];
        for path in &root_dirs {
            self.namespace.insert(
                path.to_string(),
                NtObject::new(*path, ObjectType::Directory),
            );
        }

        // Devices
        let devices = [
            ("\\Device\\HarddiskVolume1", ObjectType::Device),
            ("\\Device\\HarddiskVolume2", ObjectType::Device),
            ("\\Device\\Null", ObjectType::Device),
            ("\\Device\\ConDrv", ObjectType::Device),
            ("\\Device\\NamedPipe", ObjectType::Device),
            ("\\Device\\Afd", ObjectType::Device),
            ("\\Device\\Nsi", ObjectType::Device),
            ("\\Device\\Tcp", ObjectType::Device),
            ("\\Device\\Udp", ObjectType::Device),
            ("\\Device\\Ip", ObjectType::Device),
        ];
        for (path, ty) in &devices {
            self.namespace
                .insert(path.to_string(), NtObject::new(*path, *ty));
        }

        // Symbolic links (DosDevices)
        let symlinks: &[(&str, &str)] = &[
            ("\\GLOBAL??\\C:", "\\Device\\HarddiskVolume1"),
            ("\\GLOBAL??\\D:", "\\Device\\HarddiskVolume2"),
            ("\\GLOBAL??\\NUL", "\\Device\\Null"),
            ("\\GLOBAL??\\CON", "\\Device\\ConDrv"),
            ("\\GLOBAL??\\PIPE", "\\Device\\NamedPipe"),
        ];
        for (path, target) in symlinks {
            self.namespace.insert(
                path.to_string(),
                NtObject::symlink(*path, *target),
            );
        }

        // Kernel object types
        let types = [
            "Process", "Thread", "File", "Event", "Semaphore", "Mutant", "Key",
            "Token", "Section", "Job", "Timer", "IoCompletion", "Directory",
            "SymbolicLink", "Driver", "Device",
        ];
        for ty in &types {
            let path = format!("\\ObjectTypes\\{ty}");
            self.namespace
                .insert(path.clone(), NtObject::new(path, ObjectType::Directory));
        }
    }

    /// Resolve an NT object name, following symbolic links up to 32 hops.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::NotFound`] if the path does not exist,
    /// [`ObjMgrError::InvalidPath`] if the path is empty or the symlink chain
    /// exceeds 32 hops.
    pub fn resolve_object_name(&self, path: &str) -> Result<&NtObject> {
        self.resolve_object_name_depth(path, 0)
    }

    fn resolve_object_name_depth(&self, path: &str, depth: u32) -> Result<&NtObject> {
        if depth > 32 {
            return Err(ObjMgrError::InvalidPath(format!(
                "symlink chain too deep: {path}"
            )));
        }
        let normalized = self.normalize_path(path)?;
        match self.namespace.get(normalized.as_str()) {
            None => Err(ObjMgrError::NotFound(normalized)),
            Some(obj) if obj.object_type == ObjectType::SymbolicLink => {
                obj.symlink_target.clone().map_or(Ok(obj), |target| {
                    self.resolve_object_name_depth(&target, depth + 1)
                })
            }
            Some(obj) => Ok(obj),
        }
    }

    /// Normalize an NT path: make absolute, collapse `..` etc.
    fn normalize_path(&self, path: &str) -> Result<String> {
        if path.is_empty() {
            return Err(ObjMgrError::InvalidPath("empty path".to_string()));
        }
        let abs = if path.starts_with('\\') {
            path.to_string()
        } else {
            format!("{}\\{}", self.current_directory.trim_end_matches('\\'), path)
        };
        Ok(abs)
    }

    /// Insert an object into the namespace.
    ///
    /// Returns `AlreadyExists` when the path is already occupied.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::AlreadyExists`] if an object already exists at
    /// `obj.path`.
    pub fn insert_object(&mut self, obj: NtObject) -> Result<()> {
        if self.namespace.contains_key(obj.path.as_str()) {
            return Err(ObjMgrError::AlreadyExists(obj.path));
        }
        self.namespace.insert(obj.path.clone(), obj);
        Ok(())
    }

    /// Remove an object from the namespace by path.
    pub fn remove_object(&mut self, path: &str) -> bool {
        self.namespace.remove(path).is_some()
    }

    /// Open a handle to the object at `path` with the given access mask.
    ///
    /// Returns the allocated handle value.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::NotFound`] if the path does not resolve, or
    /// [`ObjMgrError::InvalidPath`] if the path is malformed.
    pub fn open_object(&mut self, path: &str, access: AccessMask) -> Result<u32> {
        let path = self.normalize_path(path)?;
        // Check the object exists (resolve symlinks)
        let resolved_path = {
            let obj = self.resolve_object_name(&path)?;
            obj.path.clone()
        };

        let handle = self.next_handle.fetch_add(4, Ordering::Relaxed);
        self.handles.insert(
            handle,
            HandleEntry {
                handle,
                object_path: resolved_path,
                access,
                inherit: false,
                protect_from_close: false,
            },
        );
        // Increment ref count
        if let Some(obj) = self.namespace.get_mut(&self.normalize_path(&path).unwrap_or_default()) {
            obj.ref_count += 1;
        }
        Ok(handle)
    }

    /// Close a handle, decrementing the object's reference count.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::InvalidHandle`] if the handle is not open.
    pub fn close_handle(&mut self, handle: u32) -> Result<()> {
        let entry = self
            .handles
            .remove(&handle)
            .ok_or(ObjMgrError::InvalidHandle(handle))?;
        if let Some(obj) = self.namespace.get_mut(&entry.object_path) {
            obj.ref_count = obj.ref_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Duplicate a handle, optionally inheriting access.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::InvalidHandle`] if `src_handle` is not open.
    pub fn duplicate_handle(&mut self, src_handle: u32, new_access: Option<AccessMask>) -> Result<u32> {
        let entry = self
            .handles
            .get(&src_handle)
            .ok_or(ObjMgrError::InvalidHandle(src_handle))?
            .clone();
        let access = new_access.unwrap_or(entry.access);
        let new_handle = self.next_handle.fetch_add(4, Ordering::Relaxed);
        self.handles.insert(
            new_handle,
            HandleEntry {
                handle: new_handle,
                object_path: entry.object_path.clone(),
                access,
                inherit: false,
                protect_from_close: false,
            },
        );
        if let Some(obj) = self.namespace.get_mut(&entry.object_path) {
            obj.ref_count += 1;
        }
        Ok(new_handle)
    }

    /// Query the object type of an open handle.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::InvalidHandle`] if the handle is not open, or
    /// [`ObjMgrError::NotFound`] if the object path is no longer in the namespace.
    pub fn query_handle_type(&self, handle: u32) -> Result<ObjectType> {
        let entry = self
            .handles
            .get(&handle)
            .ok_or(ObjMgrError::InvalidHandle(handle))?;
        let obj = self
            .namespace
            .get(&entry.object_path)
            .ok_or_else(|| ObjMgrError::NotFound(entry.object_path.clone()))?;
        Ok(obj.object_type)
    }

    /// List all objects in a directory.
    ///
    /// # Errors
    /// Returns [`ObjMgrError::NotFound`] if `dir_path` does not exist, or
    /// [`ObjMgrError::InvalidPath`] if it exists but is not a directory.
    pub fn list_directory(&self, dir_path: &str) -> Result<Vec<&NtObject>> {
        let dir = self.resolve_object_name(dir_path)?;
        if dir.object_type != ObjectType::Directory {
            return Err(ObjMgrError::InvalidPath(format!(
                "{dir_path} is not a directory"
            )));
        }
        let prefix = format!("{}\\", dir.path.trim_end_matches('\\'));
        let results: Vec<&NtObject> = self
            .namespace
            .values()
            .filter(|obj| {
                obj.path.starts_with(&prefix)
                    && !obj.path[prefix.len()..].contains('\\')
            })
            .collect();
        Ok(results)
    }

    /// Return all open handles.
    pub fn open_handles(&self) -> impl Iterator<Item = &HandleEntry> {
        self.handles.values()
    }

    /// Find objects by type.
    #[must_use]
    pub fn find_by_type(&self, ty: ObjectType) -> Vec<&NtObject> {
        self.namespace
            .values()
            .filter(|obj| obj.object_type == ty)
            .collect()
    }

    /// Return the number of objects in the namespace.
    #[must_use]
    pub fn namespace_size(&self) -> usize {
        self.namespace.len()
    }

    /// Return the number of open handles.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }
}

impl Default for NtObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NtObjectManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtObjectManager")
            .field("namespace_size", &self.namespace.len())
            .field("open_handles", &self.handles.len())
            .field("current_directory", &self.current_directory)
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> NtObjectManager {
        NtObjectManager::new()
    }

    #[test]
    fn object_type_name_roundtrip() {
        let types = [
            ObjectType::File,
            ObjectType::Process,
            ObjectType::Thread,
            ObjectType::Directory,
            ObjectType::SymbolicLink,
            ObjectType::Key,
        ];
        for ty in &types {
            assert_eq!(ObjectType::from_name(ty.type_name()), *ty);
        }
    }

    #[test]
    fn resolve_device_null() {
        let m = mgr();
        let obj = m.resolve_object_name("\\Device\\Null").unwrap();
        assert_eq!(obj.object_type, ObjectType::Device);
    }

    #[test]
    fn resolve_symlink_follows_to_target() {
        let m = mgr();
        // \GLOBAL??\NUL → \Device\Null
        let obj = m.resolve_object_name("\\GLOBAL??\\NUL").unwrap();
        assert_eq!(obj.path, "\\Device\\Null");
    }

    #[test]
    fn resolve_nonexistent_errors() {
        let m = mgr();
        assert!(m.resolve_object_name("\\NoSuch\\Object").is_err());
    }

    #[test]
    fn insert_duplicate_errors() {
        let mut m = mgr();
        let obj = NtObject::new("\\Device\\Null", ObjectType::Device);
        assert!(m.insert_object(obj).is_err());
    }

    #[test]
    fn insert_new_object() {
        let mut m = mgr();
        let obj = NtObject::new("\\Device\\TestDev", ObjectType::Device);
        m.insert_object(obj).unwrap();
        assert!(m.resolve_object_name("\\Device\\TestDev").is_ok());
    }

    #[test]
    fn remove_object() {
        let mut m = mgr();
        assert!(m.remove_object("\\Device\\Null"));
        assert!(!m.remove_object("\\Device\\Null"));
        assert!(m.resolve_object_name("\\Device\\Null").is_err());
    }

    #[test]
    fn open_and_close_handle() {
        let mut m = mgr();
        let h = m.open_object("\\Device\\Null", AccessMask::GENERIC_READ).unwrap();
        assert!(h > 0);
        assert!(m.close_handle(h).is_ok());
        assert!(m.close_handle(h).is_err());
    }

    #[test]
    fn duplicate_handle() {
        let mut m = mgr();
        let h = m.open_object("\\Device\\Null", AccessMask::GENERIC_READ).unwrap();
        let h2 = m.duplicate_handle(h, None).unwrap();
        assert_ne!(h, h2);
        assert_eq!(m.handle_count(), 2);
    }

    #[test]
    fn query_handle_type() {
        let mut m = mgr();
        let h = m.open_object("\\Device\\Null", AccessMask::GENERIC_READ).unwrap();
        assert_eq!(m.query_handle_type(h).unwrap(), ObjectType::Device);
    }

    #[test]
    fn query_invalid_handle_type_errors() {
        let m = mgr();
        assert!(m.query_handle_type(0xDEAD).is_err());
    }

    #[test]
    fn list_directory() {
        let m = mgr();
        let entries = m.list_directory("\\Device").unwrap();
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|o| o.name() == "Null"));
    }

    #[test]
    fn list_non_directory_errors() {
        let m = mgr();
        assert!(m.list_directory("\\Device\\Null").is_err());
    }

    #[test]
    fn find_by_type_symlink() {
        let m = mgr();
        let symlinks = m.find_by_type(ObjectType::SymbolicLink);
        assert!(!symlinks.is_empty());
        assert!(symlinks.iter().all(|o| o.object_type == ObjectType::SymbolicLink));
    }

    #[test]
    fn namespace_size_nonzero() {
        let m = mgr();
        assert!(m.namespace_size() > 10);
    }

    #[test]
    fn access_mask_contains() {
        let mask = AccessMask(AccessMask::GENERIC_READ.0 | AccessMask::SYNCHRONIZE.0);
        assert!(mask.contains(AccessMask::GENERIC_READ));
        assert!(mask.contains(AccessMask::SYNCHRONIZE));
        assert!(!mask.contains(AccessMask::GENERIC_WRITE));
    }

    #[test]
    fn nt_object_name_and_parent() {
        let obj = NtObject::new("\\Device\\HarddiskVolume1", ObjectType::Device);
        assert_eq!(obj.name(), "HarddiskVolume1");
        assert_eq!(obj.parent_path(), "\\Device");
    }

    #[test]
    fn nt_object_attributes() {
        let mut obj = NtObject::new("\\Device\\TestDev", ObjectType::Device);
        obj.set_attr("size", 1024);
        assert_eq!(obj.get_attr("size"), Some(1024));
        assert_eq!(obj.get_attr("missing"), None);
    }

    #[test]
    fn error_display() {
        assert!(ObjMgrError::NotFound("\\foo".into()).to_string().contains("not found"));
        assert!(ObjMgrError::InvalidHandle(0x1234).to_string().contains("0x1234"));
    }

    #[test]
    fn open_handles_iterator() {
        let mut m = mgr();
        let h = m.open_object("\\Device\\Null", AccessMask::GENERIC_READ).unwrap();
        let handles: Vec<_> = m.open_handles().collect();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].handle, h);
    }
}
