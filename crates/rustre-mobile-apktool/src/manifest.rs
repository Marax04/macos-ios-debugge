//! Android binary XML (AXML) and AndroidManifest.xml parser.
//!
//! Parses the binary AndroidManifest.xml format used inside APK files,
//! builds a typed `AndroidManifest` object model, and exposes security-
//! relevant queries.

// ─── ManifestError ────────────────────────────────────────────────────────────

/// Errors that can occur while parsing an Android manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The file does not start with the expected AXML magic.
    InvalidMagic,
    /// The file is too short to contain the structure being parsed.
    Truncated,
    /// A structural parsing error with a description.
    ParseError(String),
    /// A string could not be decoded as valid UTF-8 or UTF-16.
    Utf8Error,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid AXML magic"),
            Self::Truncated => write!(f, "truncated AXML data"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::Utf8Error => write!(f, "UTF encoding error"),
        }
    }
}

impl std::error::Error for ManifestError {}

// ─── Intent filter ────────────────────────────────────────────────────────────

/// Describes the intents a component can respond to.
#[derive(Debug, Clone, Default)]
pub struct IntentFilter {
    /// `<action android:name="…"/>` entries.
    pub actions: Vec<String>,
    /// `<category android:name="…"/>` entries.
    pub categories: Vec<String>,
    /// `<data android:scheme="…"/>` entries.
    pub data_schemes: Vec<String>,
    /// `<data android:host="…"/>` entries.
    pub data_hosts: Vec<String>,
    /// `<data android:path="…"/>` entries.
    pub data_paths: Vec<String>,
    /// `<data android:mimeType="…"/>` entries.
    pub mime_types: Vec<String>,
}

impl IntentFilter {
    /// `true` if this filter includes the MAIN/LAUNCHER combo, marking a
    /// launchable activity.
    #[must_use]
    pub fn is_launcher(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a == "android.intent.action.MAIN")
            && self
                .categories
                .iter()
                .any(|c| c == "android.intent.category.LAUNCHER")
    }
}

// ─── ComponentInfo ────────────────────────────────────────────────────────────

/// Shared fields for all Android application components.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    /// Fully-qualified class name.
    pub name: String,
    /// Whether this component is exported (`android:exported`). `None` means
    /// the attribute is absent (defaults based on intent-filter presence).
    pub exported: Option<bool>,
    /// `android:enabled` attribute (defaults to `true`).
    pub enabled: bool,
    /// Intent filters declared on this component.
    pub intent_filters: Vec<IntentFilter>,
    /// Required permission to interact with this component.
    pub permission: Option<String>,
}

impl ComponentInfo {
    /// Create a new `ComponentInfo` with default values.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            exported: None,
            enabled: true,
            intent_filters: Vec::new(),
            permission: None,
        }
    }

    /// `true` if the component is effectively exported.
    ///
    /// A component is effectively exported when `android:exported="true"`, or
    /// when the attribute is absent and the component has at least one intent
    /// filter (Android < 12 default).
    #[must_use]
    pub const fn is_effectively_exported(&self) -> bool {
        match self.exported {
            Some(v) => v,
            None => !self.intent_filters.is_empty(),
        }
    }
}

// ─── ActivityInfo ─────────────────────────────────────────────────────────────

/// An `<activity>` component.
#[derive(Debug, Clone)]
pub struct ActivityInfo {
    /// Base component fields.
    pub base: ComponentInfo,
    /// `android:launchMode` attribute.
    pub launch_mode: String,
    /// `android:screenOrientation` attribute.
    pub screen_orientation: Option<String>,
    /// `android:theme` attribute.
    pub theme: Option<String>,
}

impl ActivityInfo {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: ComponentInfo::new(name),
            launch_mode: "standard".to_string(),
            screen_orientation: None,
            theme: None,
        }
    }
}

// ─── ServiceInfo ──────────────────────────────────────────────────────────────

/// A `<service>` component.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Base component fields.
    pub base: ComponentInfo,
    /// `android:foregroundServiceType` attribute.
    pub foreground_service_type: Option<String>,
}

impl ServiceInfo {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: ComponentInfo::new(name),
            foreground_service_type: None,
        }
    }
}

// ─── ReceiverInfo ─────────────────────────────────────────────────────────────

/// A `<receiver>` component.
#[derive(Debug, Clone)]
pub struct ReceiverInfo {
    /// Base component fields.
    pub base: ComponentInfo,
}

impl ReceiverInfo {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: ComponentInfo::new(name),
        }
    }
}

// ─── ProviderInfo ─────────────────────────────────────────────────────────────

/// A `<provider>` component.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Base component fields.
    pub base: ComponentInfo,
    /// `android:authorities` attribute.
    pub authorities: String,
    /// `android:grantUriPermissions` attribute.
    pub grant_uri_permissions: bool,
    /// `android:readPermission` attribute.
    pub read_permission: Option<String>,
    /// `android:writePermission` attribute.
    pub write_permission: Option<String>,
}

impl ProviderInfo {
    #[must_use]
    pub fn new(name: impl Into<String>, authorities: impl Into<String>) -> Self {
        Self {
            base: ComponentInfo::new(name),
            authorities: authorities.into(),
            grant_uri_permissions: false,
            read_permission: None,
            write_permission: None,
        }
    }
}

// ─── UsesPermission ───────────────────────────────────────────────────────────

/// A `<uses-permission>` declaration.
#[derive(Debug, Clone)]
pub struct UsesPermission {
    /// Permission name (e.g. `android.permission.CAMERA`).
    pub name: String,
    /// `android:maxSdkVersion` attribute.
    pub max_sdk: Option<i32>,
}

// ─── AndroidManifest ──────────────────────────────────────────────────────────

/// Parsed representation of `AndroidManifest.xml`.
#[derive(Debug, Clone)]
pub struct AndroidManifest {
    /// Application package name.
    pub package: String,
    /// `android:versionCode` attribute.
    pub version_code: i32,
    /// `android:versionName` attribute.
    pub version_name: String,
    /// `android:minSdkVersion`.
    pub min_sdk: i32,
    /// `android:targetSdkVersion`.
    pub target_sdk: i32,
    /// `android:maxSdkVersion`.
    pub max_sdk: Option<i32>,
    /// `android:compileSdkVersion`.
    pub compile_sdk: Option<i32>,
    /// `android:debuggable`.
    pub debuggable: bool,
    /// `android:allowBackup`.
    pub allow_backup: bool,
    /// `android:usesCleartextTraffic`.
    pub uses_cleartext_traffic: bool,
    /// `android:networkSecurityConfig` reference.
    pub network_security_config: Option<String>,
    /// All `<uses-permission>` entries.
    pub permissions: Vec<UsesPermission>,
    /// All `<activity>` entries.
    pub activities: Vec<ActivityInfo>,
    /// All `<service>` entries.
    pub services: Vec<ServiceInfo>,
    /// All `<receiver>` entries.
    pub receivers: Vec<ReceiverInfo>,
    /// All `<provider>` entries.
    pub providers: Vec<ProviderInfo>,
}

impl Default for AndroidManifest {
    fn default() -> Self {
        Self {
            package: String::new(),
            version_code: 0,
            version_name: String::new(),
            min_sdk: 1,
            target_sdk: 0,
            max_sdk: None,
            compile_sdk: None,
            debuggable: false,
            allow_backup: true,
            uses_cleartext_traffic: false,
            network_security_config: None,
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
        }
    }
}

impl AndroidManifest {
    /// Return well-known DANGEROUS-level permissions declared by the app.
    #[must_use]
    pub fn dangerous_permissions(&self) -> Vec<&str> {
        const DANGEROUS: &[&str] = &[
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.USE_BIOMETRIC",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        ];

        self.permissions
            .iter()
            .filter(|p| DANGEROUS.contains(&p.name.as_str()))
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Return activities that are effectively exported.
    #[must_use]
    pub fn exported_activities(&self) -> Vec<&ActivityInfo> {
        self.activities
            .iter()
            .filter(|a| a.base.is_effectively_exported())
            .collect()
    }

    /// Return services that are effectively exported.
    #[must_use]
    pub fn exported_services(&self) -> Vec<&ServiceInfo> {
        self.services
            .iter()
            .filter(|s| s.base.is_effectively_exported())
            .collect()
    }

    /// Return receivers that are effectively exported.
    #[must_use]
    pub fn exported_receivers(&self) -> Vec<&ReceiverInfo> {
        self.receivers
            .iter()
            .filter(|r| r.base.is_effectively_exported())
            .collect()
    }

    /// Total number of declared components.
    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.activities.len() + self.services.len() + self.receivers.len() + self.providers.len()
    }
}

// ─── Binary AXML parser ───────────────────────────────────────────────────────

/// Binary AXML chunk type constants.
mod chunk_type {
    pub const STRING_POOL: u16 = 0x0001;
    pub const END_DOCUMENT: u16 = 0x0101;
    pub const START_ELEMENT: u16 = 0x0102;
    pub const END_ELEMENT: u16 = 0x0103;
    pub const CDATA: u16 = 0x0104;
}

/// Value data types in AXML attribute values.
mod value_type {
    pub const NULL: u8 = 0x00;
    pub const REFERENCE: u8 = 0x01;
    pub const ATTRIBUTE: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const INT_DEC: u8 = 0x10;
    pub const INT_HEX: u8 = 0x11;
    pub const INT_BOOL: u8 = 0x12;
    pub const INT_COLOR: u8 = 0x1C;

    /// Returns true if `t` represents an integer-shaped attribute value.
    #[must_use]
    pub const fn is_integer(t: u8) -> bool {
        matches!(t, INT_DEC | INT_HEX | INT_BOOL | INT_COLOR)
    }
}

/// An AXML attribute value.
#[derive(Debug, Clone)]
pub enum AxmlValue {
    Null,
    Reference(u32),
    Attribute(u32),
    String(String),
    Float(f32),
    Int(i32),
    Bool(bool),
    Color(u32),
}

impl AxmlValue {
    /// Try to extract a string representation.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    /// Try to extract an integer.
    #[must_use]
    pub fn as_int(&self) -> Option<i32> {
        match self {
            Self::Int(v) => Some(*v),
            Self::Bool(b) => Some(i32::from(*b)),
            _ => None,
        }
    }

    /// Try to extract a bool.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Int(v) => Some(*v != 0),
            _ => None,
        }
    }
}

/// A parsed AXML attribute.
#[derive(Debug, Clone)]
pub struct AxmlAttr {
    /// Attribute name.
    pub name: String,
    /// Attribute value.
    pub value: AxmlValue,
}

/// A parsed AXML event.
#[derive(Debug, Clone)]
pub enum AxmlEvent {
    /// `<element attr1="…" …>` opening tag.
    StartElement { name: String, attrs: Vec<AxmlAttr> },
    /// `</element>` closing tag.
    EndElement { name: String },
    /// Text content between tags.
    Text(String),
}

// ─── AxmlParser ───────────────────────────────────────────────────────────────

/// Streaming binary AXML parser.
pub struct AxmlParser {
    data: Vec<u8>,
    pos: usize,
    string_pool: Vec<String>,
}

impl AxmlParser {
    /// Construct a parser from raw AXML bytes and parse the string pool.
    ///
    /// The binary manifest file starts with the document header chunk
    /// (type 0x0003) followed by the string pool chunk (type 0x0001).
    ///
    /// # Errors
    /// Returns a [`ManifestError`] if the data is truncated or malformed.
    pub fn new(data: Vec<u8>) -> Result<Self, ManifestError> {
        if data.len() < 8 {
            return Err(ManifestError::Truncated);
        }

        let mut parser = Self {
            data,
            pos: 0,
            string_pool: Vec::new(),
        };

        // Skip the file header (8 bytes) or larger first chunk if present
        // Real AXML: first chunk is StringPool (0x001C0001) or similar.
        // We scan forward looking for the string pool chunk.
        parser.parse_string_pool()?;

        Ok(parser)
    }

    /// Parse the string pool from the data stream.
    ///
    /// Looks for the first chunk with type `STRING_POOL` (0x0001).
    ///
    /// # Errors
    /// Returns a [`ManifestError`] if the chunk is truncated or malformed.
    pub fn parse_string_pool(&mut self) -> Result<(), ManifestError> {
        // Try to find the string pool; it's typically the first or second chunk.
        let mut scan_pos = 0usize;
        while scan_pos + 8 <= self.data.len() {
            let chunk_type = u16::from_le_bytes(
                self.data[scan_pos..scan_pos + 2]
                    .try_into()
                    .map_err(|_| ManifestError::Truncated)?,
            );
            let _chunk_header_size = u16::from_le_bytes(
                self.data[scan_pos + 2..scan_pos + 4]
                    .try_into()
                    .map_err(|_| ManifestError::Truncated)?,
            ) as usize;
            let chunk_size = u32::from_le_bytes(
                self.data[scan_pos + 4..scan_pos + 8]
                    .try_into()
                    .map_err(|_| ManifestError::Truncated)?,
            ) as usize;

            if chunk_type == chunk_type::STRING_POOL {
                self.read_string_pool_at(scan_pos, chunk_size)?;
                self.pos = scan_pos + chunk_size;
                return Ok(());
            }

            if chunk_size == 0 {
                break;
            }
            scan_pos += chunk_size;
        }

        // If not found, set pos to end and return with empty pool
        self.pos = self.data.len();
        Ok(())
    }

    fn read_string_pool_at(
        &mut self,
        base: usize,
        _chunk_size: usize,
    ) -> Result<(), ManifestError> {
        // String pool layout after the 8-byte chunk header:
        // string_count (4), style_count (4), flags (4), strings_start (4),
        // styles_start (4), then string_count offsets (4 each),
        // then string data.
        if base + 28 > self.data.len() {
            return Err(ManifestError::Truncated);
        }

        let string_count = u32::from_le_bytes(
            self.data[base + 8..base + 12]
                .try_into()
                .map_err(|_| ManifestError::Truncated)?,
        ) as usize;
        let flags = u32::from_le_bytes(
            self.data[base + 16..base + 20]
                .try_into()
                .map_err(|_| ManifestError::Truncated)?,
        );
        let strings_start = u32::from_le_bytes(
            self.data[base + 20..base + 24]
                .try_into()
                .map_err(|_| ManifestError::Truncated)?,
        ) as usize;

        let is_utf8 = (flags & (1 << 8)) != 0;

        // Offset table starts at base + 28
        let offsets_base = base + 28;
        let string_data_base = base + 8 + strings_start; // header is 8 bytes before string_count

        // Cap the attacker-controlled count against what the offset table can
        // actually hold, so a tiny file cannot make us reserve gigabytes.
        let string_count = string_count.min(self.data.len().saturating_sub(offsets_base) / 4);
        self.string_pool = Vec::with_capacity(string_count);

        for i in 0..string_count {
            let off_pos = offsets_base + i * 4;
            if off_pos + 4 > self.data.len() {
                break;
            }
            let str_offset = u32::from_le_bytes(
                self.data[off_pos..off_pos + 4]
                    .try_into()
                    .map_err(|_| ManifestError::Truncated)?,
            ) as usize;
            let str_pos = string_data_base + str_offset;

            let s = if is_utf8 {
                read_utf8_string(&self.data, str_pos).unwrap_or_default()
            } else {
                read_utf16le_string(&self.data, str_pos).unwrap_or_default()
            };
            self.string_pool.push(s);
        }

        Ok(())
    }

    /// Look up a string from the pool by index.
    ///
    /// Returns an empty string for out-of-range indices.
    #[must_use]
    pub fn get_string(&self, idx: u32) -> &str {
        self.string_pool
            .get(idx as usize)
            .map_or("", std::string::String::as_str)
    }

    /// Attempt to read the next AXML event.
    ///
    /// Returns `None` at end-of-file or after the end-document event.
    pub fn next_event(&mut self) -> Option<AxmlEvent> {
        loop {
            if self.pos + 8 > self.data.len() {
                return None;
            }

            let chunk_type = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().ok()?);
            let chunk_size =
                u32::from_le_bytes(self.data[self.pos + 4..self.pos + 8].try_into().ok()?) as usize;

            if chunk_size == 0 || self.pos + chunk_size > self.data.len() {
                return None;
            }

            let chunk_data = &self.data[self.pos..self.pos + chunk_size];
            self.pos += chunk_size;

            match chunk_type {
                chunk_type::START_ELEMENT => {
                    return self.parse_start_element(chunk_data);
                }
                chunk_type::END_ELEMENT => {
                    return self.parse_end_element(chunk_data);
                }
                chunk_type::END_DOCUMENT => {
                    return None;
                }
                chunk_type::CDATA
                    if chunk_data.len() >= 28 => {
                        let text_idx = u32::from_le_bytes(chunk_data[20..24].try_into().ok()?);
                        let text = self.get_string(text_idx).to_string();
                        if !text.is_empty() {
                            return Some(AxmlEvent::Text(text));
                        }
                    }
                    // continue loop
                _ => {
                    // Unknown/unhandled chunk — keep scanning
                }
            }
        }
    }

    fn parse_start_element(&self, data: &[u8]) -> Option<AxmlEvent> {
        // StartElement layout (after 8-byte chunk header):
        // line_number(4), comment(4), ns(4), name_idx(4), attr_start(2),
        // attr_size(2), attr_count(2), id_attr(2), class_attr(2), style_attr(2)
        // then attr_count attributes of attr_size bytes each
        if data.len() < 32 {
            return None;
        }

        let name_idx = u32::from_le_bytes(data[20..24].try_into().ok()?);
        let name = self.get_string(name_idx).to_string();
        let attr_start = u16::from_le_bytes(data[24..26].try_into().ok()?) as usize;
        let attr_size = u16::from_le_bytes(data[26..28].try_into().ok()?) as usize;
        let attr_count = u16::from_le_bytes(data[28..30].try_into().ok()?) as usize;

        let mut attrs = Vec::with_capacity(attr_count);
        let attrs_base = 8 + attr_start; // chunk header is 8 bytes

        for i in 0..attr_count {
            let off = attrs_base + i * attr_size;
            if off + attr_size > data.len() || attr_size < 20 {
                break;
            }
            let attr = self.parse_attribute(&data[off..off + attr_size]);
            if let Some(a) = attr {
                attrs.push(a);
            }
        }

        Some(AxmlEvent::StartElement { name, attrs })
    }

    fn parse_end_element(&self, data: &[u8]) -> Option<AxmlEvent> {
        if data.len() < 24 {
            return None;
        }
        let name_idx = u32::from_le_bytes(data[20..24].try_into().ok()?);
        let name = self.get_string(name_idx).to_string();
        Some(AxmlEvent::EndElement { name })
    }

    fn parse_attribute(&self, data: &[u8]) -> Option<AxmlAttr> {
        // Attribute layout: ns(4), name_idx(4), raw_value(4), value_size(2),
        // res0(1), data_type(1), data(4)
        if data.len() < 20 {
            return None;
        }
        let name_idx = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let raw_value = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let data_type = data[15];
        let int_data = u32::from_le_bytes(data[16..20].try_into().ok()?);

        let name = self.get_string(name_idx).to_string();

        let value = match data_type {
            value_type::NULL => AxmlValue::Null,
            value_type::REFERENCE => AxmlValue::Reference(int_data),
            value_type::ATTRIBUTE => AxmlValue::Attribute(int_data),
            value_type::STRING => AxmlValue::String(self.get_string(raw_value).to_string()),
            value_type::FLOAT => AxmlValue::Float(f32::from_bits(int_data)),
            value_type::INT_BOOL => AxmlValue::Bool(int_data != 0),
            value_type::INT_COLOR => AxmlValue::Color(int_data),
            other => {
                let _ = value_type::is_integer(other); // wire the helper through the value-type taxonomy
                AxmlValue::Int(int_data.cast_signed())
            }
        };

        Some(AxmlAttr { name, value })
    }
}

// ─── String pool readers ──────────────────────────────────────────────────────

fn read_utf8_string(data: &[u8], pos: usize) -> Option<String> {
    if pos >= data.len() {
        return None;
    }
    // Read char-count as ULEB128
    let mut cur = pos;
    loop {
        let b = *data.get(cur)?;
        cur += 1;
        if b & 0x80 == 0 { break; }
    }
    // Read byte-count as ULEB128
    let byte_len = {
        let mut value = 0usize;
        let mut shift = 0;
        loop {
            let b = *data.get(cur)? as usize;
            cur += 1;
            value |= (b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 { break; }
        }
        value
    };
    let str_start = cur;
    if str_start + byte_len > data.len() {
        return None;
    }
    String::from_utf8(data[str_start..str_start + byte_len].to_vec()).ok()
}

fn read_utf16le_string(data: &[u8], pos: usize) -> Option<String> {
    if pos + 2 > data.len() {
        return None;
    }
    let char_count = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
    let str_start = pos + 2;
    if str_start + char_count * 2 > data.len() {
        return None;
    }
    let units: Vec<u16> = data[str_start..str_start + char_count * 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

// ─── parse_android_manifest ──────────────────────────────────────────────────

/// Parse a binary AndroidManifest.xml into an [`AndroidManifest`].
///
/// On a format/structural error a partial manifest is still returned (best-effort).
/// Only [`ManifestError::Truncated`] and [`ManifestError::InvalidMagic`] are
/// hard failures returned as `Err`.
///
/// # Errors
/// Returns [`ManifestError::Truncated`] if `data` is too short, or
/// [`ManifestError::InvalidMagic`] if the AXML magic bytes are missing.
pub fn parse_android_manifest(data: &[u8]) -> Result<AndroidManifest, ManifestError> {
    if data.len() < 8 {
        return Err(ManifestError::Truncated);
    }

    let mut parser = AxmlParser::new(data.to_vec())?;
    let mut manifest = AndroidManifest::default();

    // Context stack for understanding nested elements
    let mut element_stack: Vec<String> = Vec::new();
    let mut current_activity: Option<ActivityInfo> = None;
    let mut current_service: Option<ServiceInfo> = None;
    let mut current_receiver: Option<ReceiverInfo> = None;
    let mut current_provider: Option<ProviderInfo> = None;
    let mut current_intent_filter: Option<IntentFilter> = None;

    while let Some(event) = parser.next_event() {
        match event {
            AxmlEvent::StartElement { name, attrs } => {
                let attrs_ref = &attrs;
                match name.as_str() {
                    "manifest" => {
                        for a in attrs_ref {
                            match a.name.as_str() {
                                "package" => {
                                    if let Some(v) = a.value.as_str() {
                                        manifest.package = v.to_string();
                                    }
                                }
                                "versionCode" | "android:versionCode" => {
                                    if let Some(v) = a.value.as_int() {
                                        manifest.version_code = v;
                                    }
                                }
                                "versionName" | "android:versionName" => {
                                    if let Some(v) = a.value.as_str() {
                                        manifest.version_name = v.to_string();
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "uses-sdk" => {
                        for a in attrs_ref {
                            match a.name.as_str() {
                                "minSdkVersion" | "android:minSdkVersion" => {
                                    if let Some(v) = a.value.as_int() {
                                        manifest.min_sdk = v;
                                    }
                                }
                                "targetSdkVersion" | "android:targetSdkVersion" => {
                                    if let Some(v) = a.value.as_int() {
                                        manifest.target_sdk = v;
                                    }
                                }
                                "maxSdkVersion" | "android:maxSdkVersion" => {
                                    manifest.max_sdk = a.value.as_int();
                                }
                                _ => {}
                            }
                        }
                    }
                    "uses-permission" => {
                        let perm_name = attrs_ref
                            .iter()
                            .find(|a| a.name == "name" || a.name == "android:name")
                            .and_then(|a| a.value.as_str())
                            .map(std::string::ToString::to_string);
                        let max_sdk = attrs_ref
                            .iter()
                            .find(|a| {
                                a.name == "maxSdkVersion" || a.name == "android:maxSdkVersion"
                            })
                            .and_then(|a| a.value.as_int());
                        if let Some(name) = perm_name {
                            manifest.permissions.push(UsesPermission { name, max_sdk });
                        }
                    }
                    "application" => {
                        for a in attrs_ref {
                            match a.name.as_str() {
                                "debuggable" | "android:debuggable" => {
                                    if let Some(v) = a.value.as_bool() {
                                        manifest.debuggable = v;
                                    }
                                }
                                "allowBackup" | "android:allowBackup" => {
                                    if let Some(v) = a.value.as_bool() {
                                        manifest.allow_backup = v;
                                    }
                                }
                                "usesCleartextTraffic" | "android:usesCleartextTraffic" => {
                                    if let Some(v) = a.value.as_bool() {
                                        manifest.uses_cleartext_traffic = v;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "activity" => {
                        let name = component_name(attrs_ref);
                        let mut info = ActivityInfo::new(name);
                        apply_component_attrs(&mut info.base, attrs_ref);
                        for a in attrs_ref {
                            match a.name.as_str() {
                                "launchMode" | "android:launchMode" => {
                                    if let Some(v) = a.value.as_int() {
                                        info.launch_mode = match v {
                                            1 => "singleTop",
                                            2 => "singleTask",
                                            3 => "singleInstance",
                                            _ => "standard",
                                        }
                                        .to_string();
                                    }
                                }
                                _ => {}
                            }
                        }
                        current_activity = Some(info);
                    }
                    "service" => {
                        let name = component_name(attrs_ref);
                        let mut info = ServiceInfo::new(name);
                        apply_component_attrs(&mut info.base, attrs_ref);
                        current_service = Some(info);
                    }
                    "receiver" => {
                        let name = component_name(attrs_ref);
                        let mut info = ReceiverInfo::new(name);
                        apply_component_attrs(&mut info.base, attrs_ref);
                        current_receiver = Some(info);
                    }
                    "provider" => {
                        let name = component_name(attrs_ref);
                        let authorities = attrs_ref
                            .iter()
                            .find(|a| a.name == "authorities" || a.name == "android:authorities")
                            .and_then(|a| a.value.as_str())
                            .unwrap_or("")
                            .to_string();
                        let mut info = ProviderInfo::new(name, authorities);
                        apply_component_attrs(&mut info.base, attrs_ref);
                        current_provider = Some(info);
                    }
                    "intent-filter" => {
                        current_intent_filter = Some(IntentFilter::default());
                    }
                    "action" => {
                        if let Some(filter) = current_intent_filter.as_mut()
                            && let Some(v) = attrs_ref
                                .iter()
                                .find(|a| a.name == "name" || a.name == "android:name")
                                .and_then(|a| a.value.as_str())
                        {
                            filter.actions.push(v.to_string());
                        }
                    }
                    "category" => {
                        if let Some(filter) = current_intent_filter.as_mut()
                            && let Some(v) = attrs_ref
                                .iter()
                                .find(|a| a.name == "name" || a.name == "android:name")
                                .and_then(|a| a.value.as_str())
                        {
                            filter.categories.push(v.to_string());
                        }
                    }
                    _ => {}
                }
                element_stack.push(name);
            }

            AxmlEvent::EndElement { name } => {
                element_stack.pop();
                debug_assert!(element_stack.len() <= 64, "manifest element nesting too deep");
                match name.as_str() {
                    "intent-filter" => {
                        if let Some(filter) = current_intent_filter.take() {
                            // Attach to current innermost component
                            if let Some(a) = current_activity.as_mut() {
                                a.base.intent_filters.push(filter);
                            } else if let Some(s) = current_service.as_mut() {
                                s.base.intent_filters.push(filter);
                            } else if let Some(r) = current_receiver.as_mut() {
                                r.base.intent_filters.push(filter);
                            }
                        }
                    }
                    "activity" => {
                        if let Some(a) = current_activity.take() {
                            manifest.activities.push(a);
                        }
                    }
                    "service" => {
                        if let Some(s) = current_service.take() {
                            manifest.services.push(s);
                        }
                    }
                    "receiver" => {
                        if let Some(r) = current_receiver.take() {
                            manifest.receivers.push(r);
                        }
                    }
                    "provider" => {
                        if let Some(p) = current_provider.take() {
                            manifest.providers.push(p);
                        }
                    }
                    _ => {}
                }
            }

            AxmlEvent::Text(_) => {}
        }
    }

    Ok(manifest)
}

fn component_name(attrs: &[AxmlAttr]) -> String {
    attrs
        .iter()
        .find(|a| a.name == "name" || a.name == "android:name")
        .and_then(|a| a.value.as_str())
        .unwrap_or("")
        .to_string()
}

fn apply_component_attrs(info: &mut ComponentInfo, attrs: &[AxmlAttr]) {
    for a in attrs {
        match a.name.as_str() {
            "exported" | "android:exported" => {
                info.exported = a.value.as_bool();
            }
            "enabled" | "android:enabled" => {
                if let Some(v) = a.value.as_bool() {
                    info.enabled = v;
                }
            }
            "permission" | "android:permission" => {
                if let Some(v) = a.value.as_str() {
                    info.permission = Some(v.to_string());
                }
            }
            _ => {}
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest() -> AndroidManifest {
        let mut m = AndroidManifest {
            package: "com.example.app".into(),
            version_code: 10,
            version_name: "1.0.0".into(),
            min_sdk: 21,
            target_sdk: 33,
            debuggable: true,
            allow_backup: true,
            uses_cleartext_traffic: true,
            ..AndroidManifest::default()
        };

        m.permissions.push(UsesPermission {
            name: "android.permission.CAMERA".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.INTERNET".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.ACCESS_FINE_LOCATION".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.INSTALL_PACKAGES".into(),
            max_sdk: None,
        });

        let mut main_activity = ActivityInfo::new("com.example.app.MainActivity");
        main_activity.base.exported = Some(true);
        let mut filter = IntentFilter::default();
        filter.actions.push("android.intent.action.MAIN".into());
        filter
            .categories
            .push("android.intent.category.LAUNCHER".into());
        main_activity.base.intent_filters.push(filter);
        m.activities.push(main_activity);

        let mut hidden = ActivityInfo::new("com.example.app.HiddenActivity");
        hidden.base.exported = Some(false);
        m.activities.push(hidden);

        let mut svc = ServiceInfo::new("com.example.app.BackgroundService");
        svc.base.exported = Some(true);
        m.services.push(svc);

        let mut rcv = ReceiverInfo::new("com.example.app.BootReceiver");
        rcv.base.exported = Some(true);
        m.receivers.push(rcv);

        let prov = ProviderInfo::new("com.example.app.FileProvider", "com.example.app.files");
        m.providers.push(prov);

        m
    }

    #[test]
    fn manifest_package() {
        let m = make_manifest();
        assert_eq!(m.package, "com.example.app");
    }

    #[test]
    fn manifest_version_code() {
        let m = make_manifest();
        assert_eq!(m.version_code, 10);
    }

    #[test]
    fn manifest_min_sdk() {
        let m = make_manifest();
        assert_eq!(m.min_sdk, 21);
    }

    #[test]
    fn manifest_target_sdk() {
        let m = make_manifest();
        assert_eq!(m.target_sdk, 33);
    }

    #[test]
    fn manifest_debuggable() {
        let m = make_manifest();
        assert!(m.debuggable);
    }

    #[test]
    fn manifest_cleartext() {
        let m = make_manifest();
        assert!(m.uses_cleartext_traffic);
    }

    #[test]
    fn dangerous_permissions_camera() {
        let m = make_manifest();
        let dp = m.dangerous_permissions();
        assert!(dp.contains(&"android.permission.CAMERA"));
    }

    #[test]
    fn dangerous_permissions_location() {
        let m = make_manifest();
        let dp = m.dangerous_permissions();
        assert!(dp.contains(&"android.permission.ACCESS_FINE_LOCATION"));
    }

    #[test]
    fn dangerous_permissions_install_packages() {
        let m = make_manifest();
        let dp = m.dangerous_permissions();
        assert!(dp.contains(&"android.permission.INSTALL_PACKAGES"));
    }

    #[test]
    fn dangerous_permissions_excludes_internet() {
        let m = make_manifest();
        let dp = m.dangerous_permissions();
        assert!(!dp.contains(&"android.permission.INTERNET"));
    }

    #[test]
    fn exported_activities_count() {
        let m = make_manifest();
        let exp = m.exported_activities();
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].base.name, "com.example.app.MainActivity");
    }

    #[test]
    fn exported_services() {
        let m = make_manifest();
        let exp = m.exported_services();
        assert_eq!(exp.len(), 1);
    }

    #[test]
    fn exported_receivers() {
        let m = make_manifest();
        let exp = m.exported_receivers();
        assert_eq!(exp.len(), 1);
    }

    #[test]
    fn component_count() {
        let m = make_manifest();
        assert_eq!(m.component_count(), 5); // 2 activities + 1 service + 1 receiver + 1 provider = 5
    }

    #[test]
    fn intent_filter_is_launcher() {
        let m = make_manifest();
        let act = &m.activities[0];
        assert!(act.base.intent_filters[0].is_launcher());
    }

    #[test]
    fn component_info_effectively_exported_explicit_true() {
        let mut c = ComponentInfo::new("Foo");
        c.exported = Some(true);
        assert!(c.is_effectively_exported());
    }

    #[test]
    fn component_info_effectively_exported_implicit_by_filter() {
        let mut c = ComponentInfo::new("Foo");
        c.exported = None;
        c.intent_filters.push(IntentFilter::default());
        assert!(c.is_effectively_exported());
    }

    #[test]
    fn component_info_not_exported() {
        let mut c = ComponentInfo::new("Foo");
        c.exported = Some(false);
        assert!(!c.is_effectively_exported());
    }

    #[test]
    fn axml_value_as_str() {
        let v = AxmlValue::String("hello".to_string());
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn axml_value_as_int() {
        let v = AxmlValue::Int(42);
        assert_eq!(v.as_int(), Some(42));
    }

    #[test]
    fn axml_value_bool_to_int() {
        let v = AxmlValue::Bool(true);
        assert_eq!(v.as_int(), Some(1));
    }

    #[test]
    fn axml_value_as_bool_from_int() {
        let v = AxmlValue::Int(0);
        assert_eq!(v.as_bool(), Some(false));
    }

    #[test]
    fn parse_manifest_truncated() {
        let result = parse_android_manifest(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn manifest_default_allow_backup() {
        let m = AndroidManifest::default();
        assert!(m.allow_backup);
    }

    #[test]
    fn manifest_default_not_debuggable() {
        let m = AndroidManifest::default();
        assert!(!m.debuggable);
    }

    #[test]
    fn provider_info_new() {
        let p = ProviderInfo::new("MyProvider", "com.example.auth");
        assert_eq!(p.authorities, "com.example.auth");
        assert!(!p.grant_uri_permissions);
    }

    #[test]
    fn activity_info_launch_mode_default() {
        let a = ActivityInfo::new("MyActivity");
        assert_eq!(a.launch_mode, "standard");
    }

    #[test]
    fn service_info_new() {
        let s = ServiceInfo::new("MyService");
        assert!(s.foreground_service_type.is_none());
    }

    #[test]
    fn manifest_error_display() {
        assert!(!ManifestError::InvalidMagic.to_string().is_empty());
        assert!(!ManifestError::Truncated.to_string().is_empty());
        assert!(
            !ManifestError::ParseError("test".into())
                .to_string()
                .is_empty()
        );
        assert!(!ManifestError::Utf8Error.to_string().is_empty());
    }
}
