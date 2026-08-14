//! Android permission analysis: binary XML (AXML) parsing, permission groups,
//! dangerous permissions, custom permissions, manifest component analysis.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("invalid AXML magic: expected 0x00080003, got {0:#010x}")]
    BadAxml(u32),
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
    #[error("unsupported AXML chunk type {0:#06x}")]
    UnknownChunk(u16),
}

pub type PermissionResult<T> = Result<T, PermissionError>;

// ── Protection levels ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLevel {
    Normal,
    Dangerous,
    Signature,
    SignatureOrSystem,
    /// Android 6.0+ appOps overlay
    Preinstalled,
    Installer,
    Privileged,
    Development,
    AppOp,
    Pre23,
    Installer2,
    Runtime,
    OEM,
    VendorPrivileged,
    TextClassifier,
    Unknown(u32),
}

impl ProtectionLevel {
    #[must_use] 
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0xF {
            0x0 => Self::Normal,
            0x1 => Self::Dangerous,
            0x2 => Self::Signature,
            0x3 => Self::SignatureOrSystem,
            n => Self::Unknown(n),
        }
    }

    #[must_use] 
    pub const fn is_dangerous(&self) -> bool {
        matches!(self, Self::Dangerous)
    }

    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Dangerous => "dangerous",
            Self::Signature => "signature",
            Self::SignatureOrSystem => "signatureOrSystem",
            Self::Preinstalled => "preinstalled",
            Self::Installer => "installer",
            Self::Privileged => "privileged",
            Self::Development => "development",
            Self::AppOp => "appOp",
            Self::Pre23 => "pre23",
            Self::Installer2 => "installer2",
            Self::Runtime => "runtime",
            Self::OEM => "oem",
            Self::VendorPrivileged => "vendorPrivileged",
            Self::TextClassifier => "textClassifier",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ── Permission group ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionGroup {
    Calendar,
    CallLog,
    Camera,
    Contacts,
    Location,
    Microphone,
    NearbyDevices,
    Notifications,
    Phone,
    ReadMediaAural,
    ReadMediaVisual,
    Sensors,
    Sms,
    Storage,
    Custom(String),
    None,
}

impl PermissionGroup {
    #[must_use] 
    pub fn from_permission(name: &str) -> Self {
        match name {
            n if n.contains("CALENDAR") => Self::Calendar,
            n if n.contains("CALL_LOG") || n.contains("READ_CALL_LOG") => Self::CallLog,
            n if n.contains("CAMERA") => Self::Camera,
            n if n.contains("CONTACTS") || n.contains("GET_ACCOUNTS") => Self::Contacts,
            n if n.contains("LOCATION") => Self::Location,
            n if n.contains("RECORD_AUDIO") || n.contains("MICROPHONE") => Self::Microphone,
            n if n.contains("BLUETOOTH") || n.contains("UWB_RANGING") => Self::NearbyDevices,
            n if n.contains("POST_NOTIFICATIONS") => Self::Notifications,
            n if n.contains("PHONE_STATE") || n.contains("CALL_PHONE") || n.contains("READ_PHONE") => Self::Phone,
            n if n.contains("READ_MEDIA_AUDIO") => Self::ReadMediaAural,
            n if n.contains("READ_MEDIA_IMAGE") || n.contains("READ_MEDIA_VIDEO") => Self::ReadMediaVisual,
            n if n.contains("BODY_SENSORS") => Self::Sensors,
            n if n.contains("SMS") || n.contains("MMS") => Self::Sms,
            n if n.contains("WRITE_EXTERNAL_STORAGE") || n.contains("READ_EXTERNAL_STORAGE") => Self::Storage,
            _ => Self::None,
        }
    }
}

// ── Well-known dangerous permissions ──────────────────────────────────────────

/// Android-13 dangerous permission list from the platform.
pub const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.UWB_RANGING",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.USE_EXACT_ALARM",
];

/// Permissions that are particularly high-risk / often abused.
pub const HIGH_RISK_PERMISSIONS: &[&str] = &[
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    // System-level
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.ACCESSIBILITY_SERVICE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.MANAGE_OVERLAY_PERMISSION",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.HIDE_OVERLAY_WINDOWS",
];

// ── Permission entry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub protection_level: ProtectionLevel,
    pub group: PermissionGroup,
    pub is_dangerous: bool,
    pub is_high_risk: bool,
    pub is_custom: bool,
}

impl Permission {
    pub fn new(name: impl Into<String>, protection_level: ProtectionLevel) -> Self {
        let name = name.into();
        let group = PermissionGroup::from_permission(&name);
        let is_dangerous = DANGEROUS_PERMISSIONS.contains(&name.as_str())
            || protection_level.is_dangerous();
        let is_high_risk = HIGH_RISK_PERMISSIONS.contains(&name.as_str());
        let is_custom = !name.starts_with("android.permission.")
            && !name.starts_with("com.android.")
            && !name.starts_with("android.Manifest.");
        Self {
            name,
            protection_level,
            group,
            is_dangerous,
            is_high_risk,
            is_custom,
        }
    }
}

// ── Component kind ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentKind {
    Activity,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::Service => "service",
            Self::Receiver => "receiver",
            Self::Provider => "provider",
        }
    }
}

// ── Intent filter ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
    pub data_types: Vec<String>,
}

impl IntentFilter {
    #[must_use] 
    pub fn has_action(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
    }

    #[must_use] 
    pub fn is_main_launcher(&self) -> bool {
        self.has_action("android.intent.action.MAIN")
            && self.categories.iter().any(|c| c == "android.intent.category.LAUNCHER")
    }
}

// ── Component ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestComponent {
    pub name: String,
    pub kind: ComponentKind,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub enabled: bool,
    pub intent_filters: Vec<IntentFilter>,
    pub process: Option<String>,
}

impl ManifestComponent {
    /// A component is effectively exported if explicitly true, or if it has
    /// intent-filters and exported is not explicitly false.
    #[must_use] 
    pub const fn is_effectively_exported(&self) -> bool {
        match self.exported {
            Some(true) => true,
            Some(false) => false,
            None => !self.intent_filters.is_empty(),
        }
    }

    #[must_use] 
    pub const fn is_unprotected_exported(&self) -> bool {
        self.is_effectively_exported() && self.permission.is_none()
    }
}

// ── AXML parser ───────────────────────────────────────────────────────────────

/// Android Binary XML (AXML) chunk types.
const AXML_MAGIC: u32 = 0x0008_0003;
const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_START_NS: u16 = 0x0100;
const CHUNK_END_NS: u16 = 0x0101;
const CHUNK_START_ELEMENT: u16 = 0x0102;
const CHUNK_END_ELEMENT: u16 = 0x0103;

/// Minimal AXML parser for extracting manifest declarations.
pub struct AxmlParser<'a> {
    data: &'a [u8],
    pos: usize,
    string_pool: Vec<String>,
}

impl<'a> AxmlParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, string_pool: Vec::new() }
    }

    fn read_u16(&mut self) -> PermissionResult<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(PermissionError::UnexpectedEof(self.pos));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> PermissionResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(PermissionError::UnexpectedEof(self.pos));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_i32(&mut self) -> PermissionResult<i32> {
        Ok(self.read_u32()? as i32)
    }

    const fn skip(&mut self, n: usize) -> PermissionResult<()> {
        if self.pos + n > self.data.len() {
            return Err(PermissionError::UnexpectedEof(self.pos));
        }
        self.pos += n;
        Ok(())
    }

    fn str_at(&self, idx: i32) -> String {
        if idx < 0 {
            return String::new();
        }
        self.string_pool
            .get(idx as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn parse_string_pool(&mut self, chunk_size: u32) -> PermissionResult<()> {
        let start = self.pos;
        let string_count = self.read_u32()? as usize;
        let _style_count = self.read_u32()?;
        let _flags = self.read_u32()?;
        let strings_start = self.read_u32()? as usize;
        let _styles_start = self.read_u32()?;

        // Read string offsets
        let mut offsets = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            offsets.push(self.read_u32()? as usize);
        }

        // String data base = chunk start + 8 (chunk header) + strings_start
        let str_data_base = start - 8 + 8 + strings_start;

        for off in offsets {
            let str_off = str_data_base + off;
            if str_off + 2 > self.data.len() {
                self.string_pool.push(String::new());
                continue;
            }
            let char_len = u16::from_le_bytes([self.data[str_off], self.data[str_off + 1]]) as usize;
            let byte_off = str_off + 2;
            let byte_end = (byte_off + char_len * 2).min(self.data.len());
            // UTF-16LE decode
            let u16_chars: Vec<u16> = self.data[byte_off..byte_end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&u16_chars);
            self.string_pool.push(s);
        }

        // Advance past the chunk
        let end = (start - 8 + chunk_size as usize).min(self.data.len());
        self.pos = end;
        Ok(())
    }

    /// Parse the AXML and return a flat list of (`element_name`, attrs) tuples.
    ///
    /// # Errors
    /// Returns a `PermissionError` if the AXML magic, header, or chunk
    /// structure is malformed.
    pub fn parse_elements(&mut self) -> PermissionResult<Vec<(String, HashMap<String, String>)>> {
        // File header
        let magic = self.read_u32()?;
        if magic != AXML_MAGIC {
            return Err(PermissionError::BadAxml(magic));
        }
        let _file_size = self.read_u32()?;

        let mut elements = Vec::new();

        while self.pos + 8 <= self.data.len() {
            let chunk_type = self.read_u16()?;
            let _chunk_hdr_size = self.read_u16()?;
            let chunk_size = self.read_u32()?;
            let chunk_data_start = self.pos;

            match chunk_type {
                CHUNK_STRING_POOL => {
                    self.parse_string_pool(chunk_size)?;
                }
                CHUNK_START_NS | CHUNK_END_NS => {
                    // namespace mapping: line, comment, prefix, uri
                    self.skip(chunk_size as usize - 8)?;
                }
                CHUNK_START_ELEMENT => {
                    // line_number, comment, ns, name, attribute_start, attr_size, attr_count, ...
                    let _line = self.read_u32()?;
                    let _comment = self.read_i32()?;
                    let _ns = self.read_i32()?;
                    let name_idx = self.read_i32()?;
                    let _attr_start = self.read_u16()?;
                    let _attr_size = self.read_u16()?;
                    let attr_count = self.read_u16()? as usize;
                    let _id_attr = self.read_u16()?;
                    let _class_attr = self.read_u16()?;
                    let _style_attr = self.read_u16()?;

                    let elem_name = self.str_at(name_idx);
                    let mut attrs = HashMap::new();

                    for _ in 0..attr_count {
                        let _attr_ns = self.read_i32()?;
                        let attr_name_idx = self.read_i32()?;
                        let attr_raw_val_idx = self.read_i32()?;
                        let _attr_size = self.read_u16()?;
                        let _attr_res0 = self.read_u8_skip()?;
                        let attr_type = self.read_u8_skip()?;
                        let attr_data = self.read_u32()?;

                        let attr_name = self.str_at(attr_name_idx);
                        let attr_val = if attr_raw_val_idx >= 0 {
                            self.str_at(attr_raw_val_idx)
                        } else {
                            // Decode typed value
                            match attr_type {
                                0x10 => attr_data.to_string(),           // INT_DEC
                                0x11 => format!("{attr_data:#010x}"),  // INT_HEX
                                0x12 => if attr_data != 0 { "true".into() } else { "false".into() }, // INT_BOOL
                                _ => format!("@0x{attr_data:08x}"),
                            }
                        };
                        if !attr_name.is_empty() {
                            attrs.insert(attr_name, attr_val);
                        }
                    }
                    elements.push((elem_name, attrs));

                    // Advance to end of chunk
                    let chunk_end = chunk_data_start - 8 + chunk_size as usize;
                    if self.pos < chunk_end {
                        self.pos = chunk_end.min(self.data.len());
                    }
                }
                CHUNK_END_ELEMENT => {
                    self.skip(chunk_size as usize - 8)?;
                }
                _ => {
                    // Skip unknown chunk
                    let skip = (chunk_size as usize).saturating_sub(8);
                    if self.pos + skip > self.data.len() {
                        break;
                    }
                    self.pos += skip;
                }
            }
        }

        Ok(elements)
    }

    fn read_u8_skip(&mut self) -> PermissionResult<u8> {
        if self.pos >= self.data.len() {
            return Err(PermissionError::UnexpectedEof(self.pos));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }
}

// ── Manifest analyser ─────────────────────────────────────────────────────────

/// Full parsed manifest permission + component analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestAnalysis {
    pub package_name: String,
    pub version_code: u32,
    pub version_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub uses_permissions: Vec<Permission>,
    pub declares_permissions: Vec<Permission>,
    pub components: Vec<ManifestComponent>,
}

impl ManifestAnalysis {
    #[must_use] 
    pub fn dangerous_permissions(&self) -> Vec<&Permission> {
        self.uses_permissions.iter().filter(|p| p.is_dangerous).collect()
    }

    #[must_use] 
    pub fn high_risk_permissions(&self) -> Vec<&Permission> {
        self.uses_permissions.iter().filter(|p| p.is_high_risk).collect()
    }

    #[must_use] 
    pub fn custom_permissions(&self) -> Vec<&Permission> {
        self.declares_permissions.iter().filter(|p| p.is_custom).collect()
    }

    #[must_use] 
    pub fn exported_components(&self) -> Vec<&ManifestComponent> {
        self.components
            .iter()
            .filter(|c| c.is_effectively_exported())
            .collect()
    }

    #[must_use] 
    pub fn unprotected_exported_components(&self) -> Vec<&ManifestComponent> {
        self.components
            .iter()
            .filter(|c| c.is_unprotected_exported())
            .collect()
    }

    #[must_use] 
    pub fn permissions_by_group(&self) -> HashMap<String, Vec<&Permission>> {
        let mut map: HashMap<String, Vec<&Permission>> = HashMap::new();
        for p in &self.uses_permissions {
            let key = format!("{:?}", p.group);
            map.entry(key).or_default().push(p);
        }
        map
    }

    #[must_use] 
    pub fn risk_score(&self) -> u32 {
        let mut score = 0u32;
        score += self.high_risk_permissions().len() as u32 * 10;
        score += self.dangerous_permissions().len() as u32 * 3;
        score += self.unprotected_exported_components().len() as u32 * 5;
        score += self.custom_permissions().len() as u32 * 2;
        score
    }
}

/// Parse an `AndroidManifest.xml` in AXML binary format.
///
/// # Errors
/// Returns a `PermissionError` when the AXML payload is malformed or contains
/// elements/attributes whose structure cannot be decoded.
pub fn parse_manifest_axml(data: &[u8]) -> PermissionResult<ManifestAnalysis> {
    let mut parser = AxmlParser::new(data);
    let elements = parser.parse_elements()?;

    let mut analysis = ManifestAnalysis::default();
    let mut component_stack: Vec<ManifestComponent> = Vec::new();
    let mut current_intent_filter: Option<IntentFilter> = None;

    for (elem, attrs) in &elements {
        match elem.as_str() {
            "manifest" => {
                analysis.package_name = attrs.get("package").cloned().unwrap_or_default();
                analysis.version_code = attrs
                    .get("versionCode")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                analysis.version_name = attrs.get("versionName").cloned().unwrap_or_default();
            }
            "uses-sdk" => {
                analysis.min_sdk = attrs
                    .get("minSdkVersion")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                analysis.target_sdk = attrs
                    .get("targetSdkVersion")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
            "uses-permission" => {
                if let Some(name) = attrs.get("name") {
                    let prot = ProtectionLevel::Normal;
                    analysis.uses_permissions.push(Permission::new(name, prot));
                }
            }
            "permission" => {
                if let Some(name) = attrs.get("name") {
                    let prot_flags = attrs
                        .get("protectionLevel")
                        .and_then(|v| {
                            if v.starts_with("0x") || v.starts_with("@0x") {
                                let hex = v.trim_start_matches("@0x").trim_start_matches("0x");
                                u32::from_str_radix(hex, 16).ok()
                            } else {
                                v.parse().ok()
                            }
                        })
                        .unwrap_or(0);
                    let prot = ProtectionLevel::from_flags(prot_flags);
                    analysis.declares_permissions.push(Permission::new(name, prot));
                }
            }
            kind @ ("activity" | "service" | "receiver" | "provider") => {
                let component_kind = match kind {
                    "activity" => ComponentKind::Activity,
                    "service" => ComponentKind::Service,
                    "receiver" => ComponentKind::Receiver,
                    _ => ComponentKind::Provider,
                };
                let name = attrs.get("name").cloned().unwrap_or_default();
                let exported = attrs.get("exported").map(|v| v == "true");
                let permission = attrs.get("permission").cloned();
                let enabled = attrs.get("enabled").is_none_or(|v| v != "false");
                let process = attrs.get("process").cloned();

                component_stack.push(ManifestComponent {
                    name,
                    kind: component_kind,
                    exported,
                    permission,
                    enabled,
                    intent_filters: Vec::new(),
                    process,
                });
            }
            "intent-filter" => {
                current_intent_filter = Some(IntentFilter::default());
            }
            "action" => {
                if let Some(filter) = current_intent_filter.as_mut()
                    && let Some(name) = attrs.get("name") {
                        filter.actions.push(name.clone());
                    }
            }
            "category" => {
                if let Some(filter) = current_intent_filter.as_mut()
                    && let Some(name) = attrs.get("name") {
                        filter.categories.push(name.clone());
                    }
            }
            "data" => {
                if let Some(filter) = current_intent_filter.as_mut() {
                    if let Some(scheme) = attrs.get("scheme") {
                        filter.data_schemes.push(scheme.clone());
                    }
                    if let Some(host) = attrs.get("host") {
                        filter.data_hosts.push(host.clone());
                    }
                    if let Some(mime) = attrs.get("mimeType") {
                        filter.data_types.push(mime.clone());
                    }
                }
            }
            _ => {}
        }

        // Handle end of intent-filter or component by checking next elem
        // In a real parser we'd track element depth; here we use heuristics.
        if matches!(elem.as_str(), "intent-filter") {
            // Push to last component when the filter is complete
        }
    }

    // Flush any incomplete component/filter state
    if let Some(filter) = current_intent_filter.take()
        && let Some(comp) = component_stack.last_mut() {
            comp.intent_filters.push(filter);
        }
    analysis.components.extend(component_stack);

    Ok(analysis)
}

// ── Text manifest parser (fallback) ──────────────────────────────────────────

/// Parse a plain-text AndroidManifest.xml (e.g. from apktool output).
#[must_use] 
pub fn parse_manifest_text(xml: &str) -> ManifestAnalysis {
    let mut analysis = ManifestAnalysis::default();

    for line in xml.lines() {
        let line = line.trim();
        if line.contains("package=")
            && let Some(pkg) = extract_attr(line, "package") {
                analysis.package_name = pkg;
            }
        if line.starts_with("<uses-permission")
            && let Some(name) = extract_attr(line, "android:name") {
                analysis.uses_permissions.push(Permission::new(name, ProtectionLevel::Normal));
            }
        if line.starts_with("<permission ")
            && let Some(name) = extract_attr(line, "android:name") {
                let prot_str = extract_attr(line, "android:protectionLevel")
                    .unwrap_or_default();
                let prot_flags: u32 = prot_str.trim_start_matches("0x")
                    .parse()
                    .or_else(|_| u32::from_str_radix(prot_str.trim_start_matches("0x"), 16))
                    .unwrap_or(0);
                analysis.declares_permissions.push(Permission::new(name, ProtectionLevel::from_flags(prot_flags)));
            }
        for kind in &["activity", "service", "receiver", "provider"] {
            if line.starts_with(&format!("<{kind}")) {
                let name = extract_attr(line, "android:name").unwrap_or_default();
                let exported = extract_attr(line, "android:exported").map(|v| v == "true");
                let permission = extract_attr(line, "android:permission");
                analysis.components.push(ManifestComponent {
                    name,
                    kind: match *kind {
                        "activity" => ComponentKind::Activity,
                        "service" => ComponentKind::Service,
                        "receiver" => ComponentKind::Receiver,
                        _ => ComponentKind::Provider,
                    },
                    exported,
                    permission,
                    enabled: true,
                    intent_filters: Vec::new(),
                    process: None,
                });
            }
        }
    }

    analysis
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let search = format!("{attr}=\"");
    let start = line.find(&search)? + search.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_owned())
}

// ── Report ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionReport {
    pub package: String,
    pub total_permissions: usize,
    pub dangerous_count: usize,
    pub high_risk_count: usize,
    pub custom_declared: usize,
    pub exported_components: usize,
    pub unprotected_exported: usize,
    pub risk_score: u32,
    pub high_risk_names: Vec<String>,
    pub unprotected_component_names: Vec<String>,
}

impl PermissionReport {
    #[must_use] 
    pub fn from_analysis(a: &ManifestAnalysis) -> Self {
        let high_risk_names = a
            .high_risk_permissions()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let unprotected_component_names = a
            .unprotected_exported_components()
            .iter()
            .map(|c| format!("{} ({})", c.name, c.kind.as_str()))
            .collect();
        Self {
            package: a.package_name.clone(),
            total_permissions: a.uses_permissions.len(),
            dangerous_count: a.dangerous_permissions().len(),
            high_risk_count: a.high_risk_permissions().len(),
            custom_declared: a.custom_permissions().len(),
            exported_components: a.exported_components().len(),
            unprotected_exported: a.unprotected_exported_components().len(),
            risk_score: a.risk_score(),
            high_risk_names,
            unprotected_component_names,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_level() {
        assert!(ProtectionLevel::from_flags(1).is_dangerous());
        assert!(!ProtectionLevel::from_flags(0).is_dangerous());
        assert_eq!(ProtectionLevel::from_flags(2).as_str(), "signature");
    }

    #[test]
    fn test_permission_group() {
        assert_eq!(
            PermissionGroup::from_permission("android.permission.CAMERA"),
            PermissionGroup::Camera
        );
        assert_eq!(
            PermissionGroup::from_permission("android.permission.ACCESS_FINE_LOCATION"),
            PermissionGroup::Location
        );
    }

    #[test]
    fn test_permission_high_risk() {
        let p = Permission::new("android.permission.CAMERA", ProtectionLevel::Dangerous);
        assert!(p.is_dangerous);
        assert!(p.is_high_risk);
        assert!(!p.is_custom);
    }

    #[test]
    fn test_custom_permission() {
        let p = Permission::new("com.myapp.CUSTOM_PERM", ProtectionLevel::Signature);
        assert!(p.is_custom);
    }

    #[test]
    fn test_component_exported() {
        let c = ManifestComponent {
            name: "com.example.MyActivity".into(),
            kind: ComponentKind::Activity,
            exported: None,
            permission: None,
            enabled: true,
            intent_filters: vec![IntentFilter::default()],
            process: None,
        };
        assert!(c.is_effectively_exported());
        assert!(c.is_unprotected_exported());
    }

    #[test]
    fn test_parse_manifest_text() {
        let xml = r#"<manifest package="com.example">
        <uses-permission android:name="android.permission.CAMERA"/>
        <uses-permission android:name="android.permission.INTERNET"/>
        <activity android:name=".MainActivity" android:exported="true"/>
        </manifest>"#;
        let a = parse_manifest_text(xml);
        assert_eq!(a.package_name, "com.example");
        assert_eq!(a.uses_permissions.len(), 2);
        assert_eq!(a.components.len(), 1);
        let report = PermissionReport::from_analysis(&a);
        assert!(report.high_risk_count > 0);
    }
}
