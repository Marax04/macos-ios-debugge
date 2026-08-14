// APK threat modeling: permissions, exported components, dynamic loading, risk scoring
// Part of rustre-mobile-apktool

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PermissionCategory {
    Location,
    Camera,
    Microphone,
    Contacts,
    Storage,
    Phone,
    Sms,
    Calendar,
    BodySensors,
    CallLog,
    Notifications,
    Overlay,
    Accessibility,
    DeviceAdmin,
    Unknown,
}

impl PermissionCategory {
    #[must_use] 
    pub fn from_name(name: &str) -> Self {
        if name.contains("LOCATION") { return Self::Location; }
        if name.contains("CAMERA") { return Self::Camera; }
        if name.contains("RECORD_AUDIO") || name.contains("MICROPHONE") { return Self::Microphone; }
        if name.contains("CONTACTS") || name.contains("GET_ACCOUNTS") { return Self::Contacts; }
        if name.contains("STORAGE") || name.contains("READ_EXTERNAL") || name.contains("WRITE_EXTERNAL") { return Self::Storage; }
        if name.contains("CALL_PHONE") || name.contains("READ_PHONE") || name.contains("PROCESS_OUTGOING_CALLS") { return Self::Phone; }
        if name.contains("SEND_SMS") || name.contains("READ_SMS") || name.contains("RECEIVE_SMS") { return Self::Sms; }
        if name.contains("CALENDAR") { return Self::Calendar; }
        if name.contains("BODY_SENSORS") { return Self::BodySensors; }
        if name.contains("READ_CALL_LOG") || name.contains("WRITE_CALL_LOG") { return Self::CallLog; }
        if name.contains("POST_NOTIFICATIONS") { return Self::Notifications; }
        if name.contains("SYSTEM_ALERT_WINDOW") { return Self::Overlay; }
        if name.contains("BIND_ACCESSIBILITY") || name.contains("ACCESSIBILITY") { return Self::Accessibility; }
        if name.contains("DEVICE_ADMIN") || name.contains("BIND_DEVICE_ADMIN") { return Self::DeviceAdmin; }
        Self::Unknown
    }

    #[must_use] 
    pub const fn base_risk(&self) -> u8 {
        match self {
            Self::DeviceAdmin | Self::Accessibility | Self::Overlay => 90,
            Self::Sms | Self::CallLog => 75,
            Self::Camera | Self::Microphone => 70,
            Self::Location => 65,
            Self::Contacts | Self::Phone => 60,
            Self::Storage => 50,
            Self::Calendar | Self::BodySensors => 45,
            Self::Notifications => 20,
            Self::Unknown => 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Permission {
    pub name: String,
    pub category: PermissionCategory,
    pub protection_level: ProtectionLevel,
    pub is_dangerous: bool,
    pub declared_by_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionLevel {
    Normal,
    Dangerous,
    Signature,
    SignatureOrSystem,
    AppOp,
    Preinstalled,
    Unknown,
}

impl ProtectionLevel {
    #[must_use] 
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "normal" => Self::Normal,
            "dangerous" => Self::Dangerous,
            "signature" => Self::Signature,
            "signatureorsystem" | "signatureorprivileged" => Self::SignatureOrSystem,
            "appop" => Self::AppOp,
            "preinstalled" => Self::Preinstalled,
            _ => Self::Unknown,
        }
    }
}

impl Permission {
    pub fn new(name: impl Into<String>) -> Self {
        let name: String = name.into();
        let category = PermissionCategory::from_name(&name);
        let is_dangerous = matches!(category,
            PermissionCategory::Location | PermissionCategory::Camera |
            PermissionCategory::Microphone | PermissionCategory::Contacts |
            PermissionCategory::Storage | PermissionCategory::Phone |
            PermissionCategory::Sms | PermissionCategory::Calendar |
            PermissionCategory::BodySensors | PermissionCategory::CallLog |
            PermissionCategory::DeviceAdmin | PermissionCategory::Accessibility |
            PermissionCategory::Overlay
        );
        Self {
            name,
            category,
            protection_level: ProtectionLevel::Unknown,
            is_dangerous,
            declared_by_self: false,
        }
    }

    #[must_use] 
    pub fn risk_score(&self) -> u8 {
        let base = self.category.base_risk();
        if self.declared_by_self {
            // Self-declared custom permissions are suspicious
            base.saturating_add(10).min(100)
        } else {
            base
        }
    }
}

// ---------------------------------------------------------------------------
// Exported components
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentKind {
    Activity,
    Service,
    BroadcastReceiver,
    ContentProvider,
}

impl ComponentKind {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::Service => "service",
            Self::BroadcastReceiver => "receiver",
            Self::ContentProvider => "provider",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExportedComponent {
    pub kind: ComponentKind,
    pub class_name: String,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
    pub is_exported_explicit: bool,
    pub is_exported_implicit: bool,
    pub grant_uri_permissions: bool,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
}

impl ExportedComponent {
    #[must_use] 
    pub const fn is_exported(&self) -> bool {
        self.is_exported_explicit || self.is_exported_implicit
    }

    #[must_use] 
    pub const fn has_no_permission(&self) -> bool {
        self.permission.is_none()
            && self.read_permission.is_none()
            && self.write_permission.is_none()
    }

    #[must_use] 
    pub const fn is_high_risk(&self) -> bool {
        self.is_exported() && self.has_no_permission()
    }

    #[must_use] 
    pub fn component_risk(&self) -> u8 {
        if !self.is_exported() {
            return 0;
        }
        let base: u8 = match self.kind {
            ComponentKind::ContentProvider => 60,
            ComponentKind::BroadcastReceiver => 50,
            ComponentKind::Service => 55,
            ComponentKind::Activity => 35,
        };
        if self.has_no_permission() {
            base.saturating_add(30).min(100)
        } else {
            base
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic code loading indicators
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicCodeKind {
    DexClassLoader,
    PathClassLoader,
    InMemoryDexClassLoader,
    LoadLibrary,
    AssetDex,
    EncryptedPayload,
    ReflectiveLoad,
}

impl DynamicCodeKind {
    #[must_use] 
    pub const fn risk(&self) -> u8 {
        match self {
            Self::InMemoryDexClassLoader | Self::EncryptedPayload => 95,
            Self::DexClassLoader | Self::ReflectiveLoad => 85,
            Self::LoadLibrary | Self::AssetDex => 70,
            Self::PathClassLoader => 60,
        }
    }

    #[must_use] 
    pub const fn description(&self) -> &'static str {
        match self {
            Self::DexClassLoader => "DexClassLoader — loads DEX/JAR from file path at runtime",
            Self::PathClassLoader => "PathClassLoader — loads classes from path at runtime",
            Self::InMemoryDexClassLoader => "InMemoryDexClassLoader — loads DEX from memory buffer (highly suspicious)",
            Self::LoadLibrary => "System.loadLibrary / Runtime.load — loads native .so",
            Self::AssetDex => "DEX/JAR loaded from assets directory",
            Self::EncryptedPayload => "Encrypted payload decrypted and loaded at runtime",
            Self::ReflectiveLoad => "Class loaded via reflection (Class.forName)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DynamicCodeUsage {
    pub kind: DynamicCodeKind,
    pub location: String,
    pub path_hint: Option<String>,
}

// ---------------------------------------------------------------------------
// Background service abuse
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackgroundAbuse {
    ForegroundServiceAbuse,
    WakeLockHeld,
    AlarmManagerAbuse,
    JobSchedulerBypass,
    WorkManagerAbuse,
    StickyService,
    BootReceiver,
    PersistentProcess,
}

impl BackgroundAbuse {
    #[must_use] 
    pub const fn description(&self) -> &'static str {
        match self {
            Self::ForegroundServiceAbuse => "Foreground service used without user-visible notification",
            Self::WakeLockHeld => "WakeLock acquired without release — battery drain",
            Self::AlarmManagerAbuse => "AlarmManager with short interval — persistent execution",
            Self::JobSchedulerBypass => "JobScheduler used to evade battery optimization",
            Self::WorkManagerAbuse => "WorkManager periodic work with minimal interval",
            Self::StickyService => "Service returns START_STICKY — restarts on kill",
            Self::BootReceiver => "BOOT_COMPLETED receiver — executes on device start",
            Self::PersistentProcess => "android:persistent=true — survives system cleanup",
        }
    }

    #[must_use] 
    pub const fn risk(&self) -> u8 {
        match self {
            Self::PersistentProcess | Self::ForegroundServiceAbuse => 70,
            Self::BootReceiver | Self::StickyService => 65,
            Self::WakeLockHeld | Self::AlarmManagerAbuse => 55,
            Self::JobSchedulerBypass | Self::WorkManagerAbuse => 45,
        }
    }
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RiskFactor {
    pub category: RiskCategory,
    pub description: String,
    pub score: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskCategory {
    DangerousPermissions,
    ExportedComponents,
    DynamicCodeLoading,
    BackgroundPersistence,
    CryptoWeakness,
    AntiAnalysis,
    PrivacyLeak,
    NetworkSecurity,
}

impl RiskCategory {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DangerousPermissions => "Dangerous Permissions",
            Self::ExportedComponents => "Exported Components",
            Self::DynamicCodeLoading => "Dynamic Code Loading",
            Self::BackgroundPersistence => "Background Persistence",
            Self::CryptoWeakness => "Cryptographic Weakness",
            Self::AntiAnalysis => "Anti-Analysis Techniques",
            Self::PrivacyLeak => "Privacy Data Leakage",
            Self::NetworkSecurity => "Network Security",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub overall: u8,
    pub factors: Vec<RiskFactor>,
    pub level: ThreatLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    #[must_use] 
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=20 => Self::Clean,
            21..=40 => Self::Low,
            41..=60 => Self::Medium,
            61..=80 => Self::High,
            _ => Self::Critical,
        }
    }

    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl RiskScore {
    #[must_use] 
    pub fn compute(factors: Vec<RiskFactor>) -> Self {
        if factors.is_empty() {
            return Self { overall: 0, factors, level: ThreatLevel::Clean };
        }
        // Weighted combination: max factor contributes 40%, average 60%
        let max_score = factors.iter().map(|f| u32::from(f.score)).max().unwrap_or(0);
        let avg_score = factors.iter().map(|f| u32::from(f.score)).sum::<u32>() / u32::try_from(factors.len()).unwrap_or(u32::MAX);
        let overall = ((max_score * 40 + avg_score * 60) / 100).min(100) as u8;
        let level = ThreatLevel::from_score(overall);
        Self { overall, factors, level }
    }
}

// ---------------------------------------------------------------------------
// Threat model
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ThreatModel {
    pub package_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub permissions: Vec<Permission>,
    pub exported_components: Vec<ExportedComponent>,
    pub dynamic_code_usages: Vec<DynamicCodeUsage>,
    pub background_abuses: Vec<BackgroundAbuse>,
    pub custom_trust_managers: Vec<String>,
    pub cleartext_traffic_allowed: bool,
    pub debuggable: bool,
    pub allow_backup: bool,
    pub network_security_config: Option<String>,
    pub uses_obfuscation: bool,
    pub native_libs: Vec<String>,
}

impl ThreatModel {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn dangerous_permissions(&self) -> Vec<&Permission> {
        self.permissions.iter().filter(|p| p.is_dangerous).collect()
    }

    #[must_use] 
    pub fn exported_without_permission(&self) -> Vec<&ExportedComponent> {
        self.exported_components.iter()
            .filter(|c| c.is_exported() && c.has_no_permission())
            .collect()
    }

    #[must_use] 
    pub fn high_risk_dynamic_loads(&self) -> Vec<&DynamicCodeUsage> {
        self.dynamic_code_usages.iter()
            .filter(|d| d.kind.risk() >= 70)
            .collect()
    }

    #[must_use] 
    pub fn build_risk_factors(&self) -> Vec<RiskFactor> {
        let mut factors = Vec::new();

        // Dangerous permissions
        let dangerous = self.dangerous_permissions();
        if !dangerous.is_empty() {
            let max_perm_risk = dangerous.iter().map(|p| p.risk_score()).max().unwrap_or(0);
            let evidence: Vec<String> = dangerous.iter().map(|p| p.name.clone()).collect();
            factors.push(RiskFactor {
                category: RiskCategory::DangerousPermissions,
                description: format!("{} dangerous permission(s) requested", dangerous.len()),
                score: max_perm_risk,
                evidence,
            });
        }

        // Exported components without permission
        let exposed = self.exported_without_permission();
        if !exposed.is_empty() {
            let max_comp_risk = exposed.iter().map(|c| c.component_risk()).max().unwrap_or(0);
            let evidence: Vec<String> = exposed.iter().map(|c| {
                format!("{} {}", c.kind.as_str(), c.class_name)
            }).collect();
            factors.push(RiskFactor {
                category: RiskCategory::ExportedComponents,
                description: format!("{} exported component(s) without permission guard", exposed.len()),
                score: max_comp_risk,
                evidence,
            });
        }

        // Dynamic code loading
        let high_risk_dyn = self.high_risk_dynamic_loads();
        if !high_risk_dyn.is_empty() {
            let max_dyn_risk = high_risk_dyn.iter().map(|d| d.kind.risk()).max().unwrap_or(0);
            let evidence: Vec<String> = high_risk_dyn.iter().map(|d| {
                format!("{}: {}", d.kind.description(), d.location)
            }).collect();
            factors.push(RiskFactor {
                category: RiskCategory::DynamicCodeLoading,
                description: format!("{} high-risk dynamic code load(s)", high_risk_dyn.len()),
                score: max_dyn_risk,
                evidence,
            });
        }

        // Background persistence
        if !self.background_abuses.is_empty() {
            let max_bg_risk = self.background_abuses.iter().map(BackgroundAbuse::risk).max().unwrap_or(0);
            let evidence: Vec<String> = self.background_abuses.iter().map(|b| b.description().to_owned()).collect();
            factors.push(RiskFactor {
                category: RiskCategory::BackgroundPersistence,
                description: format!("{} background persistence technique(s)", self.background_abuses.len()),
                score: max_bg_risk,
                evidence,
            });
        }

        // Network security
        if self.cleartext_traffic_allowed {
            factors.push(RiskFactor {
                category: RiskCategory::NetworkSecurity,
                description: "Cleartext HTTP traffic permitted".to_owned(),
                score: 55,
                evidence: vec!["android:usesCleartextTraffic=true".to_owned()],
            });
        }

        if !self.custom_trust_managers.is_empty() {
            factors.push(RiskFactor {
                category: RiskCategory::NetworkSecurity,
                description: "Custom TrustManager — possible certificate pinning bypass".to_owned(),
                score: 75,
                evidence: self.custom_trust_managers.clone(),
            });
        }

        // Debug & backup flags
        if self.debuggable {
            factors.push(RiskFactor {
                category: RiskCategory::AntiAnalysis,
                description: "App is debuggable — allows arbitrary code execution via ADB".to_owned(),
                score: 80,
                evidence: vec!["android:debuggable=true".to_owned()],
            });
        }

        if self.allow_backup {
            factors.push(RiskFactor {
                category: RiskCategory::PrivacyLeak,
                description: "Backup allowed — sensitive data extractable without root".to_owned(),
                score: 40,
                evidence: vec!["android:allowBackup=true".to_owned()],
            });
        }

        factors
    }
}

// ---------------------------------------------------------------------------
// Threat report
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ThreatReport {
    pub package_name: String,
    pub risk_score: RiskScore,
    pub summary: String,
    pub dangerous_permissions: Vec<String>,
    pub exposed_components: Vec<ExposedComponentSummary>,
    pub dynamic_load_findings: Vec<String>,
    pub persistence_findings: Vec<String>,
    pub network_findings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExposedComponentSummary {
    pub kind: String,
    pub class_name: String,
    pub risk: u8,
    pub notes: String,
}

impl ThreatReport {
    #[must_use] 
    pub fn generate(model: &ThreatModel) -> Self {
        let risk_factors = model.build_risk_factors();
        let risk_score = RiskScore::compute(risk_factors);

        let dangerous_permissions: Vec<String> = model.dangerous_permissions()
            .iter()
            .map(|p| p.name.clone())
            .collect();

        let exposed_components: Vec<ExposedComponentSummary> = model.exported_without_permission()
            .iter()
            .map(|c| {
                let notes = if c.intent_filters.is_empty() {
                    "No intent filters; accessible to any caller".to_owned()
                } else {
                    format!("{} intent filter(s)", c.intent_filters.len())
                };
                ExposedComponentSummary {
                    kind: c.kind.as_str().to_owned(),
                    class_name: c.class_name.clone(),
                    risk: c.component_risk(),
                    notes,
                }
            })
            .collect();

        let dynamic_load_findings: Vec<String> = model.dynamic_code_usages.iter()
            .map(|d| format!("[{}] {} at {}", d.kind.risk(), d.kind.description(), d.location))
            .collect();

        let persistence_findings: Vec<String> = model.background_abuses.iter()
            .map(|b| b.description().to_owned())
            .collect();

        let mut network_findings = Vec::new();
        if model.cleartext_traffic_allowed {
            network_findings.push("Cleartext HTTP traffic allowed".to_owned());
        }
        for tm in &model.custom_trust_managers {
            network_findings.push(format!("Custom TrustManager: {tm}"));
        }

        let recommendations = Self::build_recommendations(model, &risk_score);

        let summary = format!(
            "{} — Threat level: {} (score {}/100). {} dangerous permissions, {} exposed components, {} dynamic loaders.",
            model.package_name,
            risk_score.level.as_str(),
            risk_score.overall,
            dangerous_permissions.len(),
            exposed_components.len(),
            model.dynamic_code_usages.len()
        );

        Self {
            package_name: model.package_name.clone(),
            risk_score,
            summary,
            dangerous_permissions,
            exposed_components,
            dynamic_load_findings,
            persistence_findings,
            network_findings,
            recommendations,
        }
    }

    fn build_recommendations(model: &ThreatModel, score: &RiskScore) -> Vec<String> {
        let mut recs = Vec::new();

        if model.debuggable {
            recs.push("Remove android:debuggable=true before release".to_owned());
        }
        if model.cleartext_traffic_allowed {
            recs.push("Disable cleartext traffic or use a Network Security Config to restrict it".to_owned());
        }
        if !model.custom_trust_managers.is_empty() {
            recs.push("Review custom TrustManager implementations for certificate validation bypass".to_owned());
        }
        for c in model.exported_without_permission() {
            recs.push(format!(
                "Add permission guard to exported {} '{}'",
                c.kind.as_str(), c.class_name
            ));
        }
        if model.dynamic_code_usages.iter().any(|d| d.kind.risk() >= 85) {
            recs.push("Investigate dynamic DEX/code loading — possible malware dropper pattern".to_owned());
        }
        if model.allow_backup {
            recs.push("Set android:allowBackup=false to prevent data extraction via ADB backup".to_owned());
        }
        if score.level >= ThreatLevel::High {
            recs.push("Conduct full manual security audit before deployment".to_owned());
        }

        recs
    }
}

// ---------------------------------------------------------------------------
// Analyzer entry point
// ---------------------------------------------------------------------------

pub struct ApkThreatAnalyzer {
    policy_dangerous_permissions: HashSet<String>,
}

impl Default for ApkThreatAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ApkThreatAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        let mut policy = HashSet::new();
        for perm in &[
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BODY_SENSORS",
        ] {
            policy.insert(perm.to_string());
        }
        Self { policy_dangerous_permissions: policy }
    }

    #[must_use] 
    pub fn analyze(&self, model: &ThreatModel) -> ThreatReport {
        ThreatReport::generate(model)
    }

    #[must_use] 
    pub fn is_policy_dangerous(&self, permission: &str) -> bool {
        self.policy_dangerous_permissions.contains(permission)
    }

    #[must_use] 
    pub fn classify_permissions(&self, raw_permissions: &[String]) -> Vec<Permission> {
        raw_permissions.iter().map(|name| {
            let mut perm = Permission::new(name.clone());
            if self.is_policy_dangerous(name) {
                perm.is_dangerous = true;
                perm.protection_level = ProtectionLevel::Dangerous;
            }
            perm
        }).collect()
    }

    #[must_use] 
    pub fn check_background_abuse(
        &self,
        has_boot_receiver: bool,
        has_sticky_service: bool,
        has_persistent: bool,
        has_alarm_manager: bool,
        has_wake_lock: bool,
        has_foreground_no_notif: bool,
    ) -> Vec<BackgroundAbuse> {
        let mut abuses = Vec::new();
        if has_boot_receiver { abuses.push(BackgroundAbuse::BootReceiver); }
        if has_sticky_service { abuses.push(BackgroundAbuse::StickyService); }
        if has_persistent { abuses.push(BackgroundAbuse::PersistentProcess); }
        if has_alarm_manager { abuses.push(BackgroundAbuse::AlarmManagerAbuse); }
        if has_wake_lock { abuses.push(BackgroundAbuse::WakeLockHeld); }
        if has_foreground_no_notif { abuses.push(BackgroundAbuse::ForegroundServiceAbuse); }
        abuses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_category() {
        let p = Permission::new("android.permission.ACCESS_FINE_LOCATION");
        assert_eq!(p.category, PermissionCategory::Location);
        assert!(p.is_dangerous);
    }

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(25), ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(55), ThreatLevel::Medium);
        assert_eq!(ThreatLevel::from_score(75), ThreatLevel::High);
        assert_eq!(ThreatLevel::from_score(95), ThreatLevel::Critical);
    }

    #[test]
    fn test_exported_component_risk() {
        let comp = ExportedComponent {
            kind: ComponentKind::Service,
            class_name: "com.example.BackdoorService".to_owned(),
            permission: None,
            intent_filters: vec![],
            is_exported_explicit: true,
            is_exported_implicit: false,
            grant_uri_permissions: false,
            read_permission: None,
            write_permission: None,
        };
        assert!(comp.is_high_risk());
        assert!(comp.component_risk() >= 80);
    }

    #[test]
    fn test_threat_report_debuggable() {
        let mut model = ThreatModel::new();
        model.package_name = "com.test.app".to_owned();
        model.debuggable = true;
        let analyzer = ApkThreatAnalyzer::new();
        let report = analyzer.analyze(&model);
        assert!(report.risk_score.level >= ThreatLevel::Medium);
        assert!(report.recommendations.iter().any(|r| r.contains("debuggable")));
    }

    #[test]
    fn test_risk_score_compute() {
        let factors = vec![
            RiskFactor {
                category: RiskCategory::DangerousPermissions,
                description: "Test".to_owned(),
                score: 80,
                evidence: vec![],
            },
        ];
        let score = RiskScore::compute(factors);
        assert!(score.overall > 0);
        assert!(score.level >= ThreatLevel::Medium);
    }
}
