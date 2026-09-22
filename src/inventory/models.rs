use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPackageType {
    AppBundle,
    PkgReceipt,
    HomebrewCask,
    WindowsRegistry,
    MsiPackage,
    AppxMsix,
    LinuxDpkg,
    LinuxRpm,
    LinuxDesktop,
    Custom,
}

impl std::fmt::Display for AppPackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppPackageType::AppBundle => write!(f, "app_bundle"),
            AppPackageType::PkgReceipt => write!(f, "pkg_receipt"),
            AppPackageType::HomebrewCask => write!(f, "homebrew_cask"),
            AppPackageType::WindowsRegistry => write!(f, "windows_registry"),
            AppPackageType::MsiPackage => write!(f, "msi_package"),
            AppPackageType::AppxMsix => write!(f, "appx_msix"),
            AppPackageType::LinuxDpkg => write!(f, "linux_dpkg"),
            AppPackageType::LinuxRpm => write!(f, "linux_rpm"),
            AppPackageType::LinuxDesktop => write!(f, "linux_desktop"),
            AppPackageType::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledApp {
    /// Unique identifier: Bundle ID on macOS (e.g. "com.apple.Safari"), Registry key / GUID on Windows
    pub app_id: String,
    /// Human-friendly display name (e.g. "Google Chrome", "Visual Studio Code")
    pub name: String,
    /// Marketing or release version string (e.g. "124.0.6367.91")
    pub version: String,
    /// Build or bundle version (e.g. "6367.91" or CFBundleVersion)
    #[serde(default)]
    pub build_version: Option<String>,
    /// Publisher or developer vendor name (e.g. "Google LLC", "Microsoft Corporation")
    #[serde(default)]
    pub publisher: Option<String>,
    /// Installation path on local disk (e.g. "/Applications/Slack.app" or "C:\\Program Files\\Slack")
    #[serde(default)]
    pub install_path: Option<String>,
    /// When the application was installed or modified
    #[serde(default)]
    pub installed_at: Option<DateTime<Utc>>,
    /// Binary architecture (e.g. "arm64", "x86_64", "universal", "x64", "x86")
    #[serde(default)]
    pub architecture: Option<String>,
    /// Underlying packaging / management mechanism
    pub package_type: AppPackageType,
    /// Silent or standard uninstallation string / CLI
    #[serde(default)]
    pub uninstall_command: Option<String>,
    /// Flag indicating whether this is a pre-installed OS / system application
    #[serde(default)]
    pub is_system_app: bool,
    /// Key-value metadata store for platform-specific extras (e.g. TeamIdentifier, MinimumOS, MSI ProductCode)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInventoryReport {
    pub org_id: u64,
    pub device_id: String,
    pub platform: Platform,
    pub collected_at: DateTime<Utc>,
    pub total_apps: usize,
    pub apps: Vec<InstalledApp>,
    pub scan_duration_ms: u64,
}

impl AppInventoryReport {
    pub fn new(org_id: u64, device_id: String, platform: Platform, apps: Vec<InstalledApp>, scan_duration_ms: u64) -> Self {
        let total_apps = apps.len();
        Self {
            org_id,
            device_id,
            platform,
            collected_at: Utc::now(),
            total_apps,
            apps,
            scan_duration_ms,
        }
    }

    /// Helper to find an installed app by either exact name, app_id, or bundle identifier (case-insensitive)
    pub fn find_app(&self, query: &str) -> Option<&InstalledApp> {
        let q = query.trim().to_lowercase();
        self.apps.iter().find(|app| {
            app.name.to_lowercase() == q
                || app.app_id.to_lowercase() == q
                || app.name.to_lowercase().contains(&q)
        })
    }
}
