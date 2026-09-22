use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;

use crate::error::Result;
use crate::inventory::models::{AppInventoryReport, AppPackageType, InstalledApp};
use crate::models::Platform;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct RawWinAppEntry {
    #[serde(default)]
    ps_child_name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    display_version: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    install_location: Option<String>,
    #[serde(default)]
    install_date: Option<String>,
    #[serde(default)]
    uninstall_string: Option<String>,
    #[serde(default)]
    quiet_uninstall_string: Option<String>,
    #[serde(default)]
    windows_installer: Option<serde_json::Value>,
    #[serde(default)]
    system_component: Option<serde_json::Value>,
}

pub struct WindowsInventoryCollector;

impl Default for WindowsInventoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsInventoryCollector {
    pub fn new() -> Self {
        Self
    }

    /// Performs the full application inventory scan on Windows.
    pub fn collect(&self, org_id: u64, device_id: String) -> Result<AppInventoryReport> {
        let start = Instant::now();
        let mut apps = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(reg_apps) = Self::query_windows_registry() {
                apps.extend(reg_apps);
            }
        }

        // Fallback directory scan (e.g. Program Files) if registry returned empty or for dry-run
        if apps.is_empty() {
            apps = Self::scan_program_files();
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(AppInventoryReport::new(
            org_id,
            device_id,
            Platform::Windows,
            apps,
            duration_ms,
        ))
    }

    #[cfg(target_os = "windows")]
    fn query_windows_registry() -> Result<Vec<InstalledApp>> {
        let script = r#"
            $roots = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            Get-ItemProperty $roots -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object PSChildName, DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate, UninstallString, QuietUninstallString, WindowsInstaller, SystemComponent |
                ConvertTo-Json -Compress
        "#;

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|e| crate::error::EngineError::Io(e))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let raw_json = String::from_utf8_lossy(&output.stdout);
        Self::parse_registry_json(&raw_json)
    }

    pub fn parse_registry_json(json_str: &str) -> Result<Vec<InstalledApp>> {
        let trimmed = json_str.trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Ok(Vec::new());
        }

        let entries: Vec<RawWinAppEntry> = if trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_default()
        } else if trimmed.starts_with('{') {
            serde_json::from_str::<RawWinAppEntry>(trimmed)
                .map(|e| vec![e])
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut seen_ids = std::collections::HashSet::new();
        let mut apps = Vec::new();

        for entry in entries {
            let name = match entry.display_name {
                Some(ref n) if !n.trim().is_empty() => n.trim().to_string(),
                _ => continue,
            };

            let app_id = entry
                .ps_child_name
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| name.clone());

            if !seen_ids.insert(app_id.clone()) {
                continue;
            }

            // Check if MSI
            let is_msi = entry
                .windows_installer
                .map(|v| v == 1 || v == "1")
                .unwrap_or(false);

            let pkg_type = if is_msi {
                AppPackageType::MsiPackage
            } else {
                AppPackageType::WindowsRegistry
            };

            let installed_at = entry.install_date.and_then(|d| {
                let s = d.trim();
                if s.len() == 8 {
                    NaiveDate::parse_from_str(s, "%Y%m%d")
                        .ok()
                        .and_then(|nd| nd.and_hms_opt(0, 0, 0))
                        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
                } else {
                    None
                }
            });

            let uninstall_command = entry
                .quiet_uninstall_string
                .or(entry.uninstall_string)
                .map(|s| s.trim().to_string());

            let mut metadata = HashMap::new();
            if is_msi {
                metadata.insert("is_msi".to_string(), "true".to_string());
            }

            apps.push(InstalledApp {
                app_id,
                name,
                version: entry.display_version.unwrap_or_else(|| "1.0.0".to_string()),
                build_version: None,
                publisher: entry.publisher,
                install_path: entry.install_location,
                installed_at,
                architecture: Some("x64".to_string()),
                package_type: pkg_type,
                uninstall_command,
                is_system_app: false,
                metadata,
            });
        }

        Ok(apps)
    }

    fn scan_program_files() -> Vec<InstalledApp> {
        let mut apps = Vec::new();
        let roots = [
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];

        for root in roots {
            if !root.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let folder_name = entry.file_name().to_string_lossy().to_string();
                        // Ignore common system/empty folders
                        if folder_name.starts_with("Common Files") || folder_name == "Windows Defender" {
                            continue;
                        }

                        apps.push(InstalledApp {
                            app_id: format!("win32.{}", folder_name),
                            name: folder_name,
                            version: "unknown".to_string(),
                            build_version: None,
                            publisher: None,
                            install_path: Some(path.to_string_lossy().to_string()),
                            installed_at: None,
                            architecture: Some("x64".to_string()),
                            package_type: AppPackageType::WindowsRegistry,
                            uninstall_command: None,
                            is_system_app: false,
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        apps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_windows_registry_json() {
        let json_sample = r#"[
            {
                "PSChildName": "{90160000-008C-0000-1000-0000000FF1CE}",
                "DisplayName": "Office 16 Click-to-Run Licensing Component",
                "DisplayVersion": "16.0.17531.20120",
                "Publisher": "Microsoft Corporation",
                "InstallLocation": "C:\\Program Files\\Microsoft Office",
                "InstallDate": "20240415",
                "UninstallString": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\" scenario=uninstall",
                "QuietUninstallString": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\" scenario=uninstall /quiet",
                "WindowsInstaller": 1
            },
            {
                "PSChildName": "Git_is1",
                "DisplayName": "Git version 2.44.0",
                "DisplayVersion": "2.44.0",
                "Publisher": "The Git Development Community",
                "InstallLocation": "C:\\Program Files\\Git",
                "InstallDate": "20240310",
                "UninstallString": "\"C:\\Program Files\\Git\\unins000.exe\"",
                "QuietUninstallString": "\"C:\\Program Files\\Git\\unins000.exe\" /VERYSILENT",
                "WindowsInstaller": 0
            }
        ]"#;

        let apps = WindowsInventoryCollector::parse_registry_json(json_sample).unwrap();
        assert_eq!(apps.len(), 2);

        let msi_app = &apps[0];
        assert_eq!(msi_app.name, "Office 16 Click-to-Run Licensing Component");
        assert_eq!(msi_app.version, "16.0.17531.20120");
        assert_eq!(msi_app.publisher, Some("Microsoft Corporation".to_string()));
        assert_eq!(msi_app.package_type, AppPackageType::MsiPackage);
        assert_eq!(
            msi_app.uninstall_command,
            Some("\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\" scenario=uninstall /quiet".to_string())
        );

        let git_app = &apps[1];
        assert_eq!(git_app.name, "Git version 2.44.0");
        assert_eq!(git_app.package_type, AppPackageType::WindowsRegistry);
    }
}
