use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::Utc;

use crate::error::Result;
use crate::inventory::models::{AppInventoryReport, AppPackageType, InstalledApp};
use crate::models::Platform;

pub struct LinuxInventoryCollector;

impl Default for LinuxInventoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxInventoryCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self, org_id: u64, device_id: String) -> Result<AppInventoryReport> {
        let start = Instant::now();
        let mut apps = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        let desktop_dirs = [
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/usr/local/share/applications"),
        ];

        for dir in desktop_dirs {
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("desktop") {
                        if let Some(app) = self.parse_desktop_entry(&path) {
                            if seen_ids.insert(app.app_id.clone()) {
                                apps.push(app);
                            }
                        }
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(AppInventoryReport::new(
            org_id,
            device_id,
            Platform::Linux,
            apps,
            duration_ms,
        ))
    }

    fn parse_desktop_entry(&self, path: &Path) -> Option<InstalledApp> {
        let content = fs::read_to_string(path).ok()?;
        let file_stem = path.file_stem()?.to_string_lossy().to_string();

        let mut name = None;
        let mut exec = None;
        let mut version = None;
        let mut comment = None;
        let mut is_nodisplay = false;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("Name=") && name.is_none() {
                name = Some(line.trim_start_matches("Name=").to_string());
            } else if line.starts_with("Exec=") && exec.is_none() {
                exec = Some(line.trim_start_matches("Exec=").to_string());
            } else if line.starts_with("Version=") && version.is_none() {
                version = Some(line.trim_start_matches("Version=").to_string());
            } else if line.starts_with("Comment=") && comment.is_none() {
                comment = Some(line.trim_start_matches("Comment=").to_string());
            } else if line == "NoDisplay=true" {
                is_nodisplay = true;
            }
        }

        if is_nodisplay {
            return None;
        }

        let display_name = name.unwrap_or_else(|| file_stem.clone());

        Some(InstalledApp {
            app_id: format!("linux.desktop.{}", file_stem),
            name: display_name,
            version: version.unwrap_or_else(|| "1.0".to_string()),
            build_version: None,
            publisher: comment,
            install_path: exec,
            installed_at: Some(Utc::now()),
            architecture: Some("x86_64".to_string()),
            package_type: AppPackageType::LinuxDesktop,
            uninstall_command: None,
            is_system_app: path.starts_with("/usr/share"),
            metadata: HashMap::new(),
        })
    }
}
