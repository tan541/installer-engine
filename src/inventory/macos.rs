use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Utc};
use plist::Value;

use crate::error::Result;
use crate::inventory::models::{AppInventoryReport, AppPackageType, InstalledApp};
use crate::models::Platform;

pub struct MacOSInventoryCollector {
    search_paths: Vec<PathBuf>,
}

impl Default for MacOSInventoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOSInventoryCollector {
    pub fn new() -> Self {
        let mut paths = vec![
            PathBuf::from("/Applications"),
            PathBuf::from("/System/Applications"),
            PathBuf::from("/System/Applications/Utilities"),
        ];

        if let Ok(home) = std::env::var("HOME") {
            let user_apps = PathBuf::from(home).join("Applications");
            if user_apps.exists() {
                paths.push(user_apps);
            }
        }

        Self { search_paths: paths }
    }

    pub fn with_custom_paths(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }

    /// Performs the full application inventory scan across all configured macOS directories.
    pub fn collect(&self, org_id: u64, device_id: String) -> Result<AppInventoryReport> {
        let start = Instant::now();
        let mut apps = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for root in &self.search_paths {
            if !root.exists() {
                continue;
            }
            self.scan_directory(root, &mut apps, &mut seen_ids, 0, 2);
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(AppInventoryReport::new(
            org_id,
            device_id,
            Platform::MacOS,
            apps,
            duration_ms,
        ))
    }

    fn scan_directory(
        &self,
        dir: &Path,
        apps: &mut Vec<InstalledApp>,
        seen_ids: &mut std::collections::HashSet<String>,
        current_depth: usize,
        max_depth: usize,
    ) {
        if current_depth > max_depth {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.extension().and_then(|ext| ext.to_str()) == Some("app") {
                    if let Some(app) = self.parse_app_bundle(&path) {
                        if seen_ids.insert(app.app_id.clone()) {
                            apps.push(app);
                        }
                    }
                } else if current_depth < max_depth {
                    // Recurse into subdirectories (e.g. /Applications/Utilities)
                    self.scan_directory(&path, apps, seen_ids, current_depth + 1, max_depth);
                }
            }
        }
    }

    pub fn parse_app_bundle(&self, bundle_path: &Path) -> Option<InstalledApp> {
        let info_plist_path = bundle_path.join("Contents").join("Info.plist");
        if !info_plist_path.exists() {
            return None;
        }

        let plist_val = match Value::from_file(&info_plist_path) {
            Ok(val) => val,
            Err(e) => {
                tracing::debug!(path = %info_plist_path.display(), error = %e, "Could not parse Info.plist");
                return None;
            }
        };

        let dict = plist_val.as_dictionary()?;

        let bundle_name_fallback = bundle_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown App")
            .to_string();

        let app_id = dict
            .get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| bundle_name_fallback.clone());

        let name = dict
            .get("CFBundleDisplayName")
            .or_else(|| dict.get("CFBundleName"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or(bundle_name_fallback);

        let version = dict
            .get("CFBundleShortVersionString")
            .or_else(|| dict.get("CFBundleVersion"))
            .and_then(|v| v.as_string())
            .unwrap_or("0.0.0")
            .to_string();

        let build_version = dict
            .get("CFBundleVersion")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        let publisher = dict
            .get("CFBundleGetInfoString")
            .or_else(|| dict.get("NSHumanReadableCopyright"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        let is_system_app = bundle_path.starts_with("/System");

        // Inspect file metadata
        let installed_at = std::fs::metadata(bundle_path)
            .ok()
            .and_then(|meta| meta.created().or_else(|_| meta.modified()).ok())
            .map(DateTime::<Utc>::from);

        // Determine executable architecture
        let mut architecture = None;
        if let Some(exec_name) = dict.get("CFBundleExecutable").and_then(|v| v.as_string()) {
            let exec_path = bundle_path.join("Contents").join("MacOS").join(exec_name);
            if exec_path.exists() {
                architecture = detect_macho_architecture(&exec_path);
            }
        }

        let mut metadata = HashMap::new();
        if let Some(min_os) = dict.get("LSMinimumSystemVersion").and_then(|v| v.as_string()) {
            metadata.insert("minimum_system_version".to_string(), min_os.to_string());
        }
        if let Some(bundle_pkg_type) = dict.get("CFBundlePackageType").and_then(|v| v.as_string()) {
            metadata.insert("bundle_package_type".to_string(), bundle_pkg_type.to_string());
        }

        Some(InstalledApp {
            app_id,
            name,
            version,
            build_version,
            publisher,
            install_path: Some(bundle_path.to_string_lossy().to_string()),
            installed_at,
            architecture,
            package_type: AppPackageType::AppBundle,
            uninstall_command: None,
            is_system_app,
            metadata,
        })
    }
}

/// Detects the CPU architecture of a Mach-O executable by inspecting its magic headers.
fn detect_macho_architecture(exec_path: &Path) -> Option<String> {
    let mut file = File::open(exec_path).ok()?;
    let mut header = [0u8; 8];
    if file.read_exact(&mut header).is_err() {
        return None;
    }

    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    match magic {
        0xCAFEBABE | 0xBEBAFECA => Some("universal".to_string()),
        0xFEEDFACF => {
            // 64-bit Mach-O (big endian)
            let cputype = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            match cputype {
                0x01000007 => Some("x86_64".to_string()),
                0x0100000C => Some("arm64".to_string()),
                _ => Some("macho_64".to_string()),
            }
        }
        0xCFFAEDFE => {
            // 64-bit Mach-O (little endian - standard on modern macOS)
            let cputype = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            match cputype {
                0x01000007 => Some("x86_64".to_string()),
                0x0100000C => Some("arm64".to_string()),
                _ => Some("macho_64".to_string()),
            }
        }
        0xFEEDFACE | 0xCEFAEDFE => Some("macho_32".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_parse_synthetic_app_bundle() {
        let temp_dir = tempdir().unwrap();
        let app_dir = temp_dir.path().join("DemoApp.app");
        let contents_dir = app_dir.join("Contents");
        let macos_dir = contents_dir.join("MacOS");
        std::fs::create_dir_all(&macos_dir).unwrap();

        let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.DemoApp</string>
    <key>CFBundleDisplayName</key>
    <string>Demo Application</string>
    <key>CFBundleShortVersionString</key>
    <string>2.4.1</string>
    <key>CFBundleVersion</key>
    <string>2410</string>
    <key>CFBundleExecutable</key>
    <string>demo_bin</string>
    <key>CFBundleGetInfoString</key>
    <string>Example Software Corp</string>
</dict>
</plist>"#;

        std::fs::write(contents_dir.join("Info.plist"), plist_content).unwrap();

        // Create dummy universal binary
        let mut bin = File::create(macos_dir.join("demo_bin")).unwrap();
        bin.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02]).unwrap();

        let collector = MacOSInventoryCollector::with_custom_paths(vec![temp_dir.path().to_path_buf()]);
        let report = collector.collect(1, "mac-test".to_string()).unwrap();

        assert_eq!(report.total_apps, 1);
        let app = &report.apps[0];
        assert_eq!(app.app_id, "com.example.DemoApp");
        assert_eq!(app.name, "Demo Application");
        assert_eq!(app.version, "2.4.1");
        assert_eq!(app.build_version, Some("2410".to_string()));
        assert_eq!(app.publisher, Some("Example Software Corp".to_string()));
        assert_eq!(app.architecture, Some("universal".to_string()));
        assert_eq!(app.package_type, AppPackageType::AppBundle);
    }
}
