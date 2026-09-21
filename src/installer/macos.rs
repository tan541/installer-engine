use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::error::{EngineError, Result};
use crate::models::InstallReport;

pub struct MacOSInstaller;

impl MacOSInstaller {
    pub fn new() -> Self {
        Self
    }

    pub async fn install(&self, package_path: &Path, args: &[String]) -> Result<InstallReport> {
        let start = Instant::now();
        let extension = package_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        tracing::info!(
            package = %package_path.display(),
            extension = %extension,
            "Executing macOS installation"
        );

        match extension.as_str() {
            "pkg" => self.install_pkg(package_path, args, start),
            "dmg" => self.install_dmg(package_path, start),
            "app" => self.install_app_bundle(package_path, start),
            "sh" | "command" => self.install_script(package_path, args, start),
            _ => {
                // If extension is not recognized, attempt execution if executable or fallback
                self.install_script(package_path, args, start)
            }
        }
    }

    pub fn extract_app_name_from_pkg(package_path: &Path) -> Option<String> {
        let output = Command::new("pkgutil")
            .arg("--payload-files")
            .arg(package_path)
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim().trim_start_matches("./");
                if trimmed.ends_with(".app") && !trimmed.contains('/') {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn install_pkg(&self, package_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("/usr/sbin/installer");
        cmd.arg("-pkg").arg(package_path);
        
        if user_args.is_empty() {
            cmd.arg("-target").arg("/");
        } else {
            for arg in user_args {
                cmd.arg(arg);
            }
        }

        let output = cmd.output().map_err(EngineError::Io)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        if output.status.success() {
            let installed_path = Self::extract_app_name_from_pkg(package_path)
                .map(|app_name| format!("/Applications/{}", app_name))
                .unwrap_or_else(|| "/Applications".to_string());

            Ok(InstallReport {
                success: true,
                exit_code: output.status.code(),
                message: String::from_utf8_lossy(&output.stdout).to_string(),
                installed_path: Some(installed_path),
                duration_ms,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: format!("macOS installer failed: {stderr}"),
            })
        }
    }

    fn install_dmg(&self, package_path: &Path, start: Instant) -> Result<InstallReport> {
        // Mount DMG: hdiutil attach <dmg> -nobrowse -mountpoint /tmp/mount_xxx
        let mount_dir = tempfile::tempdir().map_err(EngineError::Io)?;
        let mount_point = mount_dir.path().to_str().unwrap_or("/tmp/installer_mount");

        let attach_status = Command::new("hdiutil")
            .args(["attach", package_path.to_str().unwrap_or(""), "-nobrowse", "-mountpoint", mount_point])
            .output()
            .map_err(EngineError::Io)?;

        if !attach_status.status.success() {
            let err = String::from_utf8_lossy(&attach_status.stderr).to_string();
            return Err(EngineError::InstallerExecution {
                exit_code: attach_status.status.code(),
                message: format!("Failed to attach DMG: {err}"),
            });
        }

        // Search for .app inside mount point and copy to /Applications
        let mut copied_app = None;
        if let Ok(entries) = std::fs::read_dir(mount_point) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("app") {
                    let dest = Path::new("/Applications").join(path.file_name().unwrap());
                    // cp -R <app> /Applications/
                    let _ = Command::new("cp").args(["-R", path.to_str().unwrap(), dest.to_str().unwrap()]).output();
                    copied_app = Some(dest.to_string_lossy().to_string());
                    break;
                }
            }
        }

        // Unmount DMG: hdiutil detach <mount_point> -force
        let _ = Command::new("hdiutil")
            .args(["detach", mount_point, "-force"])
            .output();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(InstallReport {
            success: true,
            exit_code: Some(0),
            message: "DMG app copied successfully".to_string(),
            installed_path: copied_app,
            duration_ms,
        })
    }

    fn install_app_bundle(&self, app_path: &Path, start: Instant) -> Result<InstallReport> {
        let dest = Path::new("/Applications").join(app_path.file_name().unwrap_or_default());
        let output = Command::new("cp")
            .args(["-R", app_path.to_str().unwrap(), dest.to_str().unwrap()])
            .output()
            .map_err(EngineError::Io)?;

        let duration_ms = start.elapsed().as_millis() as u64;

        if output.status.success() {
            Ok(InstallReport {
                success: true,
                exit_code: Some(0),
                message: "App bundle copied to /Applications".to_string(),
                installed_path: Some(dest.to_string_lossy().to_string()),
                duration_ms,
            })
        } else {
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    fn install_script(&self, script_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("sh");
        cmd.arg(script_path);
        for arg in user_args {
            cmd.arg(arg);
        }

        let output = cmd.output().map_err(EngineError::Io)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        if output.status.success() {
            Ok(InstallReport {
                success: true,
                exit_code: output.status.code(),
                message: String::from_utf8_lossy(&output.stdout).to_string(),
                installed_path: None,
                duration_ms,
            })
        } else {
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }
}
