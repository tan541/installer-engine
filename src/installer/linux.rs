use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::error::{EngineError, Result};
use crate::models::InstallReport;

pub struct LinuxInstaller;

impl LinuxInstaller {
    pub fn new() -> Self {
        Self
    }

    pub async fn install(&self, package_path: &Path, args: &[String]) -> Result<InstallReport> {
        let start = Instant::now();
        let file_name = package_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_lowercase();

        tracing::info!(
            package = %package_path.display(),
            file = %file_name,
            "Executing Linux installation"
        );

        if file_name.ends_with(".deb") {
            self.install_deb(package_path, args, start)
        } else if file_name.ends_with(".rpm") {
            self.install_rpm(package_path, args, start)
        } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
            self.install_tarball(package_path, start)
        } else {
            self.install_script(package_path, args, start)
        }
    }

    fn install_deb(&self, package_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("dpkg");
        cmd.arg("-i").arg(package_path);
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
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: format!("dpkg failed: {stderr}"),
            })
        }
    }

    fn install_rpm(&self, package_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("rpm");
        cmd.arg("-Uvh").arg(package_path);
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
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: format!("rpm failed: {stderr}"),
            })
        }
    }

    fn install_tarball(&self, package_path: &Path, start: Instant) -> Result<InstallReport> {
        let target_dir = Path::new("/opt");
        let output = Command::new("tar")
            .args(["-xzf", package_path.to_str().unwrap(), "-C", target_dir.to_str().unwrap()])
            .output()
            .map_err(EngineError::Io)?;

        let duration_ms = start.elapsed().as_millis() as u64;

        if output.status.success() {
            Ok(InstallReport {
                success: true,
                exit_code: output.status.code(),
                message: "Tarball extracted to /opt".to_string(),
                installed_path: Some("/opt".to_string()),
                duration_ms,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: format!("tar extraction failed: {stderr}"),
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
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code: output.status.code(),
                message: format!("Script execution failed: {stderr}"),
            })
        }
    }
}
