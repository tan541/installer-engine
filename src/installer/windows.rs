use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::error::{EngineError, Result};
use crate::models::InstallReport;

pub struct WindowsInstaller;

impl WindowsInstaller {
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
            "Executing Windows installation"
        );

        match extension.as_str() {
            "msi" => self.install_msi(package_path, args, start),
            "exe" => self.install_exe(package_path, args, start),
            "ps1" => self.install_powershell(package_path, args, start),
            "bat" | "cmd" => self.install_batch(package_path, args, start),
            _ => self.install_exe(package_path, args, start),
        }
    }

    fn install_msi(&self, package_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("msiexec.exe");
        cmd.arg("/i").arg(package_path);

        // Filter out macOS/Linux arguments if passed in cross-platform tasks
        let filtered_args: Vec<&str> = user_args
            .iter()
            .map(|s| s.as_str())
            .filter(|&a| a != "-target" && a != "/" && a != "--target" && !a.is_empty())
            .collect();

        if filtered_args.is_empty() {
            cmd.args(["/qn", "/norestart"]);
        } else {
            let has_quiet = filtered_args.iter().any(|a| a.starts_with("/q") || a.eq_ignore_ascii_case("/passive") || a.eq_ignore_ascii_case("/quiet"));
            let has_restart = filtered_args.iter().any(|a| {
                a.eq_ignore_ascii_case("/norestart")
                    || a.eq_ignore_ascii_case("/forcerestart")
                    || a.eq_ignore_ascii_case("/promptrestart")
            });

            for arg in &filtered_args {
                cmd.arg(arg);
            }

            if !has_quiet {
                cmd.arg("/qn");
            }
            if !has_restart {
                cmd.arg("/norestart");
            }
        }

        tracing::info!(
            package = %package_path.display(),
            "Executing msiexec.exe command"
        );

        let output = cmd.output().map_err(EngineError::Io)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Windows Installer exit codes: 0 = Success, 3010 = Success (Reboot required)
        let exit_code = output.status.code();
        let is_success = output.status.success() || exit_code == Some(3010);

        if is_success {
            let msg = if exit_code == Some(3010) {
                "MSI installation completed successfully (reboot required)".to_string()
            } else {
                "MSI installation completed successfully".to_string()
            };
            Ok(InstallReport {
                success: true,
                exit_code,
                message: msg,
                installed_path: None,
                duration_ms,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let details = if !stderr.is_empty() { stderr } else { stdout };
            Err(EngineError::InstallerExecution {
                exit_code,
                message: format!("msiexec failed with exit code {:?}: {}", exit_code, details.trim()),
            })
        }
    }

    fn install_exe(&self, package_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new(package_path);

        let filtered_args: Vec<&str> = user_args
            .iter()
            .map(|s| s.as_str())
            .filter(|&a| a != "-target" && a != "/" && a != "--target" && !a.is_empty())
            .collect();

        if filtered_args.is_empty() {
            cmd.args(["/S", "/silent", "/quiet"]);
        } else {
            for arg in filtered_args {
                cmd.arg(arg);
            }
        }

        let output = cmd.output().map_err(EngineError::Io)?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let exit_code = output.status.code();
        let is_success = output.status.success() || exit_code == Some(3010);

        if is_success {
            Ok(InstallReport {
                success: true,
                exit_code,
                message: "EXE installation completed successfully".to_string(),
                installed_path: None,
                duration_ms,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(EngineError::InstallerExecution {
                exit_code,
                message: format!("EXE execution failed: {stderr}"),
            })
        }
    }

    fn install_powershell(&self, script_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("powershell.exe");
        cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
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
                message: format!("PowerShell script failed: {stderr}"),
            })
        }
    }

    fn install_batch(&self, script_path: &Path, user_args: &[String], start: Instant) -> Result<InstallReport> {
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c"]).arg(script_path);
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
                message: format!("Batch script failed: {stderr}"),
            })
        }
    }
}
