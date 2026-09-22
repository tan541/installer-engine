use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::blocker::models::BlockCandidate;
use crate::blocker::platform::PlatformRemediator;
use crate::error::{EngineError, Result};

#[derive(Debug, Default)]
pub struct LinuxRemediator;

impl LinuxRemediator {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformRemediator for LinuxRemediator {
    fn terminate_process(&self, pid: u32) -> Result<bool> {
        tracing::warn!(pid, "Terminating blocked process on Linux with SIGKILL (9)");
        let status = Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .status()
            .map_err(|e| EngineError::Installation(format!("Failed to execute kill -9 on PID {pid}: {e}")))?;

        Ok(status.success())
    }

    fn terminate_process_by_name(&self, name: &str) -> Result<usize> {
        tracing::warn!(app_name = %name, "Terminating all processes matching name on Linux");
        let output = Command::new("pkill")
            .arg("-9")
            .arg("-f")
            .arg(name)
            .output();

        match output {
            Ok(out) => Ok(if out.status.success() { 1 } else { 0 }),
            Err(e) => {
                tracing::warn!("pkill failed: {e}");
                Ok(0)
            }
        }
    }

    fn quarantine_path(&self, target_path: &Path, quarantine_dir: &Path) -> Result<PathBuf> {
        if !target_path.exists() {
            return Err(EngineError::Installation(format!(
                "Cannot quarantine non-existent path: {}",
                target_path.display()
            )));
        }

        fs::create_dir_all(quarantine_dir)?;

        let file_name = target_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("quarantined_app");

        let timestamp = chrono::Utc::now().timestamp();
        let dest_name = format!("{}_{}.quarantined", file_name, timestamp);
        let dest_path = quarantine_dir.join(dest_name);

        tracing::info!(
            from = %target_path.display(),
            to = %dest_path.display(),
            "Moving blocked Linux binary/package to quarantine"
        );

        fs::rename(target_path, &dest_path).or_else(|_| {
            if target_path.is_dir() {
                let _ = Command::new("cp")
                    .arg("-r")
                    .arg(target_path)
                    .arg(&dest_path)
                    .status();
                let _ = fs::remove_dir_all(target_path);
            } else {
                fs::copy(target_path, &dest_path)?;
                fs::remove_file(target_path)?;
            }
            Ok::<(), std::io::Error>(())
        })?;

        Ok(dest_path)
    }

    fn scan_running_processes(&self) -> Result<Vec<BlockCandidate>> {
        let output = Command::new("ps")
            .args(["-eo", "pid,comm"])
            .output()
            .map_err(|e| EngineError::Installation(format!("Failed to execute ps command: {e}")))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut candidates = Vec::new();

        for line in stdout.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut parts = trimmed.split_whitespace();
            if let Some(pid_str) = parts.next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let comm = parts.collect::<Vec<_>>().join(" ");
                    let path_buf = PathBuf::from(&comm);
                    let exe_name = path_buf
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or(&comm)
                        .to_string();

                    let is_installer = exe_name == "dpkg" || exe_name == "apt" || exe_name == "rpm" || exe_name == "flatpak";

                    candidates.push(BlockCandidate {
                        app_name: Some(exe_name.clone()),
                        bundle_id: None,
                        executable_name: Some(exe_name),
                        executable_path: Some(path_buf),
                        sha256_hash: None,
                        process_id: Some(pid),
                        is_installer,
                    });
                }
            }
        }

        Ok(candidates)
    }

    fn scan_staging_areas(&self) -> Result<Vec<BlockCandidate>> {
        let mut candidates = Vec::new();
        let staging_paths = ["/tmp", "/var/tmp"];

        for dir in staging_paths {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                        if ext == "deb" || ext == "rpm" || ext == "AppImage" {
                            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                                candidates.push(BlockCandidate {
                                    app_name: Some(stem.to_string()),
                                    bundle_id: None,
                                    executable_name: p.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()),
                                    executable_path: Some(p),
                                    sha256_hash: None,
                                    process_id: None,
                                    is_installer: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(candidates)
    }
}
