use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::blocker::models::BlockCandidate;
use crate::blocker::platform::PlatformRemediator;
use crate::error::{EngineError, Result};

#[derive(Debug, Default)]
pub struct MacOSRemediator;

impl MacOSRemediator {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformRemediator for MacOSRemediator {
    fn terminate_process(&self, pid: u32) -> Result<bool> {
        tracing::warn!(pid, "Terminating blocked process on macOS with SIGKILL (9)");
        let status = Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .status()
            .map_err(|e| EngineError::Installation(format!("Failed to execute kill -9 on PID {pid}: {e}")))?;

        Ok(status.success())
    }

    fn terminate_process_by_name(&self, name: &str) -> Result<usize> {
        tracing::warn!(app_name = %name, "Terminating all processes matching name on macOS");
        let output = Command::new("pkill")
            .arg("-9")
            .arg("-f")
            .arg(name)
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
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
            "Moving blocked application package to quarantine"
        );

        fs::rename(target_path, &dest_path).or_else(|_| {
            // Fallback for cross-device renames: copy and remove
            if target_path.is_dir() {
                let _ = Command::new("cp")
                    .arg("-R")
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

        // If target was in /Volumes (mounted DMG), try unmounting the DMG
        if target_path.starts_with("/Volumes") {
            let _ = Command::new("hdiutil")
                .arg("detach")
                .arg(target_path)
                .arg("-force")
                .status();
        }

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

                    // Detect app name from .app/Contents/MacOS path if present
                    let app_name = if comm.contains(".app/Contents/MacOS") {
                        let segments: Vec<&str> = comm.split(".app/Contents/MacOS").collect();
                        segments.first().and_then(|s| {
                            Path::new(s).file_name().and_then(|n| n.to_str())
                        }).map(|s| s.to_string())
                    } else {
                        Some(exe_name.clone())
                    };

                    let is_installer = exe_name.contains("installer") || exe_name.contains("setup") || exe_name.contains("pkg");

                    candidates.push(BlockCandidate {
                        app_name,
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

        // Scan /Volumes for mounted DMGs / installers
        if let Ok(entries) = fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|f| f.to_str()) {
                    if name != "Macintosh HD" {
                        candidates.push(BlockCandidate {
                            app_name: Some(name.to_string()),
                            bundle_id: None,
                            executable_name: None,
                            executable_path: Some(path),
                            sha256_hash: None,
                            process_id: None,
                            is_installer: true,
                        });
                    }
                }
            }
        }

        Ok(candidates)
    }
}
