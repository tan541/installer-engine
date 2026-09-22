use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::blocker::models::BlockCandidate;
use crate::blocker::platform::PlatformRemediator;
use crate::error::{EngineError, Result};

#[derive(Debug, Default)]
pub struct WindowsRemediator;

impl WindowsRemediator {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformRemediator for WindowsRemediator {
    fn terminate_process(&self, pid: u32) -> Result<bool> {
        tracing::warn!(pid, "Terminating blocked process on Windows with taskkill /F /PID");
        let status = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
            .map_err(|e| EngineError::Installation(format!("Failed to execute taskkill on PID {pid}: {e}")))?;

        Ok(status.success())
    }

    fn terminate_process_by_name(&self, name: &str) -> Result<usize> {
        tracing::warn!(image_name = %name, "Terminating all processes matching image name on Windows");
        let im_arg = if name.ends_with(".exe") {
            name.to_string()
        } else {
            format!("{}.exe", name)
        };

        let status = Command::new("taskkill")
            .args(["/F", "/IM", &im_arg])
            .status();

        match status {
            Ok(s) => Ok(if s.success() { 1 } else { 0 }),
            Err(e) => {
                tracing::warn!("taskkill /IM failed: {e}");
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
            "Moving blocked Windows application/installer to quarantine"
        );

        fs::rename(target_path, &dest_path).or_else(|_| {
            if target_path.is_dir() {
                // In case of directory, copy recursively and remove
                let _ = Command::new("robocopy")
                    .args([target_path.to_str().unwrap(), dest_path.to_str().unwrap(), "/E", "/MOVE"])
                    .status();
            } else {
                fs::copy(target_path, &dest_path)?;
                fs::remove_file(target_path)?;
            }
            Ok::<(), std::io::Error>(())
        })?;

        Ok(dest_path)
    }

    fn scan_running_processes(&self) -> Result<Vec<BlockCandidate>> {
        let output = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| EngineError::Installation(format!("Failed to execute tasklist: {e}")))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut candidates = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            let fields: Vec<String> = line
                .split("\",\"")
                .map(|s| s.trim_matches('"').to_string())
                .collect();

            if fields.len() >= 2 {
                let image_name = &fields[0];
                if let Ok(pid) = fields[1].parse::<u32>() {
                    let is_installer = image_name.eq_ignore_ascii_case("msiexec.exe")
                        || image_name.to_lowercase().contains("setup")
                        || image_name.to_lowercase().contains("install");

                    candidates.push(BlockCandidate {
                        app_name: Some(image_name.replace(".exe", "")),
                        bundle_id: None,
                        executable_name: Some(image_name.clone()),
                        executable_path: None,
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
        // Check Windows Temp directories
        if let Ok(temp_dir) = std::env::var("TEMP") {
            let path = PathBuf::from(temp_dir);
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                        if ext.eq_ignore_ascii_case("msi") || ext.eq_ignore_ascii_case("exe") {
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
