use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::blocker::models::{AppBlockPolicy, BlockCandidate, BlockRuleType};
use crate::blocker::platform::PlatformRemediator;
use crate::error::{EngineError, Result};
use crate::verifier::ChecksumVerifier;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct WinProcessInfo {
    #[serde(rename = "Id")]
    id: u32,
    #[serde(rename = "ProcessName")]
    process_name: String,
    #[serde(rename = "Path")]
    path: Option<String>,
    #[serde(rename = "CommandLine")]
    command_line: Option<String>,
}

#[derive(Debug, Default)]
pub struct WindowsRemediator;

impl WindowsRemediator {
    pub fn new() -> Self {
        Self
    }

    /// Generates standard AppLocker XML policy for Windows 11 Enterprise/Education
    pub fn generate_applocker_xml(policy: &AppBlockPolicy) -> String {
        let mut xml = String::from(
            "<AppLockerPolicy Version=\"1\">\n  <RuleCollection Type=\"Exe\" EnforcementMode=\"Enabled\">\n",
        );

        for (i, rule) in policy.rules.iter().enumerate() {
            let rule_guid = format!("00000000-0000-0000-0000-{:012x}", i + 1);
            match &rule.match_type {
                BlockRuleType::ExactName(name) | BlockRuleType::ExecutableName(name) => {
                    let exe = if name.ends_with(".exe") { name.clone() } else { format!("{name}.exe") };
                    xml.push_str(&format!(
                        "    <FilePathRule Id=\"{}\" Name=\"{}\" Description=\"{}\" UserOrGroupSid=\"S-1-1-0\" Action=\"Deny\">\n      <Conditions>\n        <FilePathCondition Path=\"%OSDRIVE%\\*\\{}\" />\n      </Conditions>\n    </FilePathRule>\n",
                        rule_guid, rule.rule_id, rule.description, exe
                    ));
                }
                BlockRuleType::PatternName(pattern) => {
                    xml.push_str(&format!(
                        "    <FilePathRule Id=\"{}\" Name=\"{}\" Description=\"{}\" UserOrGroupSid=\"S-1-1-0\" Action=\"Deny\">\n      <Conditions>\n        <FilePathCondition Path=\"%OSDRIVE%\\*\\{}\" />\n      </Conditions>\n    </FilePathRule>\n",
                        rule_guid, rule.rule_id, rule.description, pattern
                    ));
                }
                BlockRuleType::ChecksumSha256(hash) => {
                    xml.push_str(&format!(
                        "    <FileHashRule Id=\"{}\" Name=\"{}\" Description=\"{}\" UserOrGroupSid=\"S-1-1-0\" Action=\"Deny\">\n      <Conditions>\n        <FileHashCondition>\n          <FileHash Type=\"SHA256\" Data=\"0x{}\" SourceFileName=\"*\" />\n        </FileHashCondition>\n      </Conditions>\n    </FileHashRule>\n",
                        rule_guid, rule.rule_id, rule.description, hash
                    ));
                }
                BlockRuleType::InstallPathPrefix(prefix) => {
                    xml.push_str(&format!(
                        "    <FilePathRule Id=\"{}\" Name=\"{}\" Description=\"{}\" UserOrGroupSid=\"S-1-1-0\" Action=\"Deny\">\n      <Conditions>\n        <FilePathCondition Path=\"{}\\*\" />\n      </Conditions>\n    </FilePathRule>\n",
                        rule_guid, rule.rule_id, rule.description, prefix.display()
                    ));
                }
                _ => {}
            }
        }

        xml.push_str("  </RuleCollection>\n</AppLockerPolicy>");
        xml
    }

    /// Enforces Windows Registry DisallowRun policy for blocking execution
    pub fn apply_disallow_run_policy(disallowed_exes: &[&str]) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let mut ps_commands = String::from(
                "$regPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; \
                 $disallowPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun'; \
                 New-Item -Path $regPath -Force | Out-Null; \
                 Set-ItemProperty -Path $regPath -Name 'DisallowRun' -Value 1 -Type DWord; \
                 Remove-Item -Path $disallowPath -Recurse -ErrorAction SilentlyContinue; \
                 New-Item -Path $disallowPath -Force | Out-Null; "
            );

            for (idx, exe) in disallowed_exes.iter().enumerate() {
                let name = if exe.ends_with(".exe") { exe.to_string() } else { format!("{exe}.exe") };
                ps_commands.push_str(&format!(
                    "Set-ItemProperty -Path $disallowPath -Name '{}' -Value '{}' -Type String; ",
                    idx + 1,
                    name
                ));
            }

            let status = Command::new("powershell")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_commands])
                .status()
                .map_err(EngineError::Io)?;

            if !status.success() {
                return Err(EngineError::Installation("Failed to apply DisallowRun registry policy".to_string()));
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::info!("DisallowRun policy simulation for {} items", disallowed_exes.len());
        }
        Ok(())
    }

    /// Scans processes using PowerShell to capture Process ID, Image Name, and Executable Path
    #[allow(dead_code)]
    fn scan_processes_powershell(&self) -> Result<Vec<BlockCandidate>> {
        let ps_script = "Get-Process | Where-Object { $_.Path -ne $null -or $_.ProcessName -like '*setup*' -or $_.ProcessName -like '*install*' -or $_.ProcessName -eq 'msiexec' } | Select-Object Id, ProcessName, Path, @{Name='CommandLine';Expression={(Get-CimInstance Win32_Process -Filter \"ProcessId = $($_.Id)\").CommandLine}} | ConvertTo-Json -Compress";

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script])
            .output()
            .map_err(EngineError::Io)?;

        if !output.status.success() {
            return self.scan_processes_tasklist();
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() || stdout == "null" {
            return Ok(Vec::new());
        }

        let proc_list: Vec<WinProcessInfo> = if stdout.starts_with('[') {
            serde_json::from_str(&stdout).unwrap_or_default()
        } else if stdout.starts_with('{') {
            serde_json::from_str::<WinProcessInfo>(&stdout)
                .map(|p| vec![p])
                .unwrap_or_default()
        } else {
            return self.scan_processes_tasklist();
        };

        let mut candidates = Vec::new();
        for p in proc_list {
            let exe_name = format!("{}.exe", p.process_name);
            let is_installer = p.process_name.eq_ignore_ascii_case("msiexec")
                || p.process_name.to_lowercase().contains("setup")
                || p.process_name.to_lowercase().contains("install")
                || p.command_line.as_deref().unwrap_or("").to_lowercase().contains(".msi");

            let path_buf = p.path.map(PathBuf::from);
            let sha256_hash = if let Some(ref path) = path_buf {
                if path.exists() {
                    ChecksumVerifier::compute_sha256(path).ok()
                } else {
                    None
                }
            } else {
                None
            };

            candidates.push(BlockCandidate {
                app_name: Some(p.process_name.clone()),
                bundle_id: None,
                executable_name: Some(exe_name),
                executable_path: path_buf,
                sha256_hash,
                process_id: Some(p.id),
                is_installer,
            });
        }

        Ok(candidates)
    }

    /// Fallback process scanning using tasklist
    fn scan_processes_tasklist(&self) -> Result<Vec<BlockCandidate>> {
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
        #[cfg(target_os = "windows")]
        {
            self.scan_processes_powershell()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.scan_processes_tasklist()
        }
    }

    fn scan_staging_areas(&self) -> Result<Vec<BlockCandidate>> {
        let mut candidates = Vec::new();
        // Check Windows Temp directories
        let temp_dirs = [
            std::env::var("TEMP").ok(),
            std::env::var("TMP").ok(),
            Some(r"C:\Windows\Temp".to_string()),
        ];

        for temp_var in temp_dirs.into_iter().flatten() {
            let path = PathBuf::from(temp_var);
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                        if ext.eq_ignore_ascii_case("msi") || ext.eq_ignore_ascii_case("exe") {
                            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                                let sha256 = ChecksumVerifier::compute_sha256(&p).ok();
                                candidates.push(BlockCandidate {
                                    app_name: Some(stem.to_string()),
                                    bundle_id: None,
                                    executable_name: p.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()),
                                    executable_path: Some(p),
                                    sha256_hash: sha256,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocker::models::{BlockAction, BlockRule, PolicyEnforcementMode};

    #[test]
    fn test_generate_applocker_xml() {
        let policy = AppBlockPolicy {
            policy_id: 1,
            org_id: 1,
            name: "Win11 App Control".to_string(),
            mode: PolicyEnforcementMode::Blocklist,
            rules: vec![
                BlockRule::new("rule-1", "Block uTorrent", BlockRuleType::ExecutableName("uTorrent.exe".to_string()))
                    .with_action(BlockAction::TerminateAndQuarantine),
                BlockRule::new("rule-2", "Block hash", BlockRuleType::ChecksumSha256("aabbcc112233".to_string())),
            ],
            custom_notification_message: None,
            updated_at: chrono::Utc::now(),
        };

        let xml = WindowsRemediator::generate_applocker_xml(&policy);
        assert!(xml.contains("<AppLockerPolicy Version=\"1\">"));
        assert!(xml.contains("uTorrent.exe"));
        assert!(xml.contains("aabbcc112233"));
        assert!(xml.contains("Action=\"Deny\""));
    }
}
