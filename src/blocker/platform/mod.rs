use std::path::{Path, PathBuf};
use crate::blocker::models::BlockCandidate;
use crate::error::Result;

pub mod linux;
pub mod macos;
pub mod windows;

pub use linux::LinuxRemediator;
pub use macos::MacOSRemediator;
pub use windows::WindowsRemediator;

/// Trait for platform-specific remediation and inspection
pub trait PlatformRemediator: Send + Sync {
    /// Terminates a process by its PID
    fn terminate_process(&self, pid: u32) -> Result<bool>;

    /// Terminates all processes matching the given name
    fn terminate_process_by_name(&self, name: &str) -> Result<usize>;

    /// Moves a blocked application or installer file into the quarantine directory
    fn quarantine_path(&self, target_path: &Path, quarantine_dir: &Path) -> Result<PathBuf>;

    /// Inspects running processes on the system to find candidate processes
    fn scan_running_processes(&self) -> Result<Vec<BlockCandidate>>;

    /// Checks active filesystem staging / mount areas for newly dropped unapproved apps
    fn scan_staging_areas(&self) -> Result<Vec<BlockCandidate>>;
}

/// Creates the appropriate PlatformRemediator for the current operating system
pub fn create_platform_remediator() -> Box<dyn PlatformRemediator> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSRemediator::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsRemediator::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxRemediator::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Box::new(MockRemediator::new())
    }
}

/// Mock remediator for unit testing
#[derive(Debug, Default, Clone)]
pub struct MockRemediator {
    pub killed_pids: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
    pub quarantined_paths: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
    pub mocked_candidates: std::sync::Arc<std::sync::Mutex<Vec<BlockCandidate>>>,
}

impl MockRemediator {
    pub fn new() -> Self {
        Self {
            killed_pids: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            quarantined_paths: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            mocked_candidates: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn set_candidates(&self, candidates: Vec<BlockCandidate>) {
        let mut lock = self.mocked_candidates.lock().unwrap();
        *lock = candidates;
    }
}

impl PlatformRemediator for MockRemediator {
    fn terminate_process(&self, pid: u32) -> Result<bool> {
        let mut lock = self.killed_pids.lock().unwrap();
        lock.push(pid);
        Ok(true)
    }

    fn terminate_process_by_name(&self, _name: &str) -> Result<usize> {
        Ok(1)
    }

    fn quarantine_path(&self, target_path: &Path, quarantine_dir: &Path) -> Result<PathBuf> {
        let dest = quarantine_dir.join(target_path.file_name().unwrap_or_default());
        let mut lock = self.quarantined_paths.lock().unwrap();
        lock.push(target_path.to_path_buf());
        Ok(dest)
    }

    fn scan_running_processes(&self) -> Result<Vec<BlockCandidate>> {
        let lock = self.mocked_candidates.lock().unwrap();
        Ok(lock.clone())
    }

    fn scan_staging_areas(&self) -> Result<Vec<BlockCandidate>> {
        Ok(Vec::new())
    }
}
