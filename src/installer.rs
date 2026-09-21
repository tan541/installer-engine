pub mod linux;
pub mod macos;
pub mod windows;

use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use crate::error::{EngineError, Result};
use crate::models::{InstallReport, Platform};

pub trait Installer: Send + Sync {
    fn install<'a>(
        &'a self,
        package_path: &'a Path,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<InstallReport>> + Send + 'a>>;
}

pub struct PlatformInstaller {
    platform: Platform,
    macos: macos::MacOSInstaller,
    linux: linux::LinuxInstaller,
    windows: windows::WindowsInstaller,
}

impl PlatformInstaller {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            macos: macos::MacOSInstaller::new(),
            linux: linux::LinuxInstaller::new(),
            windows: windows::WindowsInstaller::new(),
        }
    }

    pub fn for_current_os() -> Self {
        Self::new(Platform::current())
    }
}

impl Installer for PlatformInstaller {
    fn install<'a>(
        &'a self,
        package_path: &'a Path,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<InstallReport>> + Send + 'a>> {
        Box::pin(async move {
            match self.platform {
                Platform::MacOS => self.macos.install(package_path, args).await,
                Platform::Linux => self.linux.install(package_path, args).await,
                Platform::Windows => self.windows.install(package_path, args).await,
                Platform::Unknown => Err(EngineError::UnsupportedPlatform(
                    "Unknown platform cannot execute native installers".to_string(),
                )),
            }
        })
    }
}

/// Simulated mock installer for deterministic testing across platforms
#[derive(Clone, Default)]
pub struct MockInstaller {
    pub should_succeed: bool,
    pub simulated_installed_path: Option<String>,
}

impl MockInstaller {
    pub fn successful() -> Self {
        Self {
            should_succeed: true,
            simulated_installed_path: Some("/opt/mock-app".to_string()),
        }
    }

    pub fn failing(err_msg: &str) -> Self {
        Self {
            should_succeed: false,
            simulated_installed_path: Some(err_msg.to_string()),
        }
    }
}

impl Installer for MockInstaller {
    fn install<'a>(
        &'a self,
        package_path: &'a Path,
        _args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<InstallReport>> + Send + 'a>> {
        Box::pin(async move {
            if self.should_succeed {
                Ok(InstallReport {
                    success: true,
                    exit_code: Some(0),
                    message: format!("Successfully installed {}", package_path.display()),
                    installed_path: self.simulated_installed_path.clone(),
                    duration_ms: 15,
                })
            } else {
                Err(EngineError::InstallerExecution {
                    exit_code: Some(1),
                    message: self
                        .simulated_installed_path
                        .clone()
                        .unwrap_or_else(|| "Simulated install failure".to_string()),
                })
            }
        })
    }
}

pub fn create_installer(platform: Platform) -> Box<dyn Installer> {
    Box::new(PlatformInstaller::new(platform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_installer_success() {
        let installer = MockInstaller::successful();
        let path = Path::new("/tmp/test.pkg");
        let report = installer.install(path, &[]).await.unwrap();
        assert!(report.success);
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_mock_installer_failure() {
        let installer = MockInstaller::failing("Disk full");
        let path = Path::new("/tmp/test.pkg");
        let err = installer.install(path, &[]).await.unwrap_err();
        match err {
            EngineError::InstallerExecution { message, .. } => {
                assert!(message.contains("Disk full"));
            }
            _ => panic!("Unexpected error type"),
        }
    }
}
