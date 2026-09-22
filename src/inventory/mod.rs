pub mod linux;
pub mod macos;
pub mod models;
pub mod windows;

use std::future::Future;
use std::pin::Pin;

use crate::error::{EngineError, Result};
use crate::models::Platform;

pub use linux::LinuxInventoryCollector;
pub use macos::MacOSInventoryCollector;
pub use models::{AppInventoryReport, AppPackageType, InstalledApp};
pub use windows::WindowsInventoryCollector;

pub trait InventoryCollector: Send + Sync {
    fn collect<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AppInventoryReport>> + Send + 'a>>;
}

pub struct PlatformInventoryCollector {
    platform: Platform,
    macos: MacOSInventoryCollector,
    windows: WindowsInventoryCollector,
    linux: LinuxInventoryCollector,
}

impl PlatformInventoryCollector {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            macos: MacOSInventoryCollector::new(),
            windows: WindowsInventoryCollector::new(),
            linux: LinuxInventoryCollector::new(),
        }
    }

    pub fn for_current_os() -> Self {
        Self::new(Platform::current())
    }
}

impl InventoryCollector for PlatformInventoryCollector {
    fn collect<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AppInventoryReport>> + Send + 'a>> {
        Box::pin(async move {
            match self.platform {
                Platform::MacOS => self.macos.collect(org_id, device_id.to_string()),
                Platform::Windows => self.windows.collect(org_id, device_id.to_string()),
                Platform::Linux => self.linux.collect(org_id, device_id.to_string()),
                Platform::Unknown => Err(EngineError::UnsupportedPlatform(
                    "Unknown platform cannot collect application inventory".to_string(),
                )),
            }
        })
    }
}

/// Simulated in-memory inventory collector for deterministic testing
#[derive(Clone, Default)]
pub struct MockInventoryCollector {
    apps: Vec<InstalledApp>,
}

impl MockInventoryCollector {
    pub fn new(apps: Vec<InstalledApp>) -> Self {
        Self { apps }
    }
}

impl InventoryCollector for MockInventoryCollector {
    fn collect<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AppInventoryReport>> + Send + 'a>> {
        let apps = self.apps.clone();
        Box::pin(async move {
            Ok(AppInventoryReport::new(
                org_id,
                device_id.to_string(),
                Platform::current(),
                apps,
                5,
            ))
        })
    }
}

pub fn create_inventory_collector(platform: Platform) -> Box<dyn InventoryCollector> {
    Box::new(PlatformInventoryCollector::new(platform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_inventory_collector() {
        let sample_app = InstalledApp {
            app_id: "test.app".to_string(),
            name: "Test App".to_string(),
            version: "1.0.0".to_string(),
            build_version: None,
            publisher: Some("Test Vendor".to_string()),
            install_path: Some("/Applications/TestApp.app".to_string()),
            installed_at: None,
            architecture: Some("arm64".to_string()),
            package_type: AppPackageType::AppBundle,
            uninstall_command: None,
            is_system_app: false,
            metadata: std::collections::HashMap::new(),
        };

        let collector = MockInventoryCollector::new(vec![sample_app]);
        let report = collector.collect(1, "dev-01").await.unwrap();

        assert_eq!(report.total_apps, 1);
        assert_eq!(report.apps[0].name, "Test App");
        assert!(report.find_app("Test App").is_some());
    }
}
