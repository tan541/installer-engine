use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::audit::AuditLogger;
use crate::control_plane::ControlPlaneClient;
use crate::download::Downloader;
use crate::error::Result;
use crate::installer::Installer;
use crate::inventory::{create_inventory_collector, AppInventoryReport, InventoryCollector};
use crate::models::{InstallReport, Platform, Task, TaskStatus, TaskType};
use crate::verifier::ChecksumVerifier;

pub struct EngineConfig {
    pub org_id: u64,
    pub device_id: String,
    pub platform: Platform,
    pub cache_dir: PathBuf,
    pub audit_log_path: PathBuf,
}

pub struct InstallerEngine {
    config: EngineConfig,
    control_plane: Arc<dyn ControlPlaneClient>,
    downloader: Downloader,
    installer: Box<dyn Installer>,
    inventory_collector: Box<dyn InventoryCollector>,
    audit_logger: AuditLogger,
}

impl InstallerEngine {
    pub fn new(
        config: EngineConfig,
        control_plane: Arc<dyn ControlPlaneClient>,
        installer: Box<dyn Installer>,
    ) -> Result<Self> {
        let downloader = Downloader::new(&config.cache_dir)?;
        let audit_logger = AuditLogger::new(&config.audit_log_path)?;
        let inventory_collector = create_inventory_collector(config.platform);

        Ok(Self {
            config,
            control_plane,
            downloader,
            installer,
            inventory_collector,
            audit_logger,
        })
    }

    pub fn with_all(
        config: EngineConfig,
        control_plane: Arc<dyn ControlPlaneClient>,
        installer: Box<dyn Installer>,
        inventory_collector: Box<dyn InventoryCollector>,
    ) -> Result<Self> {
        let downloader = Downloader::new(&config.cache_dir)?;
        let audit_logger = AuditLogger::new(&config.audit_log_path)?;

        Ok(Self {
            config,
            control_plane,
            downloader,
            installer,
            inventory_collector,
            audit_logger,
        })
    }

    /// Fetches pending `New` tasks for this device from the Control Plane.
    pub async fn fetch_pending_tasks(&self) -> Result<Vec<Task>> {
        self.control_plane
            .fetch_tasks(
                self.config.org_id,
                &self.config.device_id,
                self.config.platform,
                Some(TaskStatus::New),
            )
            .await
    }

    /// Processes a single task through the full lifecycle:
    /// 1. Mark status -> Processing
    /// 2. Download package to local cache
    /// 3. Verify Checksum (SHA-256)
    /// 4. Execute installation
    /// 5. Record Audit Trail
    /// 6. Mark status -> Done (or Failed on error)
    pub async fn process_task(&self, task: &Task) -> Result<InstallReport> {
        let start_time = Instant::now();
        tracing::info!(
            task_id = %task.task_id,
            app = %task.app_name,
            platform = %task.target_platform,
            "Starting task processing"
        );

        // 1. Mark task as Processing
        if let Err(e) = self
            .control_plane
            .update_task_status(&task.task_id, TaskStatus::Processing, None)
            .await
        {
            tracing::warn!(task_id = %task.task_id, error = %e, "Failed to update status to Processing");
        }

        let _ = self.audit_logger.record_event(
            "task.pickup",
            &task.task_id,
            task.org_id,
            &task.device_id,
            &task.app_name,
            None,
            "processing",
            Some(format!("Started processing task {}", task.task_desc)),
            None,
        );

        // Execute pipeline
        match self.execute_install_pipeline(task).await {
            Ok(report) => {
                let duration_ms = start_time.elapsed().as_millis() as u64;

                // Sync status Done
                if let Err(e) = self
                    .control_plane
                    .update_task_status(&task.task_id, TaskStatus::Done, None)
                    .await
                {
                    tracing::error!(task_id = %task.task_id, error = %e, "Failed to update task status to Done");
                }

                // Record success in audit log
                let _ = self.audit_logger.record_event(
                    "task.complete",
                    &task.task_id,
                    task.org_id,
                    &task.device_id,
                    &task.app_name,
                    Some(task.expected_checksum.clone()),
                    "done",
                    Some(report.message.clone()),
                    Some(duration_ms),
                );

                tracing::info!(
                    task_id = %task.task_id,
                    duration_ms,
                    "Task completed successfully"
                );

                Ok(report)
            }
            Err(err) => {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                let error_msg = err.to_string();

                // Sync status Failed
                if let Err(e) = self
                    .control_plane
                    .update_task_status(&task.task_id, TaskStatus::Failed, Some(error_msg.clone()))
                    .await
                {
                    tracing::error!(task_id = %task.task_id, error = %e, "Failed to update task status to Failed");
                }

                // Record failure in audit log
                let _ = self.audit_logger.record_event(
                    "task.fail",
                    &task.task_id,
                    task.org_id,
                    &task.device_id,
                    &task.app_name,
                    Some(task.expected_checksum.clone()),
                    "failed",
                    Some(error_msg.clone()),
                    Some(duration_ms),
                );

                tracing::error!(
                    task_id = %task.task_id,
                    error = %err,
                    "Task execution failed"
                );

                Err(err)
            }
        }
    }

    /// Internal execution pipeline helper
    async fn execute_install_pipeline(&self, task: &Task) -> Result<InstallReport> {
        // Handle inventory collection tasks directly
        if task.task_type == TaskType::CollectInventory {
            let report = self.collect_and_sync_inventory().await?;
            return Ok(InstallReport {
                success: true,
                exit_code: Some(0),
                message: format!(
                    "Successfully collected and synchronized {} installed applications",
                    report.total_apps
                ),
                installed_path: None,
                duration_ms: report.scan_duration_ms,
            });
        }

        // Derive local filename from download url
        let file_name = Path::new(&task.download_url)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("package.bin");

        // Step 1: Download package
        let downloaded_path = self.downloader.download(&task.download_url, file_name).await?;

        // Step 2: Verify Checksum
        ChecksumVerifier::verify(&downloaded_path, &task.expected_checksum)?;

        let _ = self.audit_logger.record_event(
            "task.verify_checksum",
            &task.task_id,
            task.org_id,
            &task.device_id,
            &task.app_name,
            Some(task.expected_checksum.clone()),
            "verified",
            None,
            None,
        );

        // Step 3: Install
        let report = self
            .installer
            .install(&downloaded_path, &task.installer_args)
            .await?;

        Ok(report)
    }

    /// Scans installed software on the current device and sends inventory to Control Plane
    pub async fn collect_and_sync_inventory(&self) -> Result<AppInventoryReport> {
        let report = self
            .inventory_collector
            .collect(self.config.org_id, &self.config.device_id)
            .await?;

        self.control_plane.sync_inventory(&report).await?;

        let _ = self.audit_logger.record_event(
            "inventory.sync",
            "inventory-job",
            self.config.org_id,
            &self.config.device_id,
            "System Inventory",
            None,
            "synced",
            Some(format!(
                "Scanned and synchronized {} installed applications",
                report.total_apps
            )),
            Some(report.scan_duration_ms),
        );

        Ok(report)
    }

    /// Polls control plane once and processes all pending tasks
    pub async fn poll_and_execute_once(&self) -> Result<usize> {
        let tasks = self.fetch_pending_tasks().await?;
        let count = tasks.len();

        for task in tasks {
            let _ = self.process_task(&task).await;
        }

        Ok(count)
    }

    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }

    pub fn inventory_collector(&self) -> &dyn InventoryCollector {
        self.inventory_collector.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::MockControlPlane;
    use crate::installer::MockInstaller;
    use crate::models::{Platform, TaskType};
    use chrono::Utc;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[tokio::test]
    async fn test_end_to_end_engine_success() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let audit_log = dir.path().join("audit.log");

        // Create a local dummy package file
        let mut pkg_file = NamedTempFile::new().unwrap();
        let payload = b"app executable binary contents";
        pkg_file.write_all(payload).unwrap();
        pkg_file.flush().unwrap();

        let sha256 = ChecksumVerifier::compute_bytes_sha256(payload);

        let cp = Arc::new(MockControlPlane::new());
        let task = Task {
            task_id: "test-task-1".to_string(),
            org_id: 1,
            device_id: "mac-01".to_string(),
            target_platform: Platform::MacOS,
            task_type: TaskType::InstallApp,
            task_desc: "ms_teams".to_string(),
            app_name: "Microsoft Teams".to_string(),
            app_version: Some("1.0.0".to_string()),
            download_url: format!("file://{}", pkg_file.path().display()),
            expected_checksum: sha256,
            installer_args: vec![],
            task_status: TaskStatus::New,
            error_message: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        cp.insert_task(task.clone());

        let config = EngineConfig {
            org_id: 1,
            device_id: "mac-01".to_string(),
            platform: Platform::MacOS,
            cache_dir,
            audit_log_path: audit_log.clone(),
        };

        let installer = Box::new(MockInstaller::successful());
        let engine = InstallerEngine::new(config, cp.clone(), installer).unwrap();

        let report = engine.process_task(&task).await.unwrap();
        assert!(report.success);

        // Check task status updated to Done in control plane
        let cp_task = cp.get_task("test-task-1").unwrap();
        assert_eq!(cp_task.task_status, TaskStatus::Done);

        // Check audit log contains events
        let audit_content = std::fs::read_to_string(audit_log).unwrap();
        assert!(audit_content.contains("task.pickup"));
        assert!(audit_content.contains("task.verify_checksum"));
        assert!(audit_content.contains("task.complete"));
    }

    #[tokio::test]
    async fn test_end_to_end_engine_checksum_mismatch() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let audit_log = dir.path().join("audit.log");

        let mut pkg_file = NamedTempFile::new().unwrap();
        pkg_file.write_all(b"legit content").unwrap();
        pkg_file.flush().unwrap();

        let cp = Arc::new(MockControlPlane::new());
        let task = Task {
            task_id: "test-task-2".to_string(),
            org_id: 1,
            device_id: "mac-01".to_string(),
            target_platform: Platform::MacOS,
            task_type: TaskType::InstallApp,
            task_desc: "tampered_app".to_string(),
            app_name: "Tampered App".to_string(),
            app_version: None,
            download_url: format!("file://{}", pkg_file.path().display()),
            expected_checksum: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            installer_args: vec![],
            task_status: TaskStatus::New,
            error_message: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        cp.insert_task(task.clone());

        let config = EngineConfig {
            org_id: 1,
            device_id: "mac-01".to_string(),
            platform: Platform::MacOS,
            cache_dir,
            audit_log_path: audit_log.clone(),
        };

        let installer = Box::new(MockInstaller::successful());
        let engine = InstallerEngine::new(config, cp.clone(), installer).unwrap();

        let result = engine.process_task(&task).await;
        assert!(result.is_err());

        // Check task status updated to Failed in control plane
        let cp_task = cp.get_task("test-task-2").unwrap();
        assert_eq!(cp_task.task_status, TaskStatus::Failed);
        assert!(cp_task.error_message.unwrap().contains("Checksum mismatch"));
    }

    #[tokio::test]
    async fn test_end_to_end_engine_inventory_task() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let audit_log = dir.path().join("audit.log");

        let cp = Arc::new(MockControlPlane::new());
        let task = Task {
            task_id: "inventory-task-1".to_string(),
            org_id: 10,
            device_id: "device-mac-01".to_string(),
            target_platform: Platform::MacOS,
            task_type: TaskType::CollectInventory,
            task_desc: "scan_installed_apps".to_string(),
            app_name: "Inventory Scanner".to_string(),
            app_version: None,
            download_url: "none".to_string(),
            expected_checksum: "none".to_string(),
            installer_args: vec![],
            task_status: TaskStatus::New,
            error_message: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        cp.insert_task(task.clone());

        let config = EngineConfig {
            org_id: 10,
            device_id: "device-mac-01".to_string(),
            platform: Platform::MacOS,
            cache_dir,
            audit_log_path: audit_log.clone(),
        };

        let sample_app = crate::inventory::InstalledApp {
            app_id: "com.test.App".to_string(),
            name: "Test App".to_string(),
            version: "1.0.0".to_string(),
            build_version: None,
            publisher: Some("Test Dev".to_string()),
            install_path: Some("/Applications/Test App.app".to_string()),
            installed_at: None,
            architecture: Some("arm64".to_string()),
            package_type: crate::inventory::AppPackageType::AppBundle,
            uninstall_command: None,
            is_system_app: false,
            metadata: std::collections::HashMap::new(),
        };

        let mock_collector = Box::new(crate::inventory::MockInventoryCollector::new(vec![sample_app]));
        let mock_installer = Box::new(MockInstaller::successful());
        let engine = InstallerEngine::with_all(config, cp.clone(), mock_installer, mock_collector).unwrap();

        let report = engine.process_task(&task).await.unwrap();
        assert!(report.success);
        assert!(report.message.contains("1 installed applications"));

        // Verify inventory synchronized to control plane
        let latest_inv = cp.get_latest_inventory().unwrap();
        assert_eq!(latest_inv.total_apps, 1);
        assert_eq!(latest_inv.apps[0].name, "Test App");

        // Verify audit log
        let audit_content = std::fs::read_to_string(audit_log).unwrap();
        assert!(audit_content.contains("inventory.sync"));
    }
}

