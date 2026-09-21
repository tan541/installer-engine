use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

use installer_engine::{
    installer::macos::MacOSInstaller, AppInstallationVerifier, ChecksumVerifier,
    ControlPlaneClient, EngineConfig, EngineError, GroupPolicy, InstallerEngine, MockControlPlane,
    MockInstaller, Platform, Task, TaskStatus, TaskType,
};

fn get_shieldnet_pkg_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pkg_path = Path::new(manifest_dir)
        .join("data")
        .join("ShieldNet 360-1.6.0-arm64.pkg");
    assert!(
        pkg_path.exists(),
        "ShieldNet 360 pkg must exist at {}",
        pkg_path.display()
    );
    pkg_path
}

#[tokio::test]
async fn test_shieldnet_e2e_successful_installation_flow() {
    let pkg_path = get_shieldnet_pkg_path();
    let computed_checksum = ChecksumVerifier::compute_sha256(&pkg_path)
        .expect("Failed to compute sha256 of ShieldNet pkg");
    assert_eq!(
        computed_checksum,
        "0e53eed38f7d0d900bf8beb1cb02ec092a7c7bf2f9704f5c3a61f10f0cbc9d2b",
        "Calculated checksum matches expected hash"
    );

    let pkg_url = format!("file://{}", pkg_path.display());

    // 1. Setup Staging Environment
    let work_dir = tempdir().expect("Failed to create temp dir");
    let cache_dir = work_dir.path().join("download_cache");
    let audit_log_path = work_dir.path().join("endpoint_audit.log");

    // 2. Control Plane & Group Policy Setup
    let control_plane = Arc::new(MockControlPlane::new());
    let policy = GroupPolicy {
        group_policy_id: 2001,
        org_id: 42,
        group_type: "distribute.app".to_string(),
        app_name: "ShieldNet 360".to_string(),
        app_version: Some("1.6.0".to_string()),
        download_url: pkg_url.clone(),
        checksum_sha256: computed_checksum.clone(),
        target_platforms: vec![Platform::MacOS],
        installer_args: vec!["-target".to_string(), "/".to_string()],
    };

    let devices = [
        ("mac-sec-endpoint-01", Platform::MacOS),
        ("mac-sec-endpoint-02", Platform::MacOS),
    ];

    let tasks = control_plane
        .generate_tasks_from_policy(&policy, &devices)
        .await
        .expect("Task generation should succeed");
    assert_eq!(tasks.len(), 2);

    // 3. Initialize Engine for Device 1
    let engine_config = EngineConfig {
        org_id: 42,
        device_id: "mac-sec-endpoint-01".to_string(),
        platform: Platform::MacOS,
        cache_dir: cache_dir.clone(),
        audit_log_path: audit_log_path.clone(),
    };

    let installer = Box::new(MockInstaller::successful());
    let engine = InstallerEngine::new(engine_config, control_plane.clone(), installer)
        .expect("Engine init should succeed");

    // 4. Fetch Pending Tasks for Device 1
    let pending_tasks = engine
        .fetch_pending_tasks()
        .await
        .expect("Fetching tasks should succeed");
    assert_eq!(pending_tasks.len(), 1);
    let target_task = &pending_tasks[0];
    assert_eq!(target_task.device_id, "mac-sec-endpoint-01");
    assert_eq!(target_task.app_name, "ShieldNet 360");
    assert_eq!(target_task.app_version, Some("1.6.0".to_string()));
    assert_eq!(target_task.task_status, TaskStatus::New);

    // 5. Execute Pipeline
    let report = engine
        .process_task(target_task)
        .await
        .expect("ShieldNet processing should succeed");
    assert!(report.success);
    assert_eq!(report.exit_code, Some(0));

    // 6. Verify Download Cache contains the PKG
    let cached_file = cache_dir.join("ShieldNet 360-1.6.0-arm64.pkg");
    assert!(
        cached_file.exists(),
        "Cached file should exist at {}",
        cached_file.display()
    );
    let cached_size = std::fs::metadata(&cached_file).unwrap().len();
    assert_eq!(
        cached_size,
        std::fs::metadata(&pkg_path).unwrap().len(),
        "Cached package size must match source pkg size"
    );

    // 7. Verify Control Plane Status Synced to Done
    let updated_task = control_plane
        .get_task(&target_task.task_id)
        .expect("Task must exist in control plane");
    assert_eq!(updated_task.task_status, TaskStatus::Done);
    assert!(updated_task.error_message.is_none());

    // 8. Verify Local Audit Trail
    let audit_content =
        std::fs::read_to_string(&audit_log_path).expect("Audit log must be readable");
    assert!(audit_content.contains("task.pickup"));
    assert!(audit_content.contains("task.verify_checksum"));
    assert!(audit_content.contains("task.complete"));
    assert!(audit_content.contains("ShieldNet 360"));
    assert!(audit_content.contains(&computed_checksum));
}

#[tokio::test]
async fn test_shieldnet_e2e_checksum_tampered_fails() {
    let pkg_path = get_shieldnet_pkg_path();
    let pkg_url = format!("file://{}", pkg_path.display());

    let work_dir = tempdir().expect("Failed to create temp dir");
    let cache_dir = work_dir.path().join("download_cache");
    let audit_log_path = work_dir.path().join("endpoint_audit.log");

    let control_plane = Arc::new(MockControlPlane::new());
    let tampered_checksum =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();

    let task = Task {
        task_id: "shieldnet-tampered-001".to_string(),
        org_id: 42,
        device_id: "mac-sec-endpoint-tampered".to_string(),
        target_platform: Platform::MacOS,
        task_type: TaskType::InstallApp,
        task_desc: "install shieldnet 360".to_string(),
        app_name: "ShieldNet 360".to_string(),
        app_version: Some("1.6.0".to_string()),
        download_url: pkg_url,
        expected_checksum: tampered_checksum.clone(),
        installer_args: vec![],
        task_status: TaskStatus::New,
        error_message: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    control_plane.insert_task(task.clone());

    let engine_config = EngineConfig {
        org_id: 42,
        device_id: "mac-sec-endpoint-tampered".to_string(),
        platform: Platform::MacOS,
        cache_dir,
        audit_log_path: audit_log_path.clone(),
    };

    let installer = Box::new(MockInstaller::successful());
    let engine = InstallerEngine::new(engine_config, control_plane.clone(), installer)
        .expect("Engine init should succeed");

    let result = engine.process_task(&task).await;
    assert!(result.is_err());

    match result.unwrap_err() {
        EngineError::ChecksumMismatch {
            expected,
            calculated,
            ..
        } => {
            assert_eq!(expected, tampered_checksum);
            assert_eq!(
                calculated,
                "0e53eed38f7d0d900bf8beb1cb02ec092a7c7bf2f9704f5c3a61f10f0cbc9d2b"
            );
        }
        other => panic!("Expected ChecksumMismatch error, got {:?}", other),
    }

    // Verify Control Plane Status Synced to Failed
    let updated_task = control_plane
        .get_task(&task.task_id)
        .expect("Task must exist in control plane");
    assert_eq!(updated_task.task_status, TaskStatus::Failed);
    assert!(
        updated_task
            .error_message
            .as_ref()
            .unwrap()
            .contains("Checksum mismatch")
    );

    // Verify Audit Log records failure
    let audit_content =
        std::fs::read_to_string(&audit_log_path).expect("Audit log must be readable");
    assert!(audit_content.contains("task.pickup"));
    assert!(audit_content.contains("task.fail"));
}

/// Custom spy installer to verify that silent/unattended flags are faithfully passed down
struct RecordingInstaller {
    captured_path: std::sync::Mutex<Option<PathBuf>>,
    captured_args: std::sync::Mutex<Option<Vec<String>>>,
}

impl RecordingInstaller {
    fn new() -> Self {
        Self {
            captured_path: std::sync::Mutex::new(None),
            captured_args: std::sync::Mutex::new(None),
        }
    }
}

impl installer_engine::Installer for RecordingInstaller {
    fn install<'a>(
        &'a self,
        package_path: &'a Path,
        args: &'a [String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = installer_engine::Result<installer_engine::InstallReport>> + Send + 'a>> {
        *self.captured_path.lock().unwrap() = Some(package_path.to_path_buf());
        *self.captured_args.lock().unwrap() = Some(args.to_vec());

        Box::pin(async move {
            Ok(installer_engine::InstallReport {
                success: true,
                exit_code: Some(0),
                message: format!("Silent installation of {} executed with args {:?}", package_path.display(), args),
                installed_path: Some("/Applications/ShieldNet 360.app".to_string()),
                duration_ms: 45,
            })
        })
    }
}

#[tokio::test]
async fn test_shieldnet_e2e_silent_installer_arguments_propagated() {
    let pkg_path = get_shieldnet_pkg_path();
    let computed_checksum = ChecksumVerifier::compute_sha256(&pkg_path)
        .expect("Failed to compute sha256 of ShieldNet pkg");
    let pkg_url = format!("file://{}", pkg_path.display());

    let work_dir = tempdir().expect("Failed to create temp dir");
    let cache_dir = work_dir.path().join("download_cache");
    let audit_log_path = work_dir.path().join("endpoint_audit.log");

    let control_plane = Arc::new(MockControlPlane::new());

    // Explicit unattended / silent installer arguments for macOS PKG
    let silent_args = vec![
        "-target".to_string(),
        "/".to_string(),
        "-allowUntrusted".to_string(),
        "-dumplog".to_string(),
    ];

    let policy = GroupPolicy {
        group_policy_id: 3001,
        org_id: 99,
        group_type: "distribute.app".to_string(),
        app_name: "ShieldNet 360".to_string(),
        app_version: Some("1.6.0".to_string()),
        download_url: pkg_url,
        checksum_sha256: computed_checksum,
        target_platforms: vec![Platform::MacOS],
        installer_args: silent_args.clone(),
    };

    let devices = [("mac-silent-test-01", Platform::MacOS)];
    let tasks = control_plane
        .generate_tasks_from_policy(&policy, &devices)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].installer_args, silent_args);

    let engine_config = EngineConfig {
        org_id: 99,
        device_id: "mac-silent-test-01".to_string(),
        platform: Platform::MacOS,
        cache_dir,
        audit_log_path: audit_log_path.clone(),
    };

    let spy = Arc::new(RecordingInstaller::new());
    struct SpyWrapper(Arc<RecordingInstaller>);
    impl installer_engine::Installer for SpyWrapper {
        fn install<'a>(
            &'a self,
            package_path: &'a Path,
            args: &'a [String],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = installer_engine::Result<installer_engine::InstallReport>> + Send + 'a>> {
            self.0.install(package_path, args)
        }
    }

    let engine = InstallerEngine::new(engine_config, control_plane.clone(), Box::new(SpyWrapper(spy.clone())))
        .expect("Engine init should succeed");

    let report = engine.process_task(&tasks[0]).await.unwrap();
    assert!(report.success);
    assert_eq!(report.exit_code, Some(0));

    // Verify spy captured exact silent args and package path
    let recorded_args = spy.captured_args.lock().unwrap().clone().unwrap();
    assert_eq!(recorded_args, silent_args, "Silent arguments must be passed untouched");

    let recorded_path = spy.captured_path.lock().unwrap().clone().unwrap();
    assert!(recorded_path.ends_with("ShieldNet 360-1.6.0-arm64.pkg"));

    // Verify audit trail captured the silent execution report
    let audit_content = std::fs::read_to_string(&audit_log_path).unwrap();
    assert!(audit_content.contains("Silent installation"));
    assert!(audit_content.contains("task.complete"));
}

#[tokio::test]
async fn test_shieldnet_e2e_installed_app_in_applications_verification() {
    let pkg_path = get_shieldnet_pkg_path();

    // 1. Verify that the PKG payload explicitly targets "ShieldNet 360.app"
    let extracted_app = MacOSInstaller::extract_app_name_from_pkg(&pkg_path)
        .expect("Must extract app bundle name from ShieldNet PKG payload");
    assert_eq!(extracted_app, "ShieldNet 360.app");

    // 2. Setup Staging Application Directory (simulating /Applications installation)
    let fake_root = tempdir().expect("Failed to create fake root temp dir");
    let fake_applications = fake_root.path().join("Applications");
    std::fs::create_dir_all(&fake_applications).unwrap();

    let fake_app_bundle = fake_applications.join("ShieldNet 360.app");
    std::fs::create_dir_all(fake_app_bundle.join("Contents/MacOS")).unwrap();
    std::fs::write(fake_app_bundle.join("Contents/Info.plist"), "<plist></plist>").unwrap();

    // 3. Verify AppInstallationVerifier locates the installed bundle in the Applications directory
    let found_app = AppInstallationVerifier::verify_in_directory("ShieldNet 360", &fake_applications);
    assert!(found_app.is_some(), "ShieldNet 360 must be verified in Applications folder");
    assert_eq!(found_app.unwrap(), fake_app_bundle);

    // 4. Verify case-insensitive and .app extension handling
    let found_app_by_filename = AppInstallationVerifier::verify_in_directory("shieldnet 360.app", &fake_applications);
    assert_eq!(found_app_by_filename, Some(fake_app_bundle));

    // 5. Test installer mock that simulates real installation into /Applications
    let target_app_path = format!("/Applications/{}", extracted_app);
    let mock_installer = MockInstaller {
        should_succeed: true,
        simulated_installed_path: Some(target_app_path.clone()),
    };

    let report = installer_engine::Installer::install(&mock_installer, &pkg_path, &[])
        .await
        .unwrap();

    assert!(report.success);
    assert_eq!(report.installed_path, Some("/Applications/ShieldNet 360.app".to_string()));
}

