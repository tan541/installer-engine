use std::io::Write;
use std::sync::Arc;
use tempfile::{tempdir, NamedTempFile};

use installer_engine::{
    init_logger, ChecksumVerifier, EngineConfig, GroupPolicy, InstallerEngine, MockControlPlane,
    MockInstaller, Platform,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize logging
    init_logger();
    println!("============================================================");
    println!("   Cross-Platform Application Installer Engine Playground    ");
    println!("============================================================\n");

    // 2. Setup staging and audit environment
    let work_dir = tempdir()?;
    let cache_dir = work_dir.path().join("download_cache");
    let audit_log_path = work_dir.path().join("endpoint_audit.log");

    // 3. Create a sample distribution payload file
    let mut sample_payload = NamedTempFile::new()?;
    let binary_bytes = b"MS_TEAMS_SIMULATED_INSTALLER_BINARY_V1.5.0";
    sample_payload.write_all(binary_bytes)?;
    sample_payload.flush()?;

    let sha256_checksum = ChecksumVerifier::compute_bytes_sha256(binary_bytes);
    let payload_url = format!("file://{}", sample_payload.path().display());

    println!("[1] Sample Payload Prepared:");
    println!("    - Source URL: {}", payload_url);
    println!("    - SHA-256:    {}\n", sha256_checksum);

    // 4. Setup Control Plane and Group Policy
    let control_plane = Arc::new(MockControlPlane::new());
    let policy = GroupPolicy {
        group_policy_id: 101,
        org_id: 1,
        group_type: "distribute.app".to_string(),
        app_name: "Microsoft Teams".to_string(),
        app_version: Some("1.5.0".to_string()),
        download_url: payload_url,
        checksum_sha256: sha256_checksum,
        target_platforms: vec![Platform::MacOS, Platform::Linux, Platform::Windows],
        installer_args: vec!["--silent".to_string()],
    };

    println!("[2] Generating Tasks from Group Policy for Devices...");
    let devices = [
        ("device-mac-001", Platform::MacOS),
        ("device-linux-002", Platform::Linux),
        ("device-win-003", Platform::Windows),
    ];

    use installer_engine::ControlPlaneClient;
    let generated_tasks = control_plane
        .generate_tasks_from_policy(&policy, &devices)
        .await?;

    println!("    -> Generated {} tasks:", generated_tasks.len());
    for t in &generated_tasks {
        println!(
            "       - Task ID: {} | Device: {} | Platform: {} | Status: {}",
            t.task_id, t.device_id, t.target_platform, t.task_status
        );
    }
    println!();

    // 5. Initialize Endpoint Agent Engine on Mac device
    println!("[3] Initializing Endpoint Agent Engine on device-mac-001...");
    let engine_config = EngineConfig {
        org_id: 1,
        device_id: "device-mac-001".to_string(),
        platform: Platform::MacOS,
        cache_dir: cache_dir.clone(),
        audit_log_path: audit_log_path.clone(),
    };

    let installer = Box::new(MockInstaller::successful());
    let engine = InstallerEngine::new(engine_config, control_plane.clone(), installer)?;

    // 6. Polling and executing pending tasks
    println!("[4] Polling Control Plane for pending tasks...");
    let pending_tasks = engine.fetch_pending_tasks().await?;
    println!("    -> Found {} pending task(s)", pending_tasks.len());

    for task in &pending_tasks {
        println!("    -> Executing Task: {}", task.task_id);
        let report = engine.process_task(task).await?;
        println!("       Success: {}", report.success);
        println!("       Exit code: {:?}", report.exit_code);
        println!("       Message: {}", report.message);
        println!("       Duration: {} ms\n", report.duration_ms);
    }

    // 7. Verify task status synced back in Control Plane
    println!("[5] Verifying Synchronized Status in Control Plane:");
    for t in &generated_tasks {
        if let Some(current) = control_plane.get_task(&t.task_id) {
            println!(
                "    - Task ID: {} | Device: {} | Status: {}",
                current.task_id, current.device_id, current.task_status
            );
        }
    }
    println!();

    // 8. Inspect Local Audit Trail
    println!("[6] Local Audit Log Records ({}):", audit_log_path.display());
    let audit_content = std::fs::read_to_string(&audit_log_path)?;
    for line in audit_content.lines() {
        println!("    {}", line);
    }

    println!("\n============================================================");
    println!("   All steps completed successfully!                        ");
    println!("============================================================");

    Ok(())
}
