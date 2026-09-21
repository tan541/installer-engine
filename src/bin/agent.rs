use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use installer_engine::{
    init_logger, AppInstallationVerifier, ChecksumVerifier, ControlPlaneClient, EngineConfig,
    HttpControlPlaneClient, InstallerEngine, MockControlPlane, Platform, PlatformInstaller, Task,
    TaskStatus, TaskType,
};

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

/// Checks if current process is running with root privileges (UID 0)
fn is_running_as_root() -> bool {
    #[cfg(unix)]
    unsafe {
        geteuid() == 0
    }
    #[cfg(windows)]
    {
        true
    }
}

struct AgentCliOptions {
    org_id: u64,
    device_id: String,
    control_plane_url: Option<String>,
    cache_dir: PathBuf,
    audit_log_path: PathBuf,
    poll_interval_secs: u64,
    one_shot: bool,
    allow_non_root: bool,
    local_pkg: Option<PathBuf>,
}

impl AgentCliOptions {
    fn parse_from_args() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();
        let mut org_id = 1u64;
        let mut device_id = format!(
            "endpoint-{}",
            hostname::get_hostname().unwrap_or_else(|| "device".to_string())
        );
        let mut control_plane_url = None;
        let mut poll_interval_secs = 10u64;
        let mut one_shot = false;
        let mut allow_non_root = false;
        let mut local_pkg = None;

        let is_root = is_running_as_root();
        let default_cache_dir = if is_root {
            #[cfg(target_os = "macos")]
            {
                PathBuf::from("/Library/Caches/installer-engine")
            }
            #[cfg(target_os = "linux")]
            {
                PathBuf::from("/var/cache/installer-engine")
            }
            #[cfg(target_os = "windows")]
            {
                PathBuf::from(r"C:\ProgramData\installer-engine\cache")
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                std::env::temp_dir().join("installer-engine-cache")
            }
        } else {
            std::env::temp_dir().join("installer-engine-cache")
        };

        let default_audit_log = if is_root {
            #[cfg(unix)]
            {
                PathBuf::from("/var/log/installer-engine-audit.log")
            }
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\ProgramData\installer-engine\audit.log")
            }
        } else {
            std::env::temp_dir().join("installer-engine-audit.log")
        };

        let mut cache_dir = default_cache_dir;
        let mut audit_log_path = default_audit_log;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    print_help(&args[0]);
                    std::process::exit(0);
                }
                "--org-id" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--org-id requires a numeric argument".to_string());
                    }
                    org_id = args[i].parse().map_err(|e| format!("Invalid org-id: {e}"))?;
                }
                "--device-id" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--device-id requires a string argument".to_string());
                    }
                    device_id = args[i].clone();
                }
                "--control-plane-url" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--control-plane-url requires a URL argument".to_string());
                    }
                    control_plane_url = Some(args[i].clone());
                }
                "--cache-dir" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--cache-dir requires a path argument".to_string());
                    }
                    cache_dir = PathBuf::from(&args[i]);
                }
                "--audit-log" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--audit-log requires a path argument".to_string());
                    }
                    audit_log_path = PathBuf::from(&args[i]);
                }
                "--poll-interval" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--poll-interval requires seconds argument".to_string());
                    }
                    poll_interval_secs = args[i]
                        .parse()
                        .map_err(|e| format!("Invalid poll-interval: {e}"))?;
                }
                "--one-shot" => {
                    one_shot = true;
                }
                "--allow-non-root" | "--skip-root-check" => {
                    allow_non_root = true;
                }
                "--pkg" | "--local-pkg" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--pkg requires a package path argument".to_string());
                    }
                    local_pkg = Some(PathBuf::from(&args[i]));
                }
                unknown => {
                    return Err(format!("Unknown argument: {unknown}. Use --help for usage."));
                }
            }
            i += 1;
        }

        Ok(Self {
            org_id,
            device_id,
            control_plane_url,
            cache_dir,
            audit_log_path,
            poll_interval_secs,
            one_shot,
            allow_non_root,
            local_pkg,
        })
    }
}

mod hostname {
    pub fn get_hostname() -> Option<String> {
        if let Ok(h) = std::env::var("HOSTNAME") {
            return Some(h);
        }
        if let Ok(h) = std::env::var("HOST") {
            return Some(h);
        }
        if let Ok(output) = std::process::Command::new("hostname").output() {
            if output.status.success() {
                return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
        }
        None
    }
}

fn print_help(bin_name: &str) {
    println!(
        r#"Installer Engine Endpoint Agent

USAGE:
    sudo {bin_name} [OPTIONS]

DESCRIPTION:
    Runs the endpoint installer agent daemon or one-shot task executor as root.
    Polls the control plane for application distribution tasks, downloads and
    verifies packages (SHA-256), and executes native silent installations.

OPTIONS:
    --pkg <PATH>                Run immediate local package installation workflow (e.g. data/ShieldNet 360-1.6.0-arm64.pkg)
    --org-id <NUM>              Organization ID (default: 1)
    --device-id <ID>            Device identifier (default: endpoint-<hostname>)
    --control-plane-url <URL>   Remote Control Plane HTTP base URL (if omitted, uses built-in mock Control Plane)
    --cache-dir <PATH>          Staging cache directory (default: /Library/Caches/installer-engine on macOS)
    --audit-log <PATH>          Audit trail output file (default: /var/log/installer-engine-audit.log)
    --poll-interval <SECS>      Polling interval in seconds for daemon mode (default: 10)
    --one-shot                  Poll control plane once, execute pending tasks, and exit
    --allow-non-root            Allow running without root privileges (useful for dry-run/testing)
    -h, --help                  Print this help information
"#
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Tracing Logger
    init_logger();

    let opts = match AgentCliOptions::parse_from_args() {
        Ok(o) => o,
        Err(err) => {
            eprintln!("[ERROR] {}\n", err);
            print_help("installer-agent");
            std::process::exit(1);
        }
    };

    println!("============================================================");
    println!("     Installer Engine Native Endpoint Agent Daemon          ");
    println!("============================================================");

    // 2. Root Privilege Check
    let is_root = is_running_as_root();
    println!("[Agent Identity]");
    println!("    - Running as Root:   {}", if is_root { "YES (UID 0)" } else { "NO" });
    println!("    - Org ID:            {}", opts.org_id);
    println!("    - Device ID:         {}", opts.device_id);
    println!("    - Platform:          {}", Platform::current());
    println!("    - Cache Directory:   {}", opts.cache_dir.display());
    println!("    - Audit Trail File:  {}\n", opts.audit_log_path.display());

    if !is_root && !opts.allow_non_root {
        eprintln!("============================================================");
        eprintln!("[ERROR] 'installer-agent' must be run with root privileges");
        eprintln!("        to perform system installations into /Applications.");
        eprintln!();
        eprintln!("Please execute using sudo:");
        eprintln!("    sudo ./target/release/installer-agent");
        eprintln!("Or pass --allow-non-root for unprivileged testing.");
        eprintln!("============================================================");
        std::process::exit(1);
    }

    // 3. Initialize Control Plane Client
    let mock_cp = if opts.control_plane_url.is_none() {
        Some(Arc::new(MockControlPlane::new()))
    } else {
        None
    };

    let control_plane: Arc<dyn ControlPlaneClient> = if let Some(ref url) = opts.control_plane_url {
        println!("[Control Plane] Connecting to remote endpoint: {}", url);
        Arc::new(HttpControlPlaneClient::new(url))
    } else {
        println!("[Control Plane] Using embedded Control Plane service");
        mock_cp.clone().unwrap()
    };

    // 4. Initialize Engine Config & Native Platform Installer
    let engine_config = EngineConfig {
        org_id: opts.org_id,
        device_id: opts.device_id.clone(),
        platform: Platform::current(),
        cache_dir: opts.cache_dir.clone(),
        audit_log_path: opts.audit_log_path.clone(),
    };

    let native_installer = Box::new(PlatformInstaller::for_current_os());
    let engine = InstallerEngine::new(engine_config, control_plane.clone(), native_installer)?;

    // 5. Handle Local Package Test Mode
    if let Some(ref pkg_path) = opts.local_pkg {
        return run_local_package_workflow(&engine, mock_cp, &opts, pkg_path).await;
    }

    // 6. Polling Execution Mode (One-shot or Daemon Loop)
    if opts.one_shot {
        println!("[Execution] Running in ONE-SHOT mode...");
        let processed = engine.poll_and_execute_once().await?;
        println!("[Execution] Processed {} task(s). Exiting.\n", processed);
        return Ok(());
    }

    println!("[Daemon] Starting task polling loop (interval: {}s)...", opts.poll_interval_secs);
    println!("[Daemon] Press Ctrl+C to stop.\n");

    let poll_interval = Duration::from_secs(opts.poll_interval_secs);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n[Daemon] Received shutdown signal. Gracefully stopping agent.");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                match engine.fetch_pending_tasks().await {
                    Ok(tasks) => {
                        if !tasks.is_empty() {
                            println!("[Daemon] Found {} pending task(s) to process", tasks.len());
                            for task in tasks {
                                println!("  -> Processing task: {} ({})", task.task_id, task.app_name);
                                match engine.process_task(&task).await {
                                    Ok(report) => {
                                        println!("     [SUCCESS] {}", report.message);
                                        if let Some(ref path) = report.installed_path {
                                            println!("     [INSTALLED PATH] {}", path);
                                        }
                                        verify_installed_app_report(&task.app_name);
                                    }
                                    Err(e) => {
                                        eprintln!("     [FAILED] Task error: {e}");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Daemon] Error polling control plane: {e}");
                    }
                }
            }
        }
    }

    println!("[Daemon] Agent stopped cleanly.");
    Ok(())
}

async fn run_local_package_workflow(
    engine: &InstallerEngine,
    mock_cp: Option<Arc<MockControlPlane>>,
    opts: &AgentCliOptions,
    pkg_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[Local Mode] Packaging target: {}", pkg_path.display());

    if !pkg_path.exists() {
        return Err(format!("Package file not found: {}", pkg_path.display()).into());
    }

    let abs_pkg_path = std::fs::canonicalize(pkg_path)?;
    println!("[Local Mode] Computing SHA-256 checksum...");
    let checksum = ChecksumVerifier::compute_sha256(&abs_pkg_path)?;
    println!("    - SHA-256: {}\n", checksum);

    let file_stem = abs_pkg_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app_package");

    // Extract app name cleanly
    let app_name = if file_stem.contains('-') {
        file_stem.split('-').next().unwrap_or(file_stem).to_string()
    } else {
        file_stem.to_string()
    };

    let task = Task {
        task_id: format!("local-task-{}", uuid::Uuid::new_v4()),
        org_id: opts.org_id,
        device_id: opts.device_id.clone(),
        target_platform: Platform::current(),
        task_type: TaskType::InstallApp,
        task_desc: format!("Local installation of {}", app_name),
        app_name: app_name.clone(),
        app_version: Some("latest".to_string()),
        download_url: format!("file://{}", abs_pkg_path.display()),
        expected_checksum: checksum,
        installer_args: vec!["-target".to_string(), "/".to_string()],
        task_status: TaskStatus::New,
        error_message: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    if let Some(cp) = mock_cp {
        cp.insert_task(task.clone());
    }

    println!("[Local Mode] Executing installation engine pipeline...");
    let report = engine.process_task(&task).await?;

    println!("\n============================================================");
    println!("               Installation Result Summary                  ");
    println!("============================================================");
    println!("Status:         {}", if report.success { "SUCCESS" } else { "FAILED" });
    println!("Exit Code:      {:?}", report.exit_code);
    println!("Message:        {}", report.message);
    println!("Duration:       {} ms", report.duration_ms);
    if let Some(ref path) = report.installed_path {
        println!("Installed Path: {}", path);
    }
    println!("============================================================\n");

    // Post-install /Applications verification
    verify_installed_app_report(&app_name);

    Ok(())
}

fn verify_installed_app_report(app_name: &str) {
    println!("[Post-Install Verification]");
    if let Some(found_path) = AppInstallationVerifier::verify_app_installed(app_name, Platform::current()) {
        println!("    -> Application verified on system at: {}", found_path.display());
    } else {
        println!("    -> Notice: '{}' was not found in standard system application directories yet.", app_name);
    }
}
