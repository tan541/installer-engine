use std::io::Write;
use std::sync::Arc;
use tempfile::{tempdir, NamedTempFile};

use installer_engine::{
    AppBlockMonitor, AppBlockMonitorConfig, AppBlockPolicy, BlockAction, BlockCandidate,
    BlockEvaluator, BlockRule, BlockRuleType, ChecksumVerifier, EngineConfig,
    EvaluationResult, InstallerEngine, MockControlPlane, MockDesktopNotifier, MockInstaller,
    MockRemediator, Platform, PolicyEnforcementMode, Task, TaskStatus, TaskType,
};

#[tokio::test]
async fn test_block_evaluator_exact_and_pattern_rules() {
    let policy = AppBlockPolicy {
        policy_id: 1,
        org_id: 100,
        name: "Security Standard Policy".to_string(),
        mode: PolicyEnforcementMode::Blocklist,
        rules: vec![
            BlockRule::new("rule-exact", "Block exact name", BlockRuleType::ExactName("ProhibitedApp".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
            BlockRule::new("rule-wildcard", "Block all torrents", BlockRuleType::PatternName("*torrent*".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
            BlockRule::new("rule-bundle", "Block Spotify", BlockRuleType::BundleIdentifier("com.spotify.client".to_string()))
                .with_action(BlockAction::TerminateOnly),
            BlockRule::new("rule-exe", "Block steam", BlockRuleType::ExecutableName("steam.exe".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
            BlockRule::new("rule-hash", "Block bad binary", BlockRuleType::ChecksumSha256("112233445566aabbcc".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
        ],
        custom_notification_message: Some("Corporate policy blocks this app.".to_string()),
        updated_at: chrono::Utc::now(),
    };

    let evaluator = BlockEvaluator::with_policies(vec![policy]);

    // 1. Exact match test
    let res = evaluator.evaluate(&BlockCandidate::from_name("ProhibitedApp"));
    assert!(res.is_blocked());
    if let EvaluationResult::Blocked { rule_id, .. } = res {
        assert_eq!(rule_id, "rule-exact");
    }

    // 2. Wildcard pattern match test
    let res = evaluator.evaluate(&BlockCandidate::from_name("uTorrent Web Installer"));
    assert!(res.is_blocked());
    if let EvaluationResult::Blocked { rule_id, .. } = res {
        assert_eq!(rule_id, "rule-wildcard");
    }

    // 3. Bundle identifier match test
    let candidate_bundle = BlockCandidate {
        bundle_id: Some("com.spotify.client".to_string()),
        ..Default::default()
    };
    let res = evaluator.evaluate(&candidate_bundle);
    assert!(res.is_blocked());
    if let EvaluationResult::Blocked { rule_id, action, .. } = res {
        assert_eq!(rule_id, "rule-bundle");
        assert_eq!(action, BlockAction::TerminateOnly);
    }

    // 4. Executable name match test
    let candidate_exe = BlockCandidate {
        executable_name: Some("steam.exe".to_string()),
        ..Default::default()
    };
    assert!(evaluator.evaluate(&candidate_exe).is_blocked());

    // 5. SHA-256 hash match test
    let candidate_hash = BlockCandidate {
        sha256_hash: Some("112233445566aabbcc".to_string()),
        ..Default::default()
    };
    assert!(evaluator.evaluate(&candidate_hash).is_blocked());

    // 6. Approved application test
    let candidate_good = BlockCandidate::from_name("Microsoft Visual Studio Code");
    assert_eq!(evaluator.evaluate(&candidate_good), EvaluationResult::Allowed);
}

#[tokio::test]
async fn test_block_evaluator_zero_trust_allowlist_mode() {
    let allowlist_policy = AppBlockPolicy {
        policy_id: 2,
        org_id: 100,
        name: "Enterprise Zero Trust Allowlist".to_string(),
        mode: PolicyEnforcementMode::Allowlist,
        rules: vec![
            BlockRule::new("allow-teams", "Allow Teams", BlockRuleType::ExactName("Microsoft Teams".to_string())),
            BlockRule::new("allow-slack", "Allow Slack", BlockRuleType::ExactName("Slack".to_string())),
        ],
        custom_notification_message: None,
        updated_at: chrono::Utc::now(),
    };

    let evaluator = BlockEvaluator::with_policies(vec![allowlist_policy]);

    // Allowed apps
    assert_eq!(evaluator.evaluate(&BlockCandidate::from_name("Microsoft Teams")), EvaluationResult::Allowed);
    assert_eq!(evaluator.evaluate(&BlockCandidate::from_name("Slack")), EvaluationResult::Allowed);

    // Any other app is denied by default
    let denied = evaluator.evaluate(&BlockCandidate::from_name("RandomGame"));
    assert!(denied.is_blocked());
    if let EvaluationResult::Blocked { rule_id, .. } = denied {
        assert_eq!(rule_id, "allowlist-default-deny");
    }
}

#[tokio::test]
async fn test_block_evaluator_audit_only_mode() {
    let audit_policy = AppBlockPolicy {
        policy_id: 3,
        org_id: 100,
        name: "Audit Policy".to_string(),
        mode: PolicyEnforcementMode::AuditMode,
        rules: vec![
            BlockRule::new("audit-rule", "Audit rule", BlockRuleType::ExactName("RiskwareApp".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
        ],
        custom_notification_message: None,
        updated_at: chrono::Utc::now(),
    };

    let evaluator = BlockEvaluator::with_policies(vec![audit_policy]);

    let res = evaluator.evaluate(&BlockCandidate::from_name("RiskwareApp"));
    assert!(res.is_blocked());
    if let EvaluationResult::Blocked { action, .. } = res {
        assert_eq!(action, BlockAction::AuditOnly);
    }
}

#[tokio::test]
async fn test_app_block_monitor_remediation_and_audit() {
    let work_dir = tempdir().unwrap();
    let audit_log = work_dir.path().join("audit.log");
    let quarantine_dir = work_dir.path().join("quarantine");

    let cp = Arc::new(MockControlPlane::new());
    let policy = AppBlockPolicy {
        policy_id: 10,
        org_id: 1,
        name: "Block Rule Test".to_string(),
        mode: PolicyEnforcementMode::Blocklist,
        rules: vec![
            BlockRule::new("rule-p2p", "Block BitTorrent", BlockRuleType::PatternName("*torrent*".to_string()))
                .with_action(BlockAction::TerminateAndQuarantine),
        ],
        custom_notification_message: None,
        updated_at: chrono::Utc::now(),
    };
    cp.add_block_policy(policy);

    let config = AppBlockMonitorConfig {
        org_id: 1,
        device_id: "endpoint-001".to_string(),
        quarantine_dir: quarantine_dir.clone(),
    };

    let evaluator = Arc::new(std::sync::RwLock::new(BlockEvaluator::new()));
    let remediator = Box::new(MockRemediator::new());
    let notifier = Box::new(MockDesktopNotifier::new());
    let audit_logger = installer_engine::AuditLogger::new(&audit_log).unwrap();

    let monitor = AppBlockMonitor::with_components(
        config,
        cp.clone(),
        evaluator,
        remediator,
        notifier,
        audit_logger,
    );

    monitor.sync_policies().await.unwrap();

    // Create fake dropped installer binary
    let dropped_file = work_dir.path().join("uTorrent_setup.exe");
    std::fs::write(&dropped_file, b"DUMMY_INSTALLER_BINARY_DATA").unwrap();

    let candidate = BlockCandidate {
        app_name: Some("uTorrent Setup".to_string()),
        bundle_id: None,
        executable_name: Some("uTorrent_setup.exe".to_string()),
        executable_path: Some(dropped_file.clone()),
        sha256_hash: None,
        process_id: Some(1234),
        is_installer: true,
    };

    let result = monitor.evaluate_and_remediate(&candidate).await.unwrap();
    assert!(result.is_some());
    let event = result.unwrap();

    assert_eq!(event.rule_id, "rule-p2p");
    assert_eq!(event.app_name, "uTorrent Setup");
    assert_eq!(event.action_taken, BlockAction::TerminateAndQuarantine);
    assert!(event.user_notified);

    // Verify Control Plane telemetry
    let violations = cp.get_block_violations();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].app_name, "uTorrent Setup");
    assert_eq!(violations[0].process_id, Some(1234));

    // Verify Audit trail
    let audit_content = std::fs::read_to_string(&audit_log).unwrap();
    assert!(audit_content.contains("app.blocked"));
    assert!(audit_content.contains("uTorrent Setup"));
}

#[tokio::test]
async fn test_installer_engine_blocks_unauthorized_task_pipeline() {
    let work_dir = tempdir().unwrap();
    let cache_dir = work_dir.path().join("cache");
    let audit_log = work_dir.path().join("audit.log");
    let quarantine_dir = work_dir.path().join("quarantine");

    let mut pkg_file = NamedTempFile::new().unwrap();
    let payload = b"unauthorized game installer package";
    pkg_file.write_all(payload).unwrap();
    pkg_file.flush().unwrap();
    let checksum = ChecksumVerifier::compute_bytes_sha256(payload);

    let cp = Arc::new(MockControlPlane::new());
    let task = Task {
        task_id: "blocked-task-001".to_string(),
        org_id: 1,
        device_id: "mac-device-01".to_string(),
        target_platform: Platform::MacOS,
        task_type: TaskType::InstallApp,
        task_desc: "install_game".to_string(),
        app_name: "Steam Client".to_string(),
        app_version: Some("1.0".to_string()),
        download_url: format!("file://{}", pkg_file.path().display()),
        expected_checksum: checksum,
        installer_args: vec![],
        task_status: TaskStatus::New,
        error_message: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    cp.insert_task(task.clone());

    let policy = AppBlockPolicy {
        policy_id: 50,
        org_id: 1,
        name: "Block Gaming Apps".to_string(),
        mode: PolicyEnforcementMode::Blocklist,
        rules: vec![
            BlockRule::new("rule-gaming", "Block Steam", BlockRuleType::PatternName("*steam*".to_string())),
        ],
        custom_notification_message: None,
        updated_at: chrono::Utc::now(),
    };
    cp.add_block_policy(policy.clone());

    let monitor_config = AppBlockMonitorConfig {
        org_id: 1,
        device_id: "mac-device-01".to_string(),
        quarantine_dir,
    };

    let evaluator = Arc::new(std::sync::RwLock::new(BlockEvaluator::new()));
    let remediator = Box::new(MockRemediator::new());
    let notifier = Box::new(MockDesktopNotifier::new());
    let audit_logger = installer_engine::AuditLogger::new(&audit_log).unwrap();

    let monitor = Arc::new(AppBlockMonitor::with_components(
        monitor_config,
        cp.clone(),
        evaluator,
        remediator,
        notifier,
        audit_logger,
    ));
    monitor.add_policy(policy);

    let engine_config = EngineConfig {
        org_id: 1,
        device_id: "mac-device-01".to_string(),
        platform: Platform::MacOS,
        cache_dir,
        audit_log_path: audit_log.clone(),
    };

    let installer = Box::new(MockInstaller::successful());
    let engine = InstallerEngine::new(engine_config, cp.clone(), installer)
        .unwrap()
        .with_block_monitor(monitor);

    // Process task should fail with policy block
    let result = engine.process_task(&task).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Installation blocked by security policy"));

    // Verify task failed in Control Plane
    let updated_task = cp.get_task("blocked-task-001").unwrap();
    assert_eq!(updated_task.task_status, TaskStatus::Failed);
}
