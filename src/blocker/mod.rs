pub mod evaluator;
pub mod models;
pub mod monitor;
pub mod notifier;
pub mod platform;

pub use evaluator::{wildcard_match, BlockEvaluator, EvaluationResult};
pub use models::{
    AppBlockPolicy, BlockAction, BlockCandidate, BlockRule, BlockRuleType, BlockViolationEvent,
    PolicyEnforcementMode,
};
pub use monitor::{AppBlockMonitor, AppBlockMonitorConfig};
pub use notifier::{DesktopNotifier, MockDesktopNotifier, PlatformDesktopNotifier};
pub use platform::{
    create_platform_remediator, LinuxRemediator, MacOSRemediator, MockRemediator,
    PlatformRemediator, WindowsRemediator,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogger;
    use crate::control_plane::MockControlPlane;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_block_monitor_end_to_end_interception() {
        let work_dir = tempdir().unwrap();
        let audit_log = work_dir.path().join("audit.log");
        let quarantine_dir = work_dir.path().join("quarantine");

        let control_plane = Arc::new(MockControlPlane::new());
        let policy = AppBlockPolicy {
            policy_id: 101,
            org_id: 1,
            name: "Prohibited P2P Policy".to_string(),
            mode: PolicyEnforcementMode::Blocklist,
            rules: vec![
                BlockRule::new("rule-p2p", "Block BitTorrent", BlockRuleType::PatternName("*bittorrent*".to_string()))
                    .with_action(BlockAction::TerminateAndQuarantine),
            ],
            custom_notification_message: None,
            updated_at: chrono::Utc::now(),
        };

        control_plane.add_block_policy(policy);

        let config = AppBlockMonitorConfig {
            org_id: 1,
            device_id: "test-device".to_string(),
            quarantine_dir: quarantine_dir.clone(),
        };

        let evaluator = std::sync::Arc::new(std::sync::RwLock::new(BlockEvaluator::new()));
        let mock_remediator = Box::new(MockRemediator::new());
        let mock_notifier = Box::new(MockDesktopNotifier::new());
        let audit_logger = AuditLogger::new(&audit_log).unwrap();

        let monitor = AppBlockMonitor::with_components(
            config,
            control_plane.clone(),
            evaluator,
            mock_remediator,
            mock_notifier,
            audit_logger,
        );

        // Sync policies
        let synced = monitor.sync_policies().await.unwrap();
        assert_eq!(synced, 1);

        // Create a dummy fake binary to simulate staged installer
        let fake_pkg_path = work_dir.path().join("BitTorrent-Installer.pkg");
        std::fs::write(&fake_pkg_path, b"FAKE_BITTORRENT_INSTALLER_BINARY").unwrap();

        let candidate = BlockCandidate {
            app_name: Some("BitTorrent Pro".to_string()),
            bundle_id: Some("com.bittorrent.client".to_string()),
            executable_name: Some("BitTorrent-Installer.pkg".to_string()),
            executable_path: Some(fake_pkg_path.clone()),
            sha256_hash: None,
            process_id: Some(9999),
            is_installer: true,
        };

        let result = monitor.evaluate_and_remediate(&candidate).await.unwrap();
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.rule_id, "rule-p2p");
        assert_eq!(event.app_name, "BitTorrent Pro");

        // Verify violation reported to Control Plane
        let violations = control_plane.get_block_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].app_name, "BitTorrent Pro");
        assert_eq!(violations[0].rule_id, "rule-p2p");

        // Verify audit log
        let audit_content = std::fs::read_to_string(&audit_log).unwrap();
        assert!(audit_content.contains("app.blocked"));
        assert!(audit_content.contains("BitTorrent Pro"));
    }
}
