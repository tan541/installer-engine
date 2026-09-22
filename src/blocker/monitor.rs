use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::audit::AuditLogger;
use crate::blocker::evaluator::{BlockEvaluator, EvaluationResult};
use crate::blocker::models::{
    AppBlockPolicy, BlockAction, BlockCandidate, BlockViolationEvent,
};
use crate::blocker::notifier::{DesktopNotifier, PlatformDesktopNotifier};
use crate::blocker::platform::{create_platform_remediator, PlatformRemediator};
use crate::control_plane::ControlPlaneClient;
use crate::error::Result;

pub struct AppBlockMonitorConfig {
    pub org_id: u64,
    pub device_id: String,
    pub quarantine_dir: PathBuf,
}

pub struct AppBlockMonitor {
    config: AppBlockMonitorConfig,
    evaluator: Arc<RwLock<BlockEvaluator>>,
    remediator: Box<dyn PlatformRemediator>,
    notifier: Box<dyn DesktopNotifier>,
    audit_logger: AuditLogger,
    control_plane: Arc<dyn ControlPlaneClient>,
}

impl AppBlockMonitor {
    pub fn new(
        config: AppBlockMonitorConfig,
        control_plane: Arc<dyn ControlPlaneClient>,
        audit_log_path: &Path,
    ) -> Result<Self> {
        let evaluator = Arc::new(RwLock::new(BlockEvaluator::new()));
        let remediator = create_platform_remediator();
        let notifier = Box::new(PlatformDesktopNotifier::new());
        let audit_logger = AuditLogger::new(audit_log_path)?;

        std::fs::create_dir_all(&config.quarantine_dir)?;

        Ok(Self {
            config,
            evaluator,
            remediator,
            notifier,
            audit_logger,
            control_plane,
        })
    }

    pub fn with_components(
        config: AppBlockMonitorConfig,
        control_plane: Arc<dyn ControlPlaneClient>,
        evaluator: Arc<RwLock<BlockEvaluator>>,
        remediator: Box<dyn PlatformRemediator>,
        notifier: Box<dyn DesktopNotifier>,
        audit_logger: AuditLogger,
    ) -> Self {
        Self {
            config,
            evaluator,
            remediator,
            notifier,
            audit_logger,
            control_plane,
        }
    }

    pub fn evaluator(&self) -> Arc<RwLock<BlockEvaluator>> {
        self.evaluator.clone()
    }

    /// Fetches updated block policies from the Control Plane and applies them
    pub async fn sync_policies(&self) -> Result<usize> {
        let policies = self
            .control_plane
            .fetch_block_policies(self.config.org_id, &self.config.device_id)
            .await?;

        let count = policies.len();
        let mut lock = self.evaluator.write().unwrap();
        lock.set_policies(policies);

        tracing::info!(
            org_id = self.config.org_id,
            device_id = %self.config.device_id,
            policies_count = count,
            "Synchronized application block policies from Control Plane"
        );

        Ok(count)
    }

    /// Manually adds a local block policy to the evaluator
    pub fn add_policy(&self, policy: AppBlockPolicy) {
        let mut lock = self.evaluator.write().unwrap();
        lock.add_policy(policy);
    }

    /// Evaluates a candidate and executes blocking/remediation if prohibited
    pub async fn evaluate_and_remediate(
        &self,
        candidate: &BlockCandidate,
    ) -> Result<Option<BlockViolationEvent>> {
        let eval_result = {
            let lock = self.evaluator.read().unwrap();
            lock.evaluate(candidate)
        };

        match eval_result {
            EvaluationResult::Allowed => Ok(None),
            EvaluationResult::Blocked {
                policy_id,
                rule_id,
                rule_description,
                action,
                match_reason,
            } => {
                let app_name = candidate
                    .app_name
                    .clone()
                    .or_else(|| candidate.executable_name.clone())
                    .unwrap_or_else(|| "Unknown Application".to_string());

                tracing::warn!(
                    app = %app_name,
                    rule = %rule_id,
                    action = %action.as_str(),
                    reason = %match_reason,
                    "APPLICATION INSTALLATION BLOCKED"
                );

                // 1. Process termination remediation
                if action != BlockAction::AuditOnly {
                    if let Some(pid) = candidate.process_id {
                        let _ = self.remediator.terminate_process(pid);
                    } else if let Some(ref name) = candidate.executable_name {
                        let _ = self.remediator.terminate_process_by_name(name);
                    }
                }

                // 2. Quarantine remediation
                let mut final_path = candidate.executable_path.clone();
                if action == BlockAction::TerminateAndQuarantine {
                    if let Some(ref path) = candidate.executable_path {
                        if path.exists() {
                            if let Ok(quarantined) = self
                                .remediator
                                .quarantine_path(path, &self.config.quarantine_dir)
                            {
                                final_path = Some(quarantined);
                            }
                        }
                    }
                }

                // 3. User Desktop Notification
                let user_notified = self
                    .notifier
                    .notify(&app_name, None)
                    .unwrap_or(false);

                // 4. Create Violation Event
                let event = BlockViolationEvent {
                    event_id: format!("event-{}", Uuid::new_v4()),
                    org_id: self.config.org_id,
                    device_id: self.config.device_id.clone(),
                    policy_id,
                    rule_id: rule_id.clone(),
                    rule_description,
                    app_name: app_name.clone(),
                    bundle_id: candidate.bundle_id.clone(),
                    executable_path: final_path.map(|p| p.to_string_lossy().to_string()),
                    sha256_hash: candidate.sha256_hash.clone(),
                    process_id: candidate.process_id,
                    action_taken: action,
                    user_notified,
                    timestamp: chrono::Utc::now(),
                };

                // 5. Audit Logging
                let _ = self.audit_logger.record_event(
                    "app.blocked",
                    &rule_id,
                    self.config.org_id,
                    &self.config.device_id,
                    &app_name,
                    candidate.sha256_hash.clone(),
                    action.as_str(),
                    Some(match_reason),
                    None,
                );

                // 6. Report Telemetry to Control Plane
                let _ = self.control_plane.report_block_violation(&event).await;

                Ok(Some(event))
            }
        }
    }

    /// Performs one complete inspection and remediation scan across running processes and staging areas
    pub async fn scan_and_remediate_cycle(&self) -> Result<Vec<BlockViolationEvent>> {
        let mut violations = Vec::new();

        // 1. Scan running processes
        if let Ok(process_candidates) = self.remediator.scan_running_processes() {
            for candidate in &process_candidates {
                if let Some(event) = self.evaluate_and_remediate(candidate).await? {
                    violations.push(event);
                }
            }
        }

        // 2. Scan staging areas
        if let Ok(staging_candidates) = self.remediator.scan_staging_areas() {
            for candidate in &staging_candidates {
                if let Some(event) = self.evaluate_and_remediate(candidate).await? {
                    violations.push(event);
                }
            }
        }

        Ok(violations)
    }
}
