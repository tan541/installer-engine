use std::sync::Arc;
use crate::blocker::models::{
    AppBlockPolicy, BlockAction, BlockCandidate, BlockRule, BlockRuleType, PolicyEnforcementMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationResult {
    Allowed,
    Blocked {
        policy_id: u64,
        rule_id: String,
        rule_description: String,
        action: BlockAction,
        match_reason: String,
    },
}

impl EvaluationResult {
    pub fn is_blocked(&self) -> bool {
        matches!(self, EvaluationResult::Blocked { .. })
    }
}

/// Evaluator that matches candidates against active security policies
#[derive(Debug, Clone, Default)]
pub struct BlockEvaluator {
    policies: Vec<Arc<AppBlockPolicy>>,
}

impl BlockEvaluator {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn with_policies(policies: Vec<AppBlockPolicy>) -> Self {
        Self {
            policies: policies.into_iter().map(Arc::new).collect(),
        }
    }

    pub fn set_policies(&mut self, policies: Vec<AppBlockPolicy>) {
        self.policies = policies.into_iter().map(Arc::new).collect();
    }

    pub fn add_policy(&mut self, policy: AppBlockPolicy) {
        self.policies.push(Arc::new(policy));
    }

    pub fn policies(&self) -> &[Arc<AppBlockPolicy>] {
        &self.policies
    }

    /// Evaluates a candidate against all configured policies
    pub fn evaluate(&self, candidate: &BlockCandidate) -> EvaluationResult {
        if self.policies.is_empty() {
            return EvaluationResult::Allowed;
        }

        for policy in &self.policies {
            match policy.mode {
                PolicyEnforcementMode::Blocklist => {
                    for rule in &policy.rules {
                        if !rule.enabled {
                            continue;
                        }
                        if let Some(reason) = self.rule_matches(rule, candidate) {
                            return EvaluationResult::Blocked {
                                policy_id: policy.policy_id,
                                rule_id: rule.rule_id.clone(),
                                rule_description: rule.description.clone(),
                                action: rule.action,
                                match_reason: reason,
                            };
                        }
                    }
                }
                PolicyEnforcementMode::Allowlist => {
                    let mut matched = false;
                    for rule in &policy.rules {
                        if !rule.enabled {
                            continue;
                        }
                        if self.rule_matches(rule, candidate).is_some() {
                            matched = true;
                            break;
                        }
                    }

                    if !matched {
                        return EvaluationResult::Blocked {
                            policy_id: policy.policy_id,
                            rule_id: "allowlist-default-deny".to_string(),
                            rule_description: format!("Application not listed in allowlist policy '{}'", policy.name),
                            action: BlockAction::TerminateAndQuarantine,
                            match_reason: "Zero-Trust Allowlist Policy Violation: Unapproved application".to_string(),
                        };
                    }
                }
                PolicyEnforcementMode::AuditMode => {
                    for rule in &policy.rules {
                        if !rule.enabled {
                            continue;
                        }
                        if let Some(reason) = self.rule_matches(rule, candidate) {
                            return EvaluationResult::Blocked {
                                policy_id: policy.policy_id,
                                rule_id: rule.rule_id.clone(),
                                rule_description: rule.description.clone(),
                                action: BlockAction::AuditOnly,
                                match_reason: reason,
                            };
                        }
                    }
                }
            }
        }

        EvaluationResult::Allowed
    }

    /// Checks if a single rule matches candidate attributes
    fn rule_matches(&self, rule: &BlockRule, candidate: &BlockCandidate) -> Option<String> {
        match &rule.match_type {
            BlockRuleType::ExactName(target) => {
                if let Some(ref name) = candidate.app_name {
                    if name.trim().eq_ignore_ascii_case(target.trim()) {
                        return Some(format!("Exact name matched '{target}'"));
                    }
                }
                None
            }
            BlockRuleType::PatternName(pattern) => {
                if let Some(ref name) = candidate.app_name {
                    if wildcard_match(pattern, name) {
                        return Some(format!("App name '{name}' matched wildcard pattern '{pattern}'"));
                    }
                }
                if let Some(ref exe_name) = candidate.executable_name {
                    if wildcard_match(pattern, exe_name) {
                        return Some(format!("Executable name '{exe_name}' matched pattern '{pattern}'"));
                    }
                }
                None
            }
            BlockRuleType::BundleIdentifier(target_bundle) => {
                if let Some(ref bundle_id) = candidate.bundle_id {
                    if bundle_id.eq_ignore_ascii_case(target_bundle) || wildcard_match(target_bundle, bundle_id) {
                        return Some(format!("Bundle identifier '{bundle_id}' matched '{target_bundle}'"));
                    }
                }
                None
            }
            BlockRuleType::ChecksumSha256(target_hash) => {
                if let Some(ref hash) = candidate.sha256_hash {
                    if hash.trim().eq_ignore_ascii_case(target_hash.trim()) {
                        return Some(format!("SHA-256 hash matched '{target_hash}'"));
                    }
                }
                None
            }
            BlockRuleType::ExecutableName(target_exe) => {
                if let Some(ref exe) = candidate.executable_name {
                    if exe.eq_ignore_ascii_case(target_exe) || wildcard_match(target_exe, exe) {
                        return Some(format!("Executable name '{exe}' matched '{target_exe}'"));
                    }
                }
                if let Some(ref path) = candidate.executable_path {
                    if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                        if file_name.eq_ignore_ascii_case(target_exe) || wildcard_match(target_exe, file_name) {
                            return Some(format!("Binary file '{file_name}' matched '{target_exe}'"));
                        }
                    }
                }
                None
            }
            BlockRuleType::InstallPathPrefix(prefix) => {
                if let Some(ref path) = candidate.executable_path {
                    if path.starts_with(prefix) {
                        return Some(format!("Path '{}' starts with restricted prefix '{}'", path.display(), prefix.display()));
                    }
                }
                None
            }
        }
    }
}

/// Helper function to match simple wildcards `*` and `?` case-insensitively
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p_lower = pattern.to_ascii_lowercase();
    let t_lower = text.to_ascii_lowercase();
    wildcard_match_bytes(p_lower.as_bytes(), t_lower.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == b'?' || pattern[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < pattern.len() && pattern[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocker::models::BlockAction;

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("*torrent*", "uTorrent Web"));
        assert!(wildcard_match("*torrent*", "BitTorrent"));
        assert!(wildcard_match("com.spotify.*", "com.spotify.client"));
        assert!(wildcard_match("*.pkg", "Installer.pkg"));
        assert!(!wildcard_match("*torrent*", "Microsoft Teams"));
        assert!(wildcard_match("steam?.exe", "steam1.exe"));
    }

    #[test]
    fn test_blocklist_evaluation() {
        let policy = AppBlockPolicy {
            policy_id: 1,
            org_id: 10,
            name: "Default Security Policy".to_string(),
            mode: PolicyEnforcementMode::Blocklist,
            rules: vec![
                BlockRule::new("rule-1", "Block torrent apps", BlockRuleType::PatternName("*torrent*".to_string()))
                    .with_action(BlockAction::TerminateAndQuarantine),
                BlockRule::new("rule-2", "Block specific hash", BlockRuleType::ChecksumSha256("badhash123".to_string())),
            ],
            custom_notification_message: None,
            updated_at: chrono::Utc::now(),
        };

        let evaluator = BlockEvaluator::with_policies(vec![policy]);

        // Allowed app
        let candidate_ok = BlockCandidate::from_name("Microsoft Teams");
        assert_eq!(evaluator.evaluate(&candidate_ok), EvaluationResult::Allowed);

        // Blocked by pattern
        let candidate_bad = BlockCandidate::from_name("BitTorrent Pro");
        let result = evaluator.evaluate(&candidate_bad);
        assert!(result.is_blocked());
        if let EvaluationResult::Blocked { rule_id, action, .. } = result {
            assert_eq!(rule_id, "rule-1");
            assert_eq!(action, BlockAction::TerminateAndQuarantine);
        }

        // Blocked by hash
        let candidate_hash = BlockCandidate {
            sha256_hash: Some("badhash123".to_string()),
            ..Default::default()
        };
        assert!(evaluator.evaluate(&candidate_hash).is_blocked());
    }

    #[test]
    fn test_allowlist_evaluation() {
        let policy = AppBlockPolicy {
            policy_id: 2,
            org_id: 10,
            name: "Zero Trust Allowlist".to_string(),
            mode: PolicyEnforcementMode::Allowlist,
            rules: vec![
                BlockRule::new("rule-allow-teams", "Allow Teams", BlockRuleType::ExactName("Microsoft Teams".to_string())),
                BlockRule::new("rule-allow-slack", "Allow Slack", BlockRuleType::ExactName("Slack".to_string())),
            ],
            custom_notification_message: None,
            updated_at: chrono::Utc::now(),
        };

        let evaluator = BlockEvaluator::with_policies(vec![policy]);

        // Approved app
        assert_eq!(evaluator.evaluate(&BlockCandidate::from_name("Microsoft Teams")), EvaluationResult::Allowed);
        assert_eq!(evaluator.evaluate(&BlockCandidate::from_name("Slack")), EvaluationResult::Allowed);

        // Unapproved app
        let blocked = evaluator.evaluate(&BlockCandidate::from_name("UnapprovedApp"));
        assert!(blocked.is_blocked());
    }
}
