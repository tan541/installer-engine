use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Rule matching condition for application blocking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum BlockRuleType {
    /// Exact match on application name (case-insensitive)
    #[serde(rename = "exact_name")]
    ExactName(String),
    /// Wildcard / pattern match on application name (e.g. "*torrent*", "*p2p*")
    #[serde(rename = "pattern_name")]
    PatternName(String),
    /// macOS / iOS bundle identifier (e.g. "com.bittorrent.client")
    #[serde(rename = "bundle_id")]
    BundleIdentifier(String),
    /// Exact SHA-256 checksum of the installer package or binary
    #[serde(rename = "sha256")]
    ChecksumSha256(String),
    /// Executable binary filename (e.g. "utorrent.exe", "bittorrent-daemon")
    #[serde(rename = "executable_name")]
    ExecutableName(String),
    /// Install path prefix / directory restriction
    #[serde(rename = "path_prefix")]
    InstallPathPrefix(PathBuf),
}

/// Action to execute when a rule matches an unapproved application or installer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockAction {
    /// Terminate process, quarantine/remove installer & staging files, and alert user
    #[default]
    TerminateAndQuarantine,
    /// Terminate installer process and notify user
    TerminateOnly,
    /// Allow the installation but record a security violation event in the audit log & Control Plane
    AuditOnly,
}

impl BlockAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockAction::TerminateAndQuarantine => "terminate_and_quarantine",
            BlockAction::TerminateOnly => "terminate_only",
            BlockAction::AuditOnly => "audit_only",
        }
    }
}

/// A specific rule within a block policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRule {
    pub rule_id: String,
    pub description: String,
    pub match_type: BlockRuleType,
    #[serde(default)]
    pub action: BlockAction,
    #[serde(default)]
    pub enabled: bool,
}

impl BlockRule {
    pub fn new(rule_id: impl Into<String>, desc: impl Into<String>, match_type: BlockRuleType) -> Self {
        Self {
            rule_id: rule_id.into(),
            description: desc.into(),
            match_type,
            action: BlockAction::TerminateAndQuarantine,
            enabled: true,
        }
    }

    pub fn with_action(mut self, action: BlockAction) -> Self {
        self.action = action;
        self
    }
}

/// Mode of enforcement for the application control engine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementMode {
    /// Default Allow: Any application can be installed except those matching BlockRules
    #[default]
    Blocklist,
    /// Default Deny (Zero-Trust): Only explicitly allowed applications can be installed
    Allowlist,
    /// Audit Mode: Monitor and report all violation events without actively blocking
    AuditMode,
}

/// Group or Organization-level Application Control Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBlockPolicy {
    pub policy_id: u64,
    pub org_id: u64,
    pub name: String,
    #[serde(default)]
    pub mode: PolicyEnforcementMode,
    #[serde(default)]
    pub rules: Vec<BlockRule>,
    #[serde(default)]
    pub custom_notification_message: Option<String>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Candidate application or process being evaluated for blocking
#[derive(Debug, Clone, Default)]
pub struct BlockCandidate {
    pub app_name: Option<String>,
    pub bundle_id: Option<String>,
    pub executable_name: Option<String>,
    pub executable_path: Option<PathBuf>,
    pub sha256_hash: Option<String>,
    pub process_id: Option<u32>,
    pub is_installer: bool,
}

impl BlockCandidate {
    pub fn from_name(name: impl Into<String>) -> Self {
        Self {
            app_name: Some(name.into()),
            ..Default::default()
        }
    }

    pub fn from_process(pid: u32, name: impl Into<String>, path: Option<PathBuf>) -> Self {
        let n = name.into();
        Self {
            process_id: Some(pid),
            app_name: Some(n.clone()),
            executable_name: Some(n),
            executable_path: path,
            ..Default::default()
        }
    }
}

/// Event generated when an unapproved installation or execution is intercepted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockViolationEvent {
    pub event_id: String,
    pub org_id: u64,
    pub device_id: String,
    pub policy_id: u64,
    pub rule_id: String,
    pub rule_description: String,
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub executable_path: Option<String>,
    pub sha256_hash: Option<String>,
    pub process_id: Option<u32>,
    pub action_taken: BlockAction,
    pub user_notified: bool,
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
}
