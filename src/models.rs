use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    #[serde(other)]
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Platform::MacOS
        }
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Platform::Unknown
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::MacOS => "macos",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    New,
    Processing,
    Done,
    Failed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::New => "new",
            TaskStatus::Processing => "processing",
            TaskStatus::Done => "done",
            TaskStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    #[serde(rename = "install.app")]
    InstallApp,
    #[serde(rename = "uninstall.app")]
    UninstallApp,
    #[serde(rename = "distribute.app")]
    DistributeApp,
    #[serde(rename = "collect.inventory")]
    CollectInventory,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub org_id: u64,
    pub device_id: String,
    pub target_platform: Platform,
    pub task_type: TaskType,
    pub task_desc: String,
    pub app_name: String,
    #[serde(default)]
    pub app_version: Option<String>,
    pub download_url: String,
    pub expected_checksum: String,
    #[serde(default)]
    pub installer_args: Vec<String>,
    pub task_status: TaskStatus,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub group_policy_id: u64,
    pub org_id: u64,
    pub group_type: String, // e.g. "distribute.app"
    pub app_name: String,
    #[serde(default)]
    pub app_version: Option<String>,
    pub download_url: String,
    pub checksum_sha256: String,
    #[serde(default)]
    pub target_platforms: Vec<Platform>,
    #[serde(default)]
    pub installer_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReport {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub message: String,
    #[serde(default)]
    pub installed_path: Option<String>,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_serialization() {
        let mac = Platform::MacOS;
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, "\"macos\"");

        let deserialized: Platform = serde_json::from_str("\"linux\"").unwrap();
        assert_eq!(deserialized, Platform::Linux);
    }

    #[test]
    fn test_task_status_serialization() {
        let status = TaskStatus::Processing;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"processing\"");

        let parsed: TaskStatus = serde_json::from_str("\"done\"").unwrap();
        assert_eq!(parsed, TaskStatus::Done);
    }

    #[test]
    fn test_task_json_roundtrip() {
        let task = Task {
            task_id: "task-123".to_string(),
            org_id: 1,
            device_id: "device-456".to_string(),
            target_platform: Platform::MacOS,
            task_type: TaskType::InstallApp,
            task_desc: "ms_teams".to_string(),
            app_name: "Microsoft Teams".to_string(),
            app_version: Some("1.5.0".to_string()),
            download_url: "https://example.com/teams.pkg".to_string(),
            expected_checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            installer_args: vec!["--target".to_string(), "/".to_string()],
            task_status: TaskStatus::New,
            error_message: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&task).unwrap();
        let decoded: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.task_id, task.task_id);
        assert_eq!(decoded.target_platform, Platform::MacOS);
        assert_eq!(decoded.task_status, TaskStatus::New);
    }
}
