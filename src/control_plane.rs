use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EngineError, Result};
use crate::models::{GroupPolicy, Platform, Task, TaskStatus, TaskType};

pub trait ControlPlaneClient: Send + Sync {
    fn generate_tasks_from_policy<'a>(
        &'a self,
        policy: &'a GroupPolicy,
        target_devices: &'a [(&'a str, Platform)],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>>;

    fn fetch_tasks<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
        platform: Platform,
        status: Option<TaskStatus>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>>;

    fn update_task_status<'a>(
        &'a self,
        task_id: &'a str,
        status: TaskStatus,
        error_message: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// Thread-safe in-memory mock Control Plane for testing and agent simulation
#[derive(Clone, Default)]
pub struct MockControlPlane {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl MockControlPlane {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert_task(&self, task: Task) {
        let mut lock = self.tasks.write().unwrap();
        lock.insert(task.task_id.clone(), task);
    }

    pub fn get_task(&self, task_id: &str) -> Option<Task> {
        let lock = self.tasks.read().unwrap();
        lock.get(task_id).cloned()
    }
}

impl ControlPlaneClient for MockControlPlane {
    fn generate_tasks_from_policy<'a>(
        &'a self,
        policy: &'a GroupPolicy,
        target_devices: &'a [(&'a str, Platform)],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>> {
        Box::pin(async move {
            let mut generated = Vec::new();
            let mut lock = self
                .tasks
                .write()
                .map_err(|_| EngineError::ControlPlane("Lock poisoned".to_string()))?;

            for (device_id, platform) in target_devices {
                if !policy.target_platforms.is_empty() && !policy.target_platforms.contains(platform) {
                    continue;
                }

                let task_type = match policy.group_type.as_str() {
                    "distribute.app" | "install.app" => TaskType::InstallApp,
                    "uninstall.app" => TaskType::UninstallApp,
                    other => TaskType::Custom(other.to_string()),
                };

                let task_id = format!("task-{}", Uuid::new_v4());
                let now = Utc::now();

                let task = Task {
                    task_id: task_id.clone(),
                    org_id: policy.org_id,
                    device_id: device_id.to_string(),
                    target_platform: *platform,
                    task_type,
                    task_desc: policy.app_name.clone(),
                    app_name: policy.app_name.clone(),
                    app_version: policy.app_version.clone(),
                    download_url: policy.download_url.clone(),
                    expected_checksum: policy.checksum_sha256.clone(),
                    installer_args: policy.installer_args.clone(),
                    task_status: TaskStatus::New,
                    error_message: None,
                    created_at: now,
                    updated_at: now,
                };

                lock.insert(task_id, task.clone());
                generated.push(task);
            }

            tracing::info!(
                policy_id = policy.group_policy_id,
                tasks_count = generated.len(),
                "Generated tasks from group policy"
            );

            Ok(generated)
        })
    }

    fn fetch_tasks<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
        platform: Platform,
        status: Option<TaskStatus>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>> {
        Box::pin(async move {
            let lock = self
                .tasks
                .read()
                .map_err(|_| EngineError::ControlPlane("Lock poisoned".to_string()))?;

            let target_status = status.unwrap_or(TaskStatus::New);

            let matching: Vec<Task> = lock
                .values()
                .filter(|t| {
                    t.org_id == org_id
                        && t.device_id == device_id
                        && (t.target_platform == platform || t.target_platform == Platform::Unknown)
                        && t.task_status == target_status
                })
                .cloned()
                .collect();

            tracing::info!(
                org_id,
                device_id,
                platform = %platform,
                count = matching.len(),
                "Fetched tasks from control plane"
            );

            Ok(matching)
        })
    }

    fn update_task_status<'a>(
        &'a self,
        task_id: &'a str,
        status: TaskStatus,
        error_message: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut lock = self
                .tasks
                .write()
                .map_err(|_| EngineError::ControlPlane("Lock poisoned".to_string()))?;

            if let Some(task) = lock.get_mut(task_id) {
                task.task_status = status;
                task.error_message = error_message.clone();
                task.updated_at = Utc::now();

                tracing::info!(
                    task_id,
                    status = %status,
                    error = ?error_message,
                    "Updated task status in control plane"
                );
                Ok(())
            } else {
                Err(EngineError::ControlPlane(format!("Task {task_id} not found")))
            }
        })
    }
}

/// HTTP REST client for communicating with a live Control Plane server
pub struct HttpControlPlaneClient {
    base_url: String,
    client: Client,
}

#[derive(Serialize)]
struct StatusUpdateRequest<'a> {
    task_id: &'a str,
    status: TaskStatus,
    error_message: Option<String>,
}

#[derive(Deserialize)]
struct FetchTasksResponse {
    tasks: Vec<Task>,
}

impl HttpControlPlaneClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }
}

impl ControlPlaneClient for HttpControlPlaneClient {
    fn generate_tasks_from_policy<'a>(
        &'a self,
        policy: &'a GroupPolicy,
        _target_devices: &'a [(&'a str, Platform)],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!("{}/api/v1/policies/{}/generate-tasks", self.base_url, policy.group_policy_id);
            let response = self
                .client
                .post(&url)
                .json(policy)
                .send()
                .await
                .map_err(EngineError::Reqwest)?;

            let tasks = response.json::<Vec<Task>>().await.map_err(EngineError::Reqwest)?;
            Ok(tasks)
        })
    }

    fn fetch_tasks<'a>(
        &'a self,
        org_id: u64,
        device_id: &'a str,
        platform: Platform,
        status: Option<TaskStatus>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send + 'a>> {
        Box::pin(async move {
            let status_str = status.unwrap_or(TaskStatus::New).to_string();
            let url = format!(
                "{}/api/v1/tasks?org_id={}&device_id={}&platform={}&task_status={}",
                self.base_url, org_id, device_id, platform, status_str
            );

            let response = self.client.get(&url).send().await.map_err(EngineError::Reqwest)?;
            let parsed = response
                .json::<FetchTasksResponse>()
                .await
                .map_err(EngineError::Reqwest)?;
            Ok(parsed.tasks)
        })
    }

    fn update_task_status<'a>(
        &'a self,
        task_id: &'a str,
        status: TaskStatus,
        error_message: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!("{}/api/v1/tasks/{}/status", self.base_url, task_id);
            let payload = StatusUpdateRequest {
                task_id,
                status,
                error_message,
            };

            let response = self
                .client
                .put(&url)
                .json(&payload)
                .send()
                .await
                .map_err(EngineError::Reqwest)?;

            if !response.status().is_success() {
                return Err(EngineError::ControlPlane(format!(
                    "Failed to update task status: HTTP {}",
                    response.status()
                )));
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_control_plane_lifecycle() {
        let cp = MockControlPlane::new();
        let policy = GroupPolicy {
            group_policy_id: 1,
            org_id: 100,
            group_type: "distribute.app".to_string(),
            app_name: "teams".to_string(),
            app_version: Some("1.0.0".to_string()),
            download_url: "https://example.com/teams.pkg".to_string(),
            checksum_sha256: "abc123hash".to_string(),
            target_platforms: vec![Platform::MacOS, Platform::Windows],
            installer_args: vec![],
        };

        let devices = [("dev-mac-01", Platform::MacOS), ("dev-linux-01", Platform::Linux)];
        let tasks = cp.generate_tasks_from_policy(&policy, &devices).await.unwrap();

        // Only MacOS device should match policy target_platforms
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].device_id, "dev-mac-01");
        assert_eq!(tasks[0].task_status, TaskStatus::New);

        // Fetch tasks
        let fetched = cp.fetch_tasks(100, "dev-mac-01", Platform::MacOS, None).await.unwrap();
        assert_eq!(fetched.len(), 1);

        // Update status
        cp.update_task_status(&tasks[0].task_id, TaskStatus::Processing, None)
            .await
            .unwrap();

        let updated = cp.get_task(&tasks[0].task_id).unwrap();
        assert_eq!(updated.task_status, TaskStatus::Processing);
    }
}
