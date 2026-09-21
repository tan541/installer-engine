use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub task_id: String,
    pub org_id: u64,
    pub device_id: String,
    pub app_name: String,
    #[serde(default)]
    pub checksum: Option<String>,
    pub status: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

#[derive(Clone)]
pub struct AuditLogger {
    file_path: PathBuf,
    writer_lock: Arc<Mutex<()>>,
}

impl AuditLogger {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();

        if let Some(parent) = file_path.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_all(parent)
                    .map_err(|e| EngineError::Audit(format!("Failed to create audit log directory: {e}")))?;
            }
        }

        Ok(Self {
            file_path,
            writer_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn log(&self, record: &AuditRecord) -> Result<()> {
        let _guard = self
            .writer_lock
            .lock()
            .map_err(|_| EngineError::Audit("Audit logger lock poisoned".to_string()))?;

        let serialized = serde_json::to_string(record)
            .map_err(|e| EngineError::Audit(format!("Failed to serialize audit record: {e}")))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| EngineError::Audit(format!("Failed to open audit log file: {e}")))?;

        writeln!(file, "{}", serialized)
            .map_err(|e| EngineError::Audit(format!("Failed to write to audit log file: {e}")))?;

        file.flush()
            .map_err(|e| EngineError::Audit(format!("Failed to flush audit log file: {e}")))?;

        tracing::info!(
            task_id = %record.task_id,
            action = %record.action,
            status = %record.status,
            "Recorded audit event to {}",
            self.file_path.display()
        );

        Ok(())
    }

    pub fn record_event(
        &self,
        action: impl Into<String>,
        task_id: impl Into<String>,
        org_id: u64,
        device_id: impl Into<String>,
        app_name: impl Into<String>,
        checksum: Option<String>,
        status: impl Into<String>,
        details: Option<String>,
        duration_ms: Option<u64>,
    ) -> Result<()> {
        let record = AuditRecord {
            timestamp: Utc::now(),
            action: action.into(),
            task_id: task_id.into(),
            org_id,
            device_id: device_id.into(),
            app_name: app_name.into(),
            checksum,
            status: status.into(),
            details,
            duration_ms,
        };

        self.log(&record)
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::read_to_string;
    use tempfile::tempdir;

    #[test]
    fn test_audit_logger_writes_and_appends() {
        let dir = tempdir().unwrap();
        let log_file = dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_file).unwrap();

        logger
            .record_event(
                "task.download",
                "task-001",
                1,
                "dev-01",
                "teams",
                Some("sha256:abc".to_string()),
                "success",
                None,
                Some(120),
            )
            .unwrap();

        logger
            .record_event(
                "task.install",
                "task-001",
                1,
                "dev-01",
                "teams",
                None,
                "done",
                Some("Installation finished successfully".to_string()),
                Some(350),
            )
            .unwrap();

        let content = read_to_string(&log_file).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let rec1: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec1.action, "task.download");
        assert_eq!(rec1.task_id, "task-001");
        assert_eq!(rec1.status, "success");

        let rec2: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(rec2.action, "task.install");
        assert_eq!(rec2.status, "done");
    }
}
