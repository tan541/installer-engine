use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Serialization/Deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Download failed: {0}")]
    Download(String),

    #[error("Checksum mismatch for {file}: expected {expected}, calculated {calculated}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        calculated: String,
    },

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Unsupported package format: {0}")]
    UnsupportedPackageFormat(String),

    #[error("Installer execution failed (exit code {exit_code:?}): {message}")]
    InstallerExecution {
        exit_code: Option<i32>,
        message: String,
    },

    #[error("Control plane error: {0}")]
    ControlPlane(String),

    #[error("Audit log error: {0}")]
    Audit(String),

    #[error("Task error: {0}")]
    Task(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;
