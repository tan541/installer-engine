pub mod audit;
pub mod control_plane;
pub mod download;
pub mod engine;
pub mod error;
pub mod installer;
pub mod logging;
pub mod models;
pub mod verifier;

// Re-exports for convenience
pub use audit::{AuditLogger, AuditRecord};
pub use control_plane::{ControlPlaneClient, HttpControlPlaneClient, MockControlPlane};
pub use download::Downloader;
pub use engine::{EngineConfig, InstallerEngine};
pub use error::{EngineError, Result};
pub use installer::{create_installer, Installer, MockInstaller, PlatformInstaller};
pub use logging::init_logger;
pub use models::{GroupPolicy, InstallReport, Platform, Task, TaskStatus, TaskType};
pub use verifier::ChecksumVerifier;
