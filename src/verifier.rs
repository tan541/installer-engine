use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{EngineError, Result};

pub struct ChecksumVerifier;

impl ChecksumVerifier {
    /// Computes the SHA-256 hex string of a file at `file_path`.
    pub fn compute_sha256<P: AsRef<Path>>(file_path: P) -> Result<String> {
        let path = file_path.as_ref();
        let file = File::open(path).map_err(|e| EngineError::Io(e))?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer).map_err(EngineError::Io)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash_result = hasher.finalize();
        Ok(hex::encode(hash_result))
    }

    /// Computes the SHA-256 hex string of an in-memory byte slice.
    pub fn compute_bytes_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Verifies that the file at `file_path` matches `expected_hex` (case-insensitive).
    /// If expected_hex has a prefix like "sha256:", it trims the prefix.
    pub fn verify<P: AsRef<Path>>(file_path: P, expected_hex: &str) -> Result<()> {
        let path = file_path.as_ref();
        let clean_expected = expected_hex
            .trim()
            .strip_prefix("sha256:")
            .unwrap_or(expected_hex.trim())
            .to_lowercase();

        let calculated = Self::compute_sha256(path)?.to_lowercase();

        if calculated != clean_expected {
            return Err(EngineError::ChecksumMismatch {
                file: path.display().to_string(),
                expected: clean_expected,
                calculated,
            });
        }

        tracing::info!(
            file = %path.display(),
            checksum = %calculated,
            "Checksum verification succeeded"
        );

        Ok(())
    }
}

pub struct AppInstallationVerifier;

impl AppInstallationVerifier {
    /// Checks if an application bundle or binary exists in standard system paths for the given platform.
    pub fn verify_app_installed(app_name: &str, platform: crate::models::Platform) -> Option<std::path::PathBuf> {
        match platform {
            crate::models::Platform::MacOS => {
                let primary_app_dir = Path::new("/Applications");
                if let Some(found) = Self::verify_in_directory(app_name, primary_app_dir) {
                    return Some(found);
                }

                if let Ok(home) = std::env::var("HOME") {
                    let user_app_dir = Path::new(&home).join("Applications");
                    if let Some(found) = Self::verify_in_directory(app_name, &user_app_dir) {
                        return Some(found);
                    }
                }
                None
            }
            crate::models::Platform::Linux => {
                let search_dirs = [Path::new("/opt"), Path::new("/usr/bin"), Path::new("/usr/local/bin")];
                for dir in search_dirs {
                    if let Some(found) = Self::verify_in_directory(app_name, dir) {
                        return Some(found);
                    }
                }
                None
            }
            crate::models::Platform::Windows => {
                let search_dirs = [
                    Path::new(r"C:\Program Files"),
                    Path::new(r"C:\Program Files (x86)"),
                ];
                for dir in search_dirs {
                    if let Some(found) = Self::verify_in_directory(app_name, dir) {
                        return Some(found);
                    }
                }
                None
            }
            crate::models::Platform::Unknown => None,
        }
    }

    /// Verifies if an app (e.g. "ShieldNet 360" or "ShieldNet 360.app") exists in `search_dir`.
    pub fn verify_in_directory<P: AsRef<Path>>(app_name: &str, search_dir: P) -> Option<std::path::PathBuf> {
        let dir = search_dir.as_ref();
        if !dir.exists() {
            return None;
        }

        let clean_name = app_name.trim();
        let lower_target = clean_name.to_lowercase();
        let lower_target_app = if lower_target.ends_with(".app") {
            lower_target.clone()
        } else {
            format!("{}.app", lower_target)
        };

        // 1. Scan directory entries to match actual on-disk file/bundle with authentic casing
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy().to_lowercase();

                if file_name_str == lower_target || file_name_str == lower_target_app {
                    return Some(entry.path());
                }
            }
        }

        // 2. Direct probe fallback
        let direct_app = dir.join(if clean_name.ends_with(".app") {
            clean_name.to_string()
        } else {
            format!("{}.app", clean_name)
        });
        if direct_app.exists() {
            return Some(direct_app);
        }

        let direct_path = dir.join(clean_name);
        if direct_path.exists() {
            return Some(direct_path);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_and_verify_sha256() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"Hello, installer engine!";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();

        let expected_hash = ChecksumVerifier::compute_bytes_sha256(data);
        assert!(!expected_hash.is_empty());

        let result = ChecksumVerifier::verify(temp_file.path(), &expected_hash);
        assert!(result.is_ok());

        let prefixed = format!("sha256:{}", expected_hash.to_uppercase());
        assert!(ChecksumVerifier::verify(temp_file.path(), &prefixed).is_ok());
    }

    #[test]
    fn test_mismatch_sha256() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Original content").unwrap();
        temp_file.flush().unwrap();

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = ChecksumVerifier::verify(temp_file.path(), wrong_hash).unwrap_err();

        match err {
            EngineError::ChecksumMismatch { expected, .. } => {
                assert_eq!(expected, wrong_hash);
            }
            _ => panic!("Expected ChecksumMismatch error"),
        }
    }
}
