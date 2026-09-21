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
