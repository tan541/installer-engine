use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use reqwest::Client;

use crate::error::{EngineError, Result};

pub struct Downloader {
    client: Client,
    cache_dir: PathBuf,
}

impl Downloader {
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let path = cache_dir.as_ref().to_path_buf();
        create_dir_all(&path)
            .map_err(|e| EngineError::Download(format!("Failed to create cache directory: {e}")))?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| EngineError::Download(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            client,
            cache_dir: path,
        })
    }

    /// Downloads from `url` to a local file inside `cache_dir`.
    /// Supports `http://`, `https://`, and `file://` schemes.
    pub async fn download(&self, url: &str, file_name: &str) -> Result<PathBuf> {
        let destination = self.cache_dir.join(file_name);

        tracing::info!(
            url = %url,
            destination = %destination.display(),
            "Starting download"
        );

        if let Some(local_path) = url.strip_prefix("file://") {
            // Local file copy for offline/testing mode
            let source_path = Path::new(local_path);
            std::fs::copy(source_path, &destination).map_err(|e| {
                EngineError::Download(format!(
                    "Failed to copy local file from {local_path} to {}: {e}",
                    destination.display()
                ))
            })?;

            tracing::info!(
                destination = %destination.display(),
                "Copied local file successfully"
            );
            return Ok(destination);
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| EngineError::Download(format!("Failed to GET {url}: {e}")))?;

        if !response.status().is_success() {
            return Err(EngineError::Download(format!(
                "HTTP request to {url} failed with status {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| EngineError::Download(format!("Failed to read response body: {e}")))?;

        let mut file = File::create(&destination)
            .map_err(|e| EngineError::Download(format!("Failed to create file at {}: {e}", destination.display())))?;

        file.write_all(&bytes)
            .map_err(|e| EngineError::Download(format!("Failed to write to file: {e}")))?;

        file.flush()
            .map_err(|e| EngineError::Download(format!("Failed to flush downloaded file: {e}")))?;

        tracing::info!(
            destination = %destination.display(),
            bytes_downloaded = bytes.len(),
            "Download completed successfully"
        );

        Ok(destination)
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, NamedTempFile};

    #[tokio::test]
    async fn test_file_scheme_download() {
        let temp_dir = tempdir().unwrap();
        let downloader = Downloader::new(temp_dir.path()).unwrap();

        let mut source_file = NamedTempFile::new().unwrap();
        source_file.write_all(b"sample package data").unwrap();
        source_file.flush().unwrap();

        let file_url = format!("file://{}", source_file.path().display());
        let downloaded = downloader.download(&file_url, "target_pkg.bin").await.unwrap();

        assert!(downloaded.exists());
        let content = std::fs::read_to_string(downloaded).unwrap();
        assert_eq!(content, "sample package data");
    }
}
