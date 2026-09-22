use std::sync::{Arc, Mutex};
use crate::error::Result;

pub trait DesktopNotifier: Send + Sync {
    fn notify(&self, app_name: &str, custom_msg: Option<&str>) -> Result<bool>;
}

/// Native platform desktop notifier
#[derive(Debug, Default)]
pub struct PlatformDesktopNotifier;

impl PlatformDesktopNotifier {
    pub fn new() -> Self {
        Self
    }
}

impl DesktopNotifier for PlatformDesktopNotifier {
    fn notify(&self, app_name: &str, custom_msg: Option<&str>) -> Result<bool> {
        let msg = custom_msg.unwrap_or(
            "Installation or execution of this application has been blocked by your organization's IT security policy."
        );

        #[cfg(target_os = "macos")]
        {
            let script = format!(
                "display notification \"{}\" with title \"IT Security: '{}' Blocked\" subtitle \"Installation Blocked\"",
                msg.replace('"', "\\\""),
                app_name.replace('"', "\\\"")
            );
            let status = std::process::Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .status();

            match status {
                Ok(s) => Ok(s.success()),
                Err(e) => {
                    tracing::warn!("Failed to display macOS notification via osascript: {e}");
                    Ok(false)
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let ps_script = format!(
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
                 $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
                 $textNodes = $template.GetElementsByTagName('text'); \
                 $textNodes.Item(0).AppendChild($template.CreateTextNode('IT Security: Installation Blocked')) > $null; \
                 $textNodes.Item(1).AppendChild($template.CreateTextNode('{} has been blocked by security policy.')) > $null;",
                app_name.replace('\'', "''")
            );
            let status = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .status();

            match status {
                Ok(s) => Ok(s.success()),
                Err(e) => {
                    tracing::warn!("Failed to display Windows notification: {e}");
                    Ok(false)
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let title = format!("IT Security: '{}' Blocked", app_name);
            let status = std::process::Command::new("notify-send")
                .arg(&title)
                .arg(msg)
                .status();

            match status {
                Ok(s) => Ok(s.success()),
                Err(e) => {
                    tracing::warn!("Failed to display Linux notification via notify-send: {e}");
                    Ok(false)
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            tracing::info!(app = %app_name, message = %msg, "[NOTIFICATION] Application installation blocked");
            Ok(true)
        }
    }
}

/// Mock Desktop Notifier for unit tests
#[derive(Debug, Default, Clone)]
pub struct MockDesktopNotifier {
    pub notifications: Arc<Mutex<Vec<(String, Option<String>)>>>,
}

impl MockDesktopNotifier {
    pub fn new() -> Self {
        Self {
            notifications: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn last_notification(&self) -> Option<(String, Option<String>)> {
        let lock = self.notifications.lock().unwrap();
        lock.last().cloned()
    }

    pub fn count(&self) -> usize {
        let lock = self.notifications.lock().unwrap();
        lock.len()
    }
}

impl DesktopNotifier for MockDesktopNotifier {
    fn notify(&self, app_name: &str, custom_msg: Option<&str>) -> Result<bool> {
        let mut lock = self.notifications.lock().unwrap();
        lock.push((app_name.to_string(), custom_msg.map(|s| s.to_string())));
        Ok(true)
    }
}
