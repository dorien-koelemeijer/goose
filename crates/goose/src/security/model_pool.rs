use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Manages long-running Python processes for model inference
/// Keeps processes alive to avoid model loading overhead
pub struct PythonModelPool {
    processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
}

struct ProcessInfo {
    process: Child,
    last_used: Instant,
}

impl PythonModelPool {
    pub fn new() -> Self {
        let pool = Self {
            processes: Arc::new(Mutex::new(HashMap::new())),
        };

        // Start cleanup task
        pool.start_cleanup_task();
        pool
    }

    pub async fn scan_with_model(&self, model_name: &str, text: &str) -> Result<String> {
        // For now, fall back to the current approach
        // TODO: Implement persistent process communication
        self.scan_with_process(model_name, text).await
    }

    async fn scan_with_process(&self, model_name: &str, text: &str) -> Result<String> {
        // Current implementation - spawn process per request
        // This is what we have now, but could be optimized
        let script_path = self.get_script_path(model_name)?;

        let output = Command::new("python3")
            .arg(&script_path)
            .arg("--text")
            .arg(text)
            .arg("--model")
            .arg(model_name)
            .output()
            .context("Failed to execute Python script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Python script failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn get_script_path(&self, model_name: &str) -> Result<String> {
        // Return appropriate script path based on model
        if model_name.contains("llama") {
            Ok("llama_prompt_guard2_scanner.py".to_string())
        } else {
            Ok("prompt_injection_scanner.py".to_string())
        }
    }

    fn start_cleanup_task(&self) {
        let processes = Arc::clone(&self.processes);
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await; // Check every minute

                let mut processes = processes.lock().unwrap();
                let now = Instant::now();
                let timeout = Duration::from_secs(300); // 5 minutes

                // Find expired processes
                let expired: Vec<String> = processes
                    .iter()
                    .filter(|(_, info)| now.duration_since(info.last_used) > timeout)
                    .map(|(key, _)| key.clone())
                    .collect();

                // Kill expired processes
                for key in expired {
                    if let Some(mut info) = processes.remove(&key) {
                        let _ = info.process.kill();
                        tracing::info!("Cleaned up expired Python process: {}", key);
                    }
                }
            }
        });
    }
}

// TODO: Future implementation for persistent processes
impl PythonModelPool {
    #[allow(dead_code)]
    async fn scan_with_persistent_process(&self, _model_name: &str, _text: &str) -> Result<String> {
        // Future implementation:
        // 1. Check if process exists and is alive
        // 2. If not, spawn new process with stdin/stdout pipes
        // 3. Send JSON request via stdin
        // 4. Read JSON response from stdout
        // 5. Update last_used timestamp

        todo!("Implement persistent process communication")
    }
}
