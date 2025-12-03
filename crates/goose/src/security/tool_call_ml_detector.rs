use crate::config::Config;
use crate::security::classification_client::ClassificationClient;
use anyhow::Result;

/// ML detector specifically for scanning shell commands in tool calls
/// Uses the bashcat model trained to detect dangerous bash command structures
pub struct ToolCallMlDetector {
    client: ClassificationClient,
}

impl ToolCallMlDetector {
    pub fn new_from_config() -> Result<Self> {
        let config = Config::global();

        let endpoint = config
            .get_param::<String>("SECURITY_TOOL_CALL_BERT_ENDPOINT")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let token = config
            .get_secret::<String>("SECURITY_TOOL_CALL_BERT_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());

        tracing::debug!(
            has_endpoint = endpoint.is_some(),
            has_token = token.is_some(),
            "Initializing tool call ML detector from config"
        );

        let endpoint = endpoint.ok_or_else(|| {
            anyhow::anyhow!("Tool call ML detection requires SECURITY_TOOL_CALL_BERT_ENDPOINT")
        })?;

        tracing::info!(
            endpoint = %endpoint,
            "Using bashcat model for tool call scanning"
        );

        let client = ClassificationClient::from_endpoint(endpoint, None, token)?;
        Ok(Self { client })
    }

    /// Scan a shell command for dangerous patterns
    /// Returns confidence score (0.0 = safe, 1.0 = dangerous)
    pub async fn scan_command(&self, command: &str) -> Result<f32> {
        tracing::debug!(
            command_length = command.len(),
            "Scanning command with bashcat model"
        );

        let score = self.client.classify(command).await?;

        tracing::debug!(score = score, "Bashcat model returned score");

        Ok(score)
    }
}
