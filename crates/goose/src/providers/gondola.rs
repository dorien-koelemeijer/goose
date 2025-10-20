use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::api_client::{ApiClient, AuthMethod};
use super::base::{ConfigKey, ModelInfo, Provider, ProviderMetadata, ProviderUsage, Usage};
use super::errors::ProviderError;
use crate::conversation::message::Message;
use crate::model::ModelConfig;
use rmcp::model::Tool;

/// Configuration for a Gondola BERT model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GondolaConfig {
    /// The model name in Gondola (e.g., "deberta-prompt-injection-v2")
    pub model_name: String,
    /// The model version (e.g., "gmv-zve9abhxe9s7fq1zep5dxd807")
    pub version: String,
    /// The source identifier (e.g., "admin-test")
    pub source: String,
    /// The Gondola endpoint URL
    pub endpoint: String,
}

impl Default for GondolaConfig {
    fn default() -> Self {
        Self {
            model_name: "deberta-prompt-injection-v2".to_string(),
            version: "gmv-zve9abhxe9s7fq1zep5dxd807".to_string(),
            source: "admin-test".to_string(),
            endpoint: "https://gondola-ski.stage.sqprod.co".to_string(),
        }
    }
}

/// Response from Gondola's BatchInfer endpoint
#[derive(Debug, Deserialize)]
struct GondolaBatchInferResponse {
    model: String,
    version: String,
    occurred_at: String,
    response_items: Vec<GondolaResponseItem>,
}

#[derive(Debug, Deserialize)]
struct GondolaResponseItem {
    double_list_value: DoubleListValue,
}

#[derive(Debug, Deserialize)]
struct DoubleListValue {
    double_values: Vec<f64>,
}

/// Result of prompt injection detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInjectionResult {
    /// Whether prompt injection was detected
    pub is_injection: bool,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Raw scores from the model [safe_score, injection_score]
    pub raw_scores: Vec<f64>,
}

impl PromptInjectionResult {
    /// Create a result from raw Gondola scores
    /// The model returns [safe_score, injection_score] where higher values indicate stronger confidence
    pub fn from_raw_scores(scores: Vec<f64>) -> Self {
        if scores.len() != 2 {
            tracing::warn!("Expected 2 scores from Gondola model, got {}", scores.len());
            return Self {
                is_injection: false,
                confidence: 0.0,
                raw_scores: scores,
            };
        }

        let safe_score = scores[0];
        let injection_score = scores[1];
        
        // Determine if injection is detected based on which score is higher
        let is_injection = injection_score > safe_score;
        
        // Calculate confidence as the difference between the scores, normalized
        let max_score = safe_score.max(injection_score);
        let min_score = safe_score.min(injection_score);
        let confidence = if max_score == min_score {
            0.5 // Equal scores = uncertain
        } else {
            // Normalize the difference to 0.5-1.0 range
            0.5 + ((max_score - min_score) / (max_score.abs() + min_score.abs()).max(1.0)) * 0.5
        };

        Self {
            is_injection,
            confidence: confidence.clamp(0.0, 1.0),
            raw_scores: scores,
        }
    }
}

/// Gondola provider for BERT-based prompt injection detection
#[derive(Debug)]
pub struct GondolaProvider {
    api_client: ApiClient,
    config: GondolaConfig,
    model: ModelConfig,
}

impl GondolaProvider {
    /// Create a new GondolaProvider from environment variables
    pub async fn from_env(model: ModelConfig) -> Result<Self> {
        let global_config = crate::config::Config::global();
        
        let config = GondolaConfig {
            model_name: global_config
                .get_param("GONDOLA_MODEL_NAME")
                .unwrap_or_else(|_| GondolaConfig::default().model_name),
            version: global_config
                .get_param("GONDOLA_MODEL_VERSION")
                .unwrap_or_else(|_| GondolaConfig::default().version),
            source: global_config
                .get_param("GONDOLA_SOURCE")
                .unwrap_or_else(|_| GondolaConfig::default().source),
            endpoint: global_config
                .get_param("GONDOLA_ENDPOINT")
                .unwrap_or_else(|_| GondolaConfig::default().endpoint),
        };

        let timeout_secs: u64 = global_config.get_param("GONDOLA_TIMEOUT").unwrap_or(30);

        // For now, we'll try without explicit authentication, assuming Trogdor handles it
        let auth = AuthMethod::None;
        let api_client = ApiClient::with_timeout(
            config.endpoint.clone(),
            auth,
            std::time::Duration::from_secs(timeout_secs),
        )?;

        Ok(Self {
            api_client,
            config,
            model,
        })
    }

    /// Create a new GondolaProvider with custom configuration
    pub fn with_config(model: ModelConfig, config: GondolaConfig) -> Result<Self> {
        let auth = AuthMethod::None;
        let api_client = ApiClient::with_timeout(
            config.endpoint.clone(),
            auth,
            std::time::Duration::from_secs(30),
        )?;

        Ok(Self {
            api_client,
            config,
            model,
        })
    }

    /// Scan text for prompt injection using the Gondola BERT model
    pub async fn scan_for_prompt_injection(&self, text: &str) -> Result<PromptInjectionResult, ProviderError> {
        let payload = json!({
            "model": self.config.model_name,
            "version": self.config.version,
            "source": self.config.source,
            "input_names": ["text_input"],
            "request_items": [{
                "inputs": [{
                    "string_value": text
                }]
            }]
        });

        tracing::debug!("Sending request to Gondola: {}", payload);

        let response = self
            .api_client
            .response_post("services/squareup.gondola.service.ModelService/BatchInfer", &payload)
            .await
            .map_err(|e| ProviderError::RequestFailed(format!("Gondola request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ProviderError::RequestFailed(format!(
                "Gondola API error {}: {}",
                status, error_text
            )));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| ProviderError::RequestFailed(format!("Failed to read response: {}", e)))?;

        tracing::debug!("Gondola response: {}", response_text);

        let gondola_response: GondolaBatchInferResponse = serde_json::from_str(&response_text)
            .map_err(|e| ProviderError::RequestFailed(format!("Failed to parse Gondola response: {}", e)))?;

        if gondola_response.response_items.is_empty() {
            return Err(ProviderError::RequestFailed(
                "Empty response from Gondola".to_string(),
            ));
        }

        let scores = gondola_response.response_items[0]
            .double_list_value
            .double_values
            .clone();

        Ok(PromptInjectionResult::from_raw_scores(scores))
    }

    /// Check if the Gondola service is available
    pub async fn is_available(&self) -> bool {
        // Simple health check - try to make a minimal request
        let test_payload = json!({
            "model": self.config.model_name,
            "version": self.config.version,
            "source": self.config.source,
            "input_names": ["text_input"],
            "request_items": [{
                "inputs": [{
                    "string_value": "test"
                }]
            }]
        });

        match self
            .api_client
            .response_post("services/squareup.gondola.service.ModelService/BatchInfer", &test_payload)
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait]
impl Provider for GondolaProvider {
    fn metadata() -> ProviderMetadata {
        ProviderMetadata::with_models(
            "gondola",
            "Gondola",
            "Internal Gondola service for BERT-based security scanning",
            "deberta-prompt-injection-v2",
            vec![ModelInfo::new("deberta-prompt-injection-v2", 512)], // BERT models typically have 512 token limit
            "https://gondola-internal-docs", // Placeholder for internal docs
            vec![
                ConfigKey::new("GONDOLA_ENDPOINT", false, false, Some("https://gondola-ski.stage.sqprod.co")),
                ConfigKey::new("GONDOLA_MODEL_NAME", false, false, Some("deberta-prompt-injection-v2")),
                ConfigKey::new("GONDOLA_MODEL_VERSION", false, false, Some("gmv-zve9abhxe9s7fq1zep5dxd807")),
                ConfigKey::new("GONDOLA_SOURCE", false, false, Some("admin-test")),
                ConfigKey::new("GONDOLA_TIMEOUT", false, false, Some("30")),
            ],
        )
    }

    fn get_model_config(&self) -> ModelConfig {
        self.model.clone()
    }

    async fn complete_with_model(
        &self,
        _model_config: &ModelConfig,
        _system: &str,
        _messages: &[Message],
        _tools: &[Tool],
    ) -> Result<(Message, ProviderUsage), ProviderError> {
        // Gondola is not a chat completion provider - it's specialized for security scanning
        Err(ProviderError::NotImplemented(
            "GondolaProvider is specialized for security scanning, not chat completion".to_string(),
        ))
    }

    async fn fetch_supported_models(&self) -> Result<Option<Vec<String>>, ProviderError> {
        // For now, return the configured model
        // In the future, this could query Gondola for available models
        Ok(Some(vec![self.config.model_name.clone()]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_injection_result_from_scores() {
        // Test case where injection is detected (injection_score > safe_score)
        let scores = vec![2.0, 5.0]; // [safe_score, injection_score]
        let result = PromptInjectionResult::from_raw_scores(scores.clone());
        
        assert!(result.is_injection);
        assert!(result.confidence > 0.5);
        assert_eq!(result.raw_scores, scores);

        // Test case where no injection is detected (safe_score > injection_score)
        let scores = vec![5.0, 2.0]; // [safe_score, injection_score]
        let result = PromptInjectionResult::from_raw_scores(scores.clone());
        
        assert!(!result.is_injection);
        assert!(result.confidence > 0.5);
        assert_eq!(result.raw_scores, scores);

        // Test case with equal scores (uncertain)
        let scores = vec![3.0, 3.0];
        let result = PromptInjectionResult::from_raw_scores(scores.clone());
        
        assert_eq!(result.confidence, 0.5);
        assert_eq!(result.raw_scores, scores);
    }

    #[test]
    fn test_prompt_injection_result_invalid_scores() {
        // Test with wrong number of scores
        let scores = vec![1.0]; // Only one score
        let result = PromptInjectionResult::from_raw_scores(scores.clone());
        
        assert!(!result.is_injection);
        assert_eq!(result.confidence, 0.0);
        assert_eq!(result.raw_scores, scores);
    }

    #[test]
    fn test_gondola_config_default() {
        let config = GondolaConfig::default();
        assert_eq!(config.model_name, "deberta-prompt-injection-v2");
        assert_eq!(config.version, "gmv-zve9abhxe9s7fq1zep5dxd807");
        assert_eq!(config.source, "admin-test");
        assert_eq!(config.endpoint, "https://gondola-ski.stage.sqprod.co");
    }
}
