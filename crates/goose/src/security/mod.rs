pub mod config;
pub mod content_scanner;
pub mod feedback_manager;
pub mod model_downloader;
pub mod model_pool;
pub mod rust_scanners;
pub mod threat_detection;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_types;

#[cfg(test)]
mod test_onnx;

#[cfg(test)]
mod test_scanner;

#[cfg(test)]
mod test_ensemble;

use anyhow::Result;
use config::{ActionPolicy, ContentType, EffectiveConfig, ScannerType, SecurityConfig};
use content_scanner::{ContentScanner, ScanResult, ThreatLevel};
use feedback_manager::SecurityFeedbackManager;
use rmcp::model::Content;
use serde_json::Value;
use std::sync::Arc;
use threat_detection::{
    DeepsetDebertaScanner, LazyEnsembleScanner,
    OpenAiModerationScanner, SimpleTestScanner, ToxicBertScanner,
};

#[cfg(feature = "security-onnx")]
use rust_scanners::{OnnxDeepsetDebertaScanner, OnnxProtectAiDebertaScanner};

#[derive(Debug)]
struct HighConfidenceThreat {
    model_name: String,
    confidence: f32,
    threat_level: ThreatLevel,
}

/// Extract confidence value from text for a specific model
fn extract_confidence_from_text(text: &str, model_name: &str) -> Option<f32> {
    // Look for patterns like "(confidence: 0.999)" after the model name
    if let Some(model_start) = text.find(model_name) {
        let text_after_model = &text[model_start..];
        // Look for confidence pattern
        if let Some(conf_start) = text_after_model.find("confidence: ") {
            let conf_text = &text_after_model[conf_start + 12..]; // Skip "confidence: "
            // Find the end of the number (either ) or space)
            let conf_end = conf_text.find(')').unwrap_or_else(|| {
                conf_text.find(' ').unwrap_or(conf_text.len())
            });
            let conf_str = &conf_text[..conf_end];
            return conf_str.parse::<f32>().ok();
        }
    }
    None
}

#[derive(Clone)]
pub struct SecurityManager {
    config: SecurityConfig,
    scanner: Option<Arc<dyn ContentScanner>>,
    feedback_manager: SecurityFeedbackManager,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        tracing::info!(
            "🔒 SECURITY: Initializing SecurityManager with scanner_type: {:?}",
            config.scanner_type
        );
        
        let scanner = if config.enabled {
            match config.scanner_type {
                ScannerType::SimpleTest => {
                    tracing::info!(
                        enabled = true,
                        scanner = ?config.scanner_type,
                        action_policy = ?config.action_policy,
                        threshold = ?config.scan_threshold,
                        confidence_threshold = config.confidence_threshold,
                        "Initializing SimpleTest security scanner (pattern-based testing)"
                    );
                    Some(
                        Arc::new(SimpleTestScanner::new(config.confidence_threshold))
                            as Arc<dyn ContentScanner>,
                    )
                }
                ScannerType::ProtectAiDeberta => {
                    tracing::info!(
                        enabled = true,
                        scanner = ?config.scanner_type,
                        action_policy = ?config.action_policy,
                        threshold = ?config.scan_threshold,
                        confidence_threshold = config.confidence_threshold,
                        "Initializing ProtectAI DeBERTa security scanner (using Deepset as fallback)"
                    );
                    Some(
                        Arc::new(DeepsetDebertaScanner::new(config.confidence_threshold))
                            as Arc<dyn ContentScanner>,
                    )
                }
                ScannerType::DeepsetDeberta => {
                    tracing::info!(
                        enabled = true,
                        scanner = ?config.scanner_type,
                        action_policy = ?config.action_policy,
                        threshold = ?config.scan_threshold,
                        confidence_threshold = config.confidence_threshold,
                        "Initializing Deepset DeBERTa security scanner (Python-based)"
                    );
                    Some(
                        Arc::new(DeepsetDebertaScanner::new(config.confidence_threshold))
                            as Arc<dyn ContentScanner>,
                    )
                }
                ScannerType::RustDeepsetDeberta => {
                    #[cfg(feature = "security-onnx")]
                    {
                        tracing::info!(
                            enabled = true,
                            scanner = ?config.scanner_type,
                            action_policy = ?config.action_policy,
                            threshold = ?config.scan_threshold,
                            confidence_threshold = config.confidence_threshold,
                            "Initializing ONNX Deepset DeBERTa security scanner"
                        );
                        Some(
                            Arc::new(OnnxDeepsetDebertaScanner::new(config.confidence_threshold))
                                as Arc<dyn ContentScanner>,
                        )
                    }
                    #[cfg(not(feature = "security-onnx"))]
                    {
                        tracing::warn!("ONNX scanner requested but security-onnx feature not enabled, falling back to None");
                        None
                    }
                }
                ScannerType::RustProtectAiDeberta => {
                    #[cfg(feature = "security-onnx")]
                    {
                        tracing::info!(
                            enabled = true,
                            scanner = ?config.scanner_type,
                            action_policy = ?config.action_policy,
                            threshold = ?config.scan_threshold,
                            confidence_threshold = config.confidence_threshold,
                            "Initializing ONNX ProtectAI DeBERTa security scanner"
                        );
                        Some(Arc::new(OnnxProtectAiDebertaScanner::new(
                            config.confidence_threshold,
                        )) as Arc<dyn ContentScanner>)
                    }
                    #[cfg(not(feature = "security-onnx"))]
                    {
                        tracing::warn!("ONNX scanner requested but security-onnx feature not enabled, falling back to None");
                        None
                    }
                }
                ScannerType::OpenAiModeration => {
                    tracing::info!(
                        enabled = true,
                        scanner = ?config.scanner_type,
                        action_policy = ?config.action_policy,
                        threshold = ?config.scan_threshold,
                        confidence_threshold = config.confidence_threshold,
                        "Initializing OpenAI Moderation security scanner"
                    );
                    Some(
                        Arc::new(OpenAiModerationScanner::new(config.confidence_threshold))
                            as Arc<dyn ContentScanner>,
                    )
                }
                ScannerType::ToxicBert => {
                    tracing::info!(
                        enabled = true,
                        scanner = ?config.scanner_type,
                        action_policy = ?config.action_policy,
                        threshold = ?config.scan_threshold,
                        confidence_threshold = config.confidence_threshold,
                        "Initializing ToxicBERT security scanner"
                    );
                    Some(Arc::new(ToxicBertScanner::new(config.confidence_threshold))
                        as Arc<dyn ContentScanner>)
                }
                ScannerType::ParallelEnsemble => {
                    if let Some(ensemble_config) = config.ensemble_config.clone() {
                        tracing::info!(
                            enabled = true,
                            scanner = ?config.scanner_type,
                            action_policy = ?config.action_policy,
                            threshold = ?config.scan_threshold,
                            confidence_threshold = config.confidence_threshold,
                            voting_strategy = ?ensemble_config.voting_strategy,
                            member_count = ensemble_config.member_configs.len(),
                            "Initializing Parallel Ensemble security scanner (lazy loading)"
                        );
                        Some(Arc::new(LazyEnsembleScanner::new(ensemble_config)) as Arc<dyn ContentScanner>)
                    } else {
                        tracing::error!("ParallelEnsemble scanner type requires ensemble_config");
                        None
                    }
                }
                ScannerType::HybridTiered => {
                    tracing::error!("HybridTiered scanner not yet implemented");
                    None
                }
                ScannerType::None => {
                    tracing::info!("Security scanner type is None, scanner will be disabled");
                    None
                }
            }
        } else {
            tracing::info!("Security scanner is disabled in configuration");
            None
        };

        Self { 
            config, 
            scanner,
            feedback_manager: SecurityFeedbackManager::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.scanner.is_some()
    }

    // Rest of the implementation would go here...
    // For now, let's add the essential methods
    
    pub async fn scan_content(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        if !self.is_enabled() {
            return Ok(None);
        }
        
        if let Some(scanner) = &self.scanner {
            Ok(Some(scanner.scan_content(content).await?))
        } else {
            Ok(None)
        }
    }
}
