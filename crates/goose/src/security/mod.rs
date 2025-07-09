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
use mcp_core::Content;
use serde_json::Value;
use std::sync::Arc;
use threat_detection::{
    DeepsetDebertaScanner, LazyEnsembleScanner,
    OpenAiModerationScanner, ToxicBertScanner,
};

#[cfg(feature = "security-onnx")]
use rust_scanners::{OnnxDeepsetDebertaScanner, OnnxProtectAiDebertaScanner};

#[derive(Clone)]
pub struct SecurityManager {
    config: SecurityConfig,
    scanner: Option<Arc<dyn ContentScanner>>,
    feedback_manager: SecurityFeedbackManager,
}
// check if this is the right scanner or if it should be RustProtectAiDeberta
impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        let scanner = if config.enabled {
            match config.scanner_type {
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
                        // Create a lazy ensemble scanner that doesn't immediately load models
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

    pub async fn check_models_need_download(&self) -> bool {
        if !self.is_enabled() {
            return false;
        }

        // For ONNX scanners, check if models exist in cache
        #[cfg(feature = "security-onnx")]
        {
            use crate::security::model_downloader::{get_global_downloader, ModelInfo};
            
            // Check if we're using ONNX scanners that need model downloads
            if matches!(self.config.scanner_type, 
                ScannerType::RustDeepsetDeberta | 
                ScannerType::RustProtectAiDeberta |
                ScannerType::ParallelEnsemble
            ) {
                if let Ok(downloader) = get_global_downloader().await {
                    // Check if any required models are missing
                    let models_to_check = match self.config.scanner_type {
                        ScannerType::RustDeepsetDeberta => vec![ModelInfo::deepset_deberta()],
                        ScannerType::RustProtectAiDeberta => vec![ModelInfo::protectai_deberta()],
                        ScannerType::ParallelEnsemble => {
                            // Check ensemble members
                            if let Some(ref ensemble_config) = self.config.ensemble_config {
                                let mut models = Vec::new();
                                for member in &ensemble_config.member_configs {
                                    match member.scanner_type {
                                        ScannerType::RustDeepsetDeberta => models.push(ModelInfo::deepset_deberta()),
                                        ScannerType::RustProtectAiDeberta => models.push(ModelInfo::protectai_deberta()),
                                        _ => {}
                                    }
                                }
                                models
                            } else {
                                vec![]
                            }
                        },
                        _ => vec![]
                    };
                    
                    for model_info in models_to_check {
                        let model_path = downloader.get_cache_dir().join(&model_info.onnx_filename);
                        let tokenizer_path = downloader.get_cache_dir().join(&model_info.tokenizer_filename);
                        
                        if !model_path.exists() || !tokenizer_path.exists() {
                            return true; // At least one model needs download
                        }
                    }
                }
            }
        }
        
        false // No downloads needed
    }

    pub async fn prewarm_models(&self) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        tracing::info!("Pre-warming security models in background...");
        
        // Create a dummy content to trigger model loading
        let dummy_content = vec![Content::text("test")];
        
        // This will trigger model downloads and caching
        if let Err(e) = self.scan_content(&dummy_content).await {
            tracing::warn!("Failed to pre-warm models: {}", e);
            return Err(e);
        }
        
        tracing::info!("Security models pre-warmed successfully");
        Ok(())
    }

    pub async fn scan_content(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::UserMessage).await
    }

    pub async fn scan_content_with_type(&self, content: &[Content], content_type: ContentType) -> Result<Option<ScanResult>> {
        if !self.is_enabled() {
            tracing::info!("Security scanner is disabled, skipping content scan");
            return Ok(None);
        }

        let effective_config = self.config.get_config_for_type(content_type);

        // Log the content being scanned for debugging
        let content_text: Vec<String> = content.iter()
            .filter_map(|c| c.as_text().map(String::from))
            .collect();
        let combined_text = content_text.join("\n");
        let preview = if combined_text.len() > 200 {
            format!("{}...", &combined_text[..200])
        } else {
            combined_text.clone()
        };
        
        tracing::info!(
            content_type = ?content_type,
            content_length = combined_text.len(),
            content_preview = %preview,
            confidence_threshold = effective_config.confidence_threshold,
            scan_threshold = ?effective_config.scan_threshold,
            action_policy = ?effective_config.action_policy,
            "Starting security scan of content with type-specific configuration"
        );
        
        let scanner = self.scanner.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Security scanner not initialized"))?;
        
        // Handle the case where security models aren't ready yet
        match scanner.scan_content(content).await {
            Ok(mut scan_result) => {
                // Apply content-type-specific thresholds to the scan result
                scan_result = self.apply_type_specific_thresholds(scan_result, &effective_config);
                
                // Log the scan result with message content for debugging
                match scan_result.threat_level {
                    ThreatLevel::Safe => {
                        tracing::info!(
                            content_type = ?content_type,
                            content_preview = %preview,
                            "Content scan result: Safe"
                        );
                    }
                    ThreatLevel::Low => {
                        tracing::info!(
                            content_type = ?content_type,
                            threat = "low",
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            "Content scan detected low threat"
                        );
                    }
                    ThreatLevel::Medium => {
                        tracing::info!(
                            content_type = ?content_type,
                            threat = "medium",
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            "Content scan detected medium threat"
                        );
                    }
                    ThreatLevel::High | ThreatLevel::Critical => {
                        tracing::warn!(
                            content_type = ?content_type,
                            threat = ?scan_result.threat_level,
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            "Content scan detected high/critical threat"
                        );
                    }
                }
                Ok(Some(scan_result))
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("Security system not ready") {
                    // Return a special error that the agent can handle
                    Err(anyhow::anyhow!("SECURITY_NOT_READY: 🔒 Initialising Goose security models, this may take up to a minute. Please wait..."))
                } else {
                    // Other errors should be propagated normally
                    Err(e)
                }
            }
        }
    }

    /// Apply content-type-specific thresholds to adjust the scan result
    fn apply_type_specific_thresholds(&self, scan_result: ScanResult, effective_config: &EffectiveConfig) -> ScanResult {
        // If the effective confidence threshold is higher than the default,
        // we might need to downgrade the threat level
        if effective_config.confidence_threshold > self.config.confidence_threshold {
            // This is a simplified approach - we might want to
            // re-evaluate the raw confidence scores with the new threshold
            tracing::debug!(
                original_threshold = self.config.confidence_threshold,
                effective_threshold = effective_config.confidence_threshold,
                original_threat = ?scan_result.threat_level,
                "Applying content-type-specific threshold adjustment"
            );
            
            // For now, we'll keep the original scan result but the should_block/should_ask_user
            // methods will use the effective config
        }
        
        scan_result
    }

    pub async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<Option<ScanResult>> {
        if !self.is_enabled() {
            tracing::info!("Security scanner is disabled, skipping tool result scan");
            return Ok(None);
        }

        tracing::info!(tool = tool_name, "Starting security scan of tool result");
        let scanner = self.scanner.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Security scanner not initialized"))?;
        let scan_result = scanner
            .scan_tool_result(tool_name, arguments, result)
            .await?;

        // Log the scan result
        match scan_result.threat_level {
            ThreatLevel::Safe => {
                tracing::info!(tool = tool_name, "Tool result scan: Safe");
            }
            ThreatLevel::Low => {
                tracing::info!(
                    tool = tool_name,
                    threat = "low",
                    explanation = %scan_result.explanation,
                    "Tool result scan detected low threat"
                );
            }
            ThreatLevel::Medium => {
                tracing::info!(
                    tool = tool_name,
                    threat = "medium",
                    explanation = %scan_result.explanation,
                    "Tool result scan detected medium threat"
                );
            }
            ThreatLevel::High | ThreatLevel::Critical => {
                tracing::info!(
                    tool = tool_name,
                    threat = ?scan_result.threat_level,
                    explanation = %scan_result.explanation,
                    "Tool result scan detected high/critical threat"
                );
            }
        }

        Ok(Some(scan_result))
    }

    pub fn should_block(&self, scan_result: &ScanResult) -> bool {
        self.should_block_for_type(scan_result, ContentType::UserMessage)
    }

    pub fn should_block_for_type(&self, scan_result: &ScanResult, content_type: ContentType) -> bool {
        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
        
        if !self.config.enabled {
            return false;
        }

        matches!(action_policy, ActionPolicy::Block | ActionPolicy::BlockWithNote)
    }

    pub fn should_process_with_note(&self, scan_result: &ScanResult, content_type: ContentType) -> bool {
        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
        
        if !self.config.enabled {
            return false;
        }

        matches!(action_policy, ActionPolicy::ProcessWithNote)
    }

    /// Create a security note for the UI to display
    pub fn create_security_note(
        &self,
        scan_result: &ScanResult,
        content_type: ContentType,
    ) -> Option<config::SecurityNote> {
        if !self.is_enabled() {
            return None;
        }

        let action_taken = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
        
        // Determine feedback options directly from action type - WithNote actions get feedback
        let show_feedback_options = matches!(action_taken, 
            ActionPolicy::ProcessWithNote | ActionPolicy::BlockWithNote
        );

        // Only create notes for actions that show something to the user
        match action_taken {
            ActionPolicy::ProcessWithNote | ActionPolicy::Block | ActionPolicy::BlockWithNote => {
                Some(self.feedback_manager.create_security_note(
                    content_type,
                    scan_result,
                    action_taken,
                    show_feedback_options,
                ))
            }
            _ => None,
        }
    }

    /// Log user feedback (simple logging for now)
    pub fn log_user_feedback(
        &self,
        note_id: &str,
        feedback_type: config::FeedbackType,
        content_type: ContentType,
        threat_level: &ThreatLevel,
        user_comment: Option<&str>,
    ) {
        self.feedback_manager.log_user_feedback(
            note_id,
            feedback_type,
            content_type,
            threat_level,
            user_comment,
        );
    }

    /// Get the action policy for a specific threat level and content type
    pub fn get_action_for_threat(&self, content_type: ContentType, threat_level: &ThreatLevel) -> ActionPolicy {
        self.config.get_action_for_threat(content_type, threat_level)
    }

    pub fn get_safe_content(&self, original: &[Content], scan_result: &ScanResult) -> Vec<Content> {
        if !self.is_enabled() || self.config.action_policy == ActionPolicy::LogOnly {
            tracing::info!(
                "Security scanner: passing through original content (policy: {})",
                if !self.is_enabled() {
                    "disabled"
                } else {
                    "LogOnly"
                }
            );
            return original.to_vec();
        }

        // For AskUser policy, we don't modify content here - that's handled by the confirmation flow
        if self.config.action_policy == ActionPolicy::AskUser {
            tracing::info!(
                threat = ?scan_result.threat_level,
                policy = "AskUser",
                "Security scanner: content will be subject to user confirmation"
            );
            return original.to_vec();
        }

        if self.config.action_policy == ActionPolicy::Sanitize
            && scan_result.sanitized_content.is_some()
        {
            tracing::info!(
                threat = ?scan_result.threat_level,
                policy = "Sanitize",
                "Security scanner: sanitizing content due to detected threat: {}",
                scan_result.explanation
            );
            return scan_result.sanitized_content.clone()
                .unwrap_or_else(|| {
                    tracing::warn!("Sanitized content not available, falling back to original");
                    original.to_vec()
                });
        }

        if self.should_block(scan_result) {
            // Replace with warning message
            tracing::info!(
                threat = ?scan_result.threat_level,
                policy = "Block",
                "Security scanner: BLOCKING content due to detected threat: {}",
                scan_result.explanation
            );
            return vec![Content::text(format!(
                "[SECURITY WARNING] Content blocked due to detected threat: {}",
                scan_result.explanation
            ))];
        }

        // Default to original content
        tracing::info!(
            threat = ?scan_result.threat_level,
            policy = ?self.config.action_policy,
            "Security scanner: allowing content through (threat below threshold)"
        );
        original.to_vec()
    }
}
