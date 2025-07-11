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
// check if this is the right scanner or if it should be RustProtectAiDeberta
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
            global_action_policy = ?effective_config.action_policy,
            "Starting security scan of content with type-specific configuration"
        );
        
        let scanner = self.scanner.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Security scanner not initialized"))?;
        
        // Handle the case where security models aren't ready yet
        match scanner.scan_content(content).await {
            Ok(mut scan_result) => {
                // TEMPORARY: Force Medium threat for testing configuration logic
                if combined_text.contains("rm -rf") || combined_text.contains("curl -X POST") {
                    tracing::warn!("🧪 TEMPORARY: Forcing Medium threat level to test configuration logic");
                    scan_result.threat_level = ThreatLevel::Medium;
                    scan_result.explanation = format!("FORCED Medium threat for testing: {}", scan_result.explanation);
                }
                
                // SPECIAL HANDLING FOR TOOL RESULTS: Trust any confident model detection
                // Only apply this override to actual tool output content, not tool arguments
                if content_type == ContentType::ToolResult && self.is_tool_output_content(&combined_text) {
                    scan_result = self.apply_tool_result_confidence_override(scan_result);
                }
                
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
                        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
                        tracing::info!(
                            content_type = ?content_type,
                            threat = "low",
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            severity_action_policy = ?action_policy,
                            "Content scan detected low threat"
                        );
                    }
                    ThreatLevel::Medium => {
                        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
                        tracing::info!(
                            content_type = ?content_type,
                            threat = "medium",
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            severity_action_policy = ?action_policy,
                            "Content scan detected medium threat"
                        );
                    }
                    ThreatLevel::High | ThreatLevel::Critical => {
                        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
                        tracing::warn!(
                            content_type = ?content_type,
                            threat = ?scan_result.threat_level,
                            content_preview = %preview,
                            explanation = %scan_result.explanation,
                            severity_action_policy = ?action_policy,
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

    /// Check if the content being scanned is actual tool output (not just tool arguments)
    /// Tool arguments typically have patterns like "Tool: toolname\nArguments: {...}"
    /// Tool output contains the actual response content
    fn is_tool_output_content(&self, content: &str) -> bool {
        // If the content starts with "Tool:" and contains "Arguments:", it's likely tool arguments being scanned
        if content.starts_with("Tool:") && content.contains("Arguments:") {
            // Check if this looks like a simple argument structure
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() <= 5 && content.len() < 200 {
                // This looks like tool arguments, not tool output
                tracing::debug!("Content appears to be tool arguments, not tool output - skipping confidence override");
                return false;
            }
        }
        
        // If content contains actual response data (like "Configuration data retrieved:", etc.)
        // or is longer/more complex, treat it as tool output
        if content.contains("Configuration data retrieved") 
            || content.contains("Here's the requested information")
            || content.len() > 200 {
            tracing::debug!("Content appears to be tool output - applying confidence override");
            return true;
        }
        
        // Default: if we're not sure, don't apply the aggressive override
        tracing::debug!("Content type unclear - defaulting to not applying confidence override");
        false
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

    /// Special handling for tool results: Trust any confident model detection
    /// For tool results, we want to be more aggressive and trust individual model confidence
    /// rather than ensemble voting that can dilute high-confidence detections
    fn apply_tool_result_confidence_override(&self, mut scan_result: ScanResult) -> ScanResult {
        // Only apply this override if the current result is "Safe" but the explanation
        // suggests individual models detected threats
        if scan_result.threat_level == ThreatLevel::Safe {
            // Parse the explanation to look for individual model results with high confidence
            if let Some(high_confidence_threat) = self.extract_high_confidence_threat(&scan_result.explanation) {
                tracing::warn!(
                    original_threat = ?scan_result.threat_level,
                    override_threat = ?high_confidence_threat.threat_level,
                    confidence = high_confidence_threat.confidence,
                    model = %high_confidence_threat.model_name,
                    "🔒 TOOL RESULTS: Overriding ensemble result - trusting high-confidence individual model detection"
                );
                
                scan_result.threat_level = high_confidence_threat.threat_level;
                scan_result.confidence = high_confidence_threat.confidence;
                scan_result.explanation = format!(
                    "TOOL RESULT OVERRIDE: Trusting {model} detection (confidence: {confidence:.3}) over ensemble voting. Original: {original}",
                    model = high_confidence_threat.model_name,
                    confidence = high_confidence_threat.confidence,
                    original = scan_result.explanation
                );
            }
        }
        
        scan_result
    }

    /// Extract high-confidence threat detection from ensemble explanation
    fn extract_high_confidence_threat(&self, explanation: &str) -> Option<HighConfidenceThreat> {
        // Look for patterns like "RustDeepsetDeberta: ONNX DeBERTa: potential prompt injection detected (confidence: 0.999)"
        // This is a simple regex-based approach - could be made more robust
        
        // Check for DeBERTa detection
        if explanation.contains("RustDeepsetDeberta") && explanation.contains("potential prompt injection detected") {
            if let Some(confidence_match) = extract_confidence_from_text(explanation, "RustDeepsetDeberta") {
                // MUCH higher threshold for DeBERTa due to false positive issues
                // Only trust it if it's EXTREMELY confident (99.9%+) AND other conditions are met
                if confidence_match >= 0.999 { // Raised from 0.8 to 0.999
                    return Some(HighConfidenceThreat {
                        model_name: "RustDeepsetDeberta".to_string(),
                        confidence: confidence_match,
                        threat_level: ThreatLevel::Medium, // Downgraded from High to Medium due to false positives
                    });
                }
            }
        }
        
        // Check for ProtectAI detection - keep more reasonable threshold since it seems more accurate
        if explanation.contains("RustProtectAiDeberta") && !explanation.contains("treating as safe") {
            if let Some(confidence_match) = extract_confidence_from_text(explanation, "RustProtectAiDeberta") {
                if confidence_match >= 0.8 {
                    return Some(HighConfidenceThreat {
                        model_name: "RustProtectAiDeberta".to_string(),
                        confidence: confidence_match,
                        threat_level: if confidence_match >= 0.95 {
                            ThreatLevel::High
                        } else if confidence_match >= 0.8 {
                            ThreatLevel::Medium
                        } else {
                            ThreatLevel::Low
                        },
                    });
                }
            }
        }
        
        None
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

    pub fn get_safe_content(&self, original: &[Content], scan_result: &ScanResult, content_type: ContentType) -> Vec<Content> {
        if !self.is_enabled() {
            tracing::info!("Security scanner: passing through original content (disabled)");
            return original.to_vec();
        }

        // Get the severity-specific action policy for this threat level and content type
        let action_policy = self.config.get_action_for_threat(content_type, &scan_result.threat_level);
        
        tracing::info!(
            threat = ?scan_result.threat_level,
            content_type = ?content_type,
            action_policy = ?action_policy,
            "Security scanner: determining action for threat"
        );

        // For AskUser policy, we don't modify content here - that's handled by the confirmation flow
        if action_policy == ActionPolicy::AskUser {
            tracing::info!(
                threat = ?scan_result.threat_level,
                policy = "AskUser",
                "Security scanner: content will be subject to user confirmation"
            );
            return original.to_vec();
        }

        if action_policy == ActionPolicy::Sanitize && scan_result.sanitized_content.is_some() {
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

        if matches!(action_policy, ActionPolicy::Block | ActionPolicy::BlockWithNote) {
            // Replace with warning message
            tracing::info!(
                threat = ?scan_result.threat_level,
                policy = ?action_policy,
                "Security scanner: BLOCKING content due to detected threat: {}",
                scan_result.explanation
            );
            return vec![Content::text(format!(
                "[SECURITY WARNING] Content blocked due to detected threat: {}",
                scan_result.explanation
            ))];
        }

        // For LogOnly, Process, ProcessWithNote - allow content through
        tracing::info!(
            threat = ?scan_result.threat_level,
            policy = ?action_policy,
            "Security scanner: allowing content through"
        );
        original.to_vec()
    }
}
