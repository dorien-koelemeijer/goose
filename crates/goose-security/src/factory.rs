use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use rmcp::model::Content;

use crate::types::{ScanResult, SecurityConfig, ContentType, ThreatLevel, ResponseMode};
use crate::scanner::SecurityScanner;

/// No-op scanner for when security is disabled
pub struct DisabledScanner;

#[async_trait]
impl SecurityScanner for DisabledScanner {
    async fn scan_content(&self, _content: &[Content], _content_type: ContentType) -> Result<Option<ScanResult>> {
        Ok(None)
    }
    
    fn is_enabled(&self) -> bool {
        false
    }
    
    fn name(&self) -> &str {
        "Disabled"
    }
}

/// Simple pattern-based scanner for testing and fallback
pub struct SimpleScanner {
    confidence_threshold: f32,
    response_mode: ResponseMode,
}

impl SimpleScanner {
    pub fn new(confidence_threshold: f32, response_mode: ResponseMode) -> Self {
        Self {
            confidence_threshold,
            response_mode,
        }
    }
}

#[async_trait]
impl SecurityScanner for SimpleScanner {
    async fn scan_content(&self, content: &[Content], content_type: ContentType) -> Result<Option<ScanResult>> {
        // Extract text content
        let text_content = content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join(" ");

        if text_content.is_empty() {
            return Ok(Some(ScanResult::safe("SimpleScanner".to_string(), content_type)));
        }

        // Simple pattern matching for demonstration
        let suspicious_patterns = [
            "ignore previous instructions",
            "system prompt",
            "you are now",
            "forget everything",
            "new instructions",
            "disregard",
            "override",
            "jailbreak",
        ];

        for pattern in &suspicious_patterns {
            if text_content.to_lowercase().contains(pattern) {
                let confidence = 0.8; // Fixed confidence for pattern matching
                
                // Determine warning/blocking based on response mode
                let (should_warn, should_block) = match self.response_mode {
                    ResponseMode::Warn => (true, false),
                    ResponseMode::Block => (true, true),
                };

                return Ok(Some(ScanResult::threat(
                    ThreatLevel::Medium,
                    confidence,
                    format!("Detected suspicious pattern: '{}'", pattern),
                    "SimpleScanner".to_string(),
                    content_type,
                    should_warn,
                    should_block,
                )));
            }
        }

        Ok(Some(ScanResult::safe("SimpleScanner".to_string(), content_type)))
    }
    
    fn is_enabled(&self) -> bool {
        true
    }
    
    fn name(&self) -> &str {
        "SimpleScanner"
    }
}

/// Factory function to create the appropriate scanner based on configuration
pub fn create_scanner(config: SecurityConfig) -> Arc<dyn SecurityScanner> {
    tracing::info!("🏭 Creating scanner with config: enabled={}, models={}", 
        config.enabled, config.models.len());
    
    if !config.enabled {
        tracing::info!("🚫 Security disabled, returning DisabledScanner");
        return Arc::new(DisabledScanner);
    }

    // Use the new config-driven ONNX scanner
    #[cfg(feature = "onnx")]
    {
        tracing::info!("🔧 ONNX feature enabled, creating DualOnnxScanner");
        match crate::onnx::DualOnnxScanner::from_config(&config) {
            Ok(scanner) => {
                tracing::info!("✅ DualOnnxScanner created successfully");
                Arc::new(scanner)
            },
            Err(e) => {
                tracing::error!("❌ Failed to create ONNX scanner from config: {}, falling back to SimpleScanner", e);
                Arc::new(SimpleScanner::new(config.confidence_threshold(), config.response_mode()))
            }
        }
    }
    
    #[cfg(not(feature = "onnx"))]
    {
        tracing::warn!("⚠️ ONNX scanner requested but onnx feature not enabled, falling back to SimpleScanner");
        Arc::new(SimpleScanner::new(config.confidence_threshold(), config.response_mode()))
    }
}