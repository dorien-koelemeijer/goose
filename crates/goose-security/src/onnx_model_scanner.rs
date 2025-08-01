#[cfg(feature = "onnx")]
use async_trait::async_trait;
use anyhow::Result;
use crate::model_scanner::ModelScanner;
use crate::scanner::SecurityScanner;  // Add this import
use crate::types::{ScanResult, ContentType, ModelConfig, ThreatLevel, ResponseMode};

#[cfg(not(feature = "onnx"))]
use async_trait::async_trait;

#[cfg(feature = "onnx")]
pub struct OnnxModelScanner {
    model_config: ModelConfig,
    response_mode: ResponseMode,
    name: String,
    // Internal ONNX-specific fields would go here
}

#[cfg(feature = "onnx")]
impl OnnxModelScanner {
    pub fn new(model_config: ModelConfig, response_mode: ResponseMode) -> Result<Self> {
        let name = format!("ONNX-{}", model_config.model.replace("/", "-"));
        
        Ok(Self {
            model_config,
            response_mode,
            name,
        })
    }
    
    async fn analyze_text_with_threshold(&self, text: &str, content_type: ContentType, threshold: f32) -> Result<ScanResult> {
        // This would contain the actual ONNX inference logic
        // For now, let's create a placeholder that delegates to the existing OnnxScanner
        
        // Import the existing ONNX implementation
        let scanner = crate::onnx::OnnxScanner::from_config(&self.model_config, self.response_mode.clone())?;
        let content = vec![rmcp::model::Content::text(text)];
        
        match scanner.scan_content(&content, content_type.clone()).await? {
            Some(result) => Ok(result),
            None => Ok(ScanResult::safe(self.name.clone(), content_type)),
        }
    }
}

#[cfg(feature = "onnx")]
#[async_trait]
impl ModelScanner for OnnxModelScanner {
    async fn scan_text(&self, text: &str, content_type: ContentType) -> Result<ScanResult> {
        let threshold = self.get_threshold_for_content_type(&content_type);
        self.analyze_text_with_threshold(text, content_type, threshold).await
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn is_enabled(&self) -> bool {
        true
    }
    
    fn weight(&self) -> f32 {
        self.model_config.weight.unwrap_or(1.0)
    }
    
    fn should_scan_content_type(&self, content_type: &ContentType) -> bool {
        self.model_config.should_scan_content_type(content_type)
    }
    
    fn get_threshold_for_content_type(&self, content_type: &ContentType) -> f32 {
        self.model_config.get_threshold_for_content_type(content_type)
    }
}

// Stub implementation when ONNX feature is not enabled
#[cfg(not(feature = "onnx"))]
pub struct OnnxModelScanner;

#[cfg(not(feature = "onnx"))]
impl OnnxModelScanner {
    pub fn new(_model_config: ModelConfig, _response_mode: ResponseMode) -> Result<Self> {
        Err(anyhow::anyhow!("ONNX scanner not available (onnx feature not enabled)"))
    }
}

#[cfg(not(feature = "onnx"))]
#[async_trait]
impl ModelScanner for OnnxModelScanner {
    async fn scan_text(&self, _text: &str, _content_type: ContentType) -> Result<ScanResult> {
        Err(anyhow::anyhow!("ONNX scanner not available (onnx feature not enabled)"))
    }
    
    fn name(&self) -> &str {
        "ONNX-Disabled"
    }
    
    fn is_enabled(&self) -> bool {
        false
    }
    
    fn weight(&self) -> f32 {
        0.0
    }
    
    fn should_scan_content_type(&self, _content_type: &ContentType) -> bool {
        false
    }
    
    fn get_threshold_for_content_type(&self, _content_type: &ContentType) -> f32 {
        0.0
    }
}