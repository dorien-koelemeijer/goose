use async_trait::async_trait;
use anyhow::Result;
use rmcp::model::Content;
use crate::types::{ScanResult, ContentType};

/// Generic trait for all model scanners (ONNX, API-based, etc.)
#[async_trait]
pub trait ModelScanner: Send + Sync {
    /// Scan text content and return a result
    async fn scan_text(&self, text: &str, content_type: ContentType) -> Result<ScanResult>;
    
    /// Get the scanner name for identification
    fn name(&self) -> &str;
    
    /// Check if this scanner is enabled and ready
    fn is_enabled(&self) -> bool;
    
    /// Get the weight for ensemble scoring
    fn weight(&self) -> f32;
    
    /// Check if this scanner should scan the given content type
    fn should_scan_content_type(&self, content_type: &ContentType) -> bool;
    
    /// Get the effective threshold for this content type
    fn get_threshold_for_content_type(&self, content_type: &ContentType) -> f32;
}

/// Helper function to extract text from Content array
pub fn extract_text_content(content: &[Content]) -> String {
    content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .collect::<Vec<_>>()
        .join(" ")
}