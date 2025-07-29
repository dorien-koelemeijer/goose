use anyhow::Result;
use async_trait::async_trait;
use rmcp::model::Content;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct ScanResult {
    pub threat_level: ThreatLevel,
    pub confidence: f32, // Confidence score (0.0-1.0)
    pub explanation: String,
    pub sanitized_content: Option<Vec<Content>>, // Optional sanitized version
}

impl ScanResult {
    /// Create a ScanResult with default confidence based on threat level
    pub fn new(threat_level: ThreatLevel, explanation: String) -> Self {
        let confidence = match threat_level {
            ThreatLevel::Safe => 0.1,
            ThreatLevel::Low => 0.4,
            ThreatLevel::Medium => 0.7,
            ThreatLevel::High => 0.9,
            ThreatLevel::Critical => 0.95,
        };
        
        Self {
            threat_level,
            confidence,
            explanation,
            sanitized_content: None,
        }
    }

    /// Create a ScanResult with explicit confidence
    pub fn with_confidence(threat_level: ThreatLevel, confidence: f32, explanation: String) -> Self {
        Self {
            threat_level,
            confidence,
            explanation,
            sanitized_content: None,
        }
    }
}

#[async_trait]
pub trait ContentScanner: Send + Sync {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult>;
    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult>;
}
