use anyhow::Result;
use async_trait::async_trait;
use mcp_core::Content;
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
    pub explanation: String,
    pub sanitized_content: Option<Vec<Content>>, // Optional sanitized version
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
