use anyhow::Result;
use async_trait::async_trait;
use rmcp::model::Content;

use crate::types::{ContentType, ScanResult};

/// Core security scanner trait - completely abstracted from the main codebase
#[async_trait]
pub trait SecurityScanner: Send + Sync {
    /// Scan content for security threats
    async fn scan_content(
        &self,
        content: &[Content],
        content_type: ContentType,
    ) -> Result<Option<ScanResult>>;

    /// Check if the scanner is enabled
    fn is_enabled(&self) -> bool;

    /// Get scanner name for identification
    fn name(&self) -> &str;
}
