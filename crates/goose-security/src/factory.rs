use anyhow::Result;
use async_trait::async_trait;
use rmcp::model::Content;
use std::sync::Arc;

use crate::scanner::SecurityScanner;
use crate::types::{ContentType, ScanResult, SecurityConfig};

/// No-op scanner for when security is disabled
pub struct DisabledScanner;

#[async_trait]
impl SecurityScanner for DisabledScanner {
    async fn scan_content(
        &self,
        _content: &[Content],
        _content_type: ContentType,
    ) -> Result<Option<ScanResult>> {
        Ok(None)
    }

    fn is_enabled(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "Disabled"
    }
}

/// Factory function to create the appropriate scanner based on configuration
pub fn create_scanner(config: SecurityConfig) -> Arc<dyn SecurityScanner> {
    tracing::info!(
        "🏭 Creating scanner with config: enabled={}, models={}",
        config.enabled,
        config.models.len()
    );

    if !config.enabled {
        tracing::info!("🚫 Security disabled, returning DisabledScanner");
        return Arc::new(DisabledScanner);
    }

    if config.models.is_empty() {
        tracing::warn!("⚠️ Security enabled but no models configured, returning DisabledScanner");
        return Arc::new(DisabledScanner);
    }

    // Use the new generic EnsembleScanner
    tracing::info!(
        "🔧 Creating EnsembleScanner with {} models",
        config.models.len()
    );
    match crate::ensemble_scanner::EnsembleScanner::from_config(&config) {
        Ok(scanner) => {
            tracing::info!("✅ EnsembleScanner created successfully");
            Arc::new(scanner)
        }
        Err(e) => {
            tracing::error!("❌ Failed to create EnsembleScanner from config: {}", e);
            tracing::error!("🚫 No fallback available, returning DisabledScanner");
            Arc::new(DisabledScanner)
        }
    }
}
