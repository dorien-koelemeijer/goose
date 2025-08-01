use std::sync::Arc;
use anyhow::Result;
use rmcp::model::Content;
use tracing::{info, warn, error};

use crate::security::SecurityManager;
use goose_security::{ScanResult, ContentType, ThreatLevel};

/// Helper for integrating security scanning throughout the codebase
/// This provides a simple interface that can be used anywhere content flows
pub struct SecurityIntegration {
    manager: Arc<SecurityManager>,
}

impl SecurityIntegration {
    pub fn new(manager: Arc<SecurityManager>) -> Self {
        Self { manager }
    }

    pub fn disabled() -> Self {
        Self {
            manager: Arc::new(SecurityManager::disabled()),
        }
    }

    /// Scan content and handle the result automatically
    /// Returns Ok(true) if content should be allowed, Ok(false) if blocked
    pub async fn check_and_handle(&self, content: &[Content], content_type: ContentType) -> Result<bool> {
        tracing::info!(
            content_type = ?content_type,
            enabled = self.manager.is_enabled(),
            content_length = content.len(),
            "🚨 SecurityIntegration::check_and_handle called"
        );

        if !self.manager.is_enabled() {
            tracing::info!("🚫 Security manager is disabled, allowing content");
            return Ok(true);
        }

        match self.manager.scan_content_with_type(content, content_type.clone()).await? {
            Some(result) => {
                self.handle_scan_result(&result, &content_type).await;
                Ok(!result.should_block)
            }
            None => {
                tracing::info!(
                    content_type = ?content_type,
                    "⚪ No scan result returned (content type not configured for scanning)"
                );
                Ok(true)
            }
        }
    }

    /// Scan content and return the result for custom handling
    pub async fn scan(&self, content: &[Content], content_type: ContentType) -> Result<Option<ScanResult>> {
        self.manager.scan_content_with_type(content, content_type).await
    }

    /// Handle a scan result (logging, user notifications, etc.)
    async fn handle_scan_result(&self, result: &ScanResult, content_type: &ContentType) {
        match result.threat_level {
            ThreatLevel::Safe => {
                // Log safe results at INFO level so they're always visible
                tracing::info!(
                    threat_level = ?result.threat_level,
                    confidence = result.confidence,
                    content_type = ?content_type,
                    scanner = result.scanner_type,
                    "🔍 Security scan completed (SAFE): {}",
                    result.explanation
                );
            }
            ThreatLevel::Low | ThreatLevel::Medium | ThreatLevel::High | ThreatLevel::Critical => {
                if result.should_warn {
                    warn!(
                        threat_level = ?result.threat_level,
                        confidence = result.confidence,
                        content_type = ?content_type,
                        scanner = result.scanner_type,
                        finding_id = result.finding_id,
                        "🔒 Security threat detected: {}",
                        result.explanation
                    );
                }

                if result.should_block {
                    error!(
                        threat_level = ?result.threat_level,
                        confidence = result.confidence,
                        content_type = ?content_type,
                        scanner = result.scanner_type,
                        finding_id = result.finding_id,
                        "🚫 Content blocked due to security threat: {}",
                        result.explanation
                    );
                } else {
                    info!(
                        "Content allowed but flagged for review. Finding ID: {}",
                        result.finding_id
                    );
                }
            }
        }
    }

    /// Get a user-friendly security message for the UI
    pub fn get_security_message(&self, result: &ScanResult) -> Option<String> {
        if !result.should_warn {
            return None;
        }

        let action = if result.should_block { "blocked" } else { "flagged" };
        let confidence_desc = match result.confidence {
            c if c >= 0.9 => "high confidence",
            c if c >= 0.7 => "medium confidence", 
            _ => "low confidence",
        };

        Some(format!(
            "🔒 Security: Content {} due to potential security threat ({}, {}).\nFinding ID: {} (for feedback)",
            action, confidence_desc, result.scanner_type, result.finding_id
        ))
    }

    pub fn is_enabled(&self) -> bool {
        self.manager.is_enabled()
    }
}

impl Clone for SecurityIntegration {
    fn clone(&self) -> Self {
        Self {
            manager: Arc::clone(&self.manager),
        }
    }
}