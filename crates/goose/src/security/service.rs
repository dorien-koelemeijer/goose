use anyhow::Result;
use async_trait::async_trait;
use rmcp::model::Content;
use std::sync::Arc;

use crate::security::config::{ActionPolicy, ContentType, FeedbackType, SecurityNote};
use crate::security::content_scanner::{ScanResult, ThreatLevel};

/// Trait that abstracts security operations to minimize coupling with the rest of the codebase
#[async_trait]
pub trait SecurityService: Send + Sync {
    /// Check if security scanning is enabled
    fn is_enabled(&self) -> bool;
    
    /// Scan content for security threats
    async fn scan_content(&self, content: &[Content]) -> Result<Option<ScanResult>>;
    
    /// Get the action to take for a specific threat level and content type
    fn get_action_for_threat(&self, content_type: ContentType, threat_level: &ThreatLevel) -> ActionPolicy;
    
    /// Create a security note for the UI
    fn create_security_note(&self, scan_result: &ScanResult, content_type: ContentType) -> Option<SecurityNote>;
    
    /// Log user feedback about security decisions
    fn log_user_feedback(&self, feedback_type: FeedbackType, content: &str, finding_id: &str);
    
    /// Determine if content should be blocked based on scan result
    fn should_block(&self, scan_result: &ScanResult) -> bool;
    
    /// Get sanitized version of content (placeholder for future implementation)
    fn get_safe_content(&self, content: &[Content], _scan_result: &ScanResult, _content_type: ContentType) -> Vec<Content>;
}

/// No-op security service for when security is disabled
pub struct DisabledSecurityService;

#[async_trait]
impl SecurityService for DisabledSecurityService {
    fn is_enabled(&self) -> bool {
        false
    }
    
    async fn scan_content(&self, _content: &[Content]) -> Result<Option<ScanResult>> {
        Ok(None)
    }
    
    fn get_action_for_threat(&self, _content_type: ContentType, _threat_level: &ThreatLevel) -> ActionPolicy {
        ActionPolicy::Allow
    }
    
    fn create_security_note(&self, _scan_result: &ScanResult, _content_type: ContentType) -> Option<SecurityNote> {
        None
    }
    
    fn log_user_feedback(&self, _feedback_type: FeedbackType, _content: &str, _finding_id: &str) {
        // No-op
    }
    
    fn should_block(&self, _scan_result: &ScanResult) -> bool {
        false
    }
    
    fn get_safe_content(&self, content: &[Content], _scan_result: &ScanResult, _content_type: ContentType) -> Vec<Content> {
        content.to_vec()
    }
}

/// Factory function to create the appropriate security service
pub fn create_security_service(config: crate::security::config::SecurityConfig) -> Arc<dyn SecurityService> {
    if config.enabled {
        Arc::new(crate::security::SecurityManager::new(config))
    } else {
        Arc::new(DisabledSecurityService)
    }
}