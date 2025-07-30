use std::sync::Arc;
use rmcp::model::Content;
use anyhow::Result;

use crate::security::service::{SecurityService, create_security_service};
use crate::security::config::{SecurityConfig, ContentType, FeedbackType};
use crate::security::content_scanner::ScanResult;

/// Simple wrapper around SecurityService that provides a clean interface for the agent
pub struct SecurityWrapper {
    service: Arc<dyn SecurityService>,
}

impl SecurityWrapper {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            service: create_security_service(config),
        }
    }
    
    pub fn is_enabled(&self) -> bool {
        self.service.is_enabled()
    }
    
    pub async fn scan_user_message(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.service.scan_content(content).await
    }
    
    pub async fn scan_tool_result(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.service.scan_content(content).await
    }
    
    pub fn should_block_user_message(&self, scan_result: &ScanResult) -> bool {
        let action = self.service.get_action_for_threat(ContentType::UserMessage, &scan_result.threat_level);
        matches!(action, crate::security::config::ActionPolicy::Block | crate::security::config::ActionPolicy::BlockWithNote)
    }
    
    pub fn should_block_tool_result(&self, scan_result: &ScanResult) -> bool {
        let action = self.service.get_action_for_threat(ContentType::ToolResult, &scan_result.threat_level);
        matches!(action, crate::security::config::ActionPolicy::Block | crate::security::config::ActionPolicy::BlockWithNote)
    }
    
    pub fn create_user_message_note(&self, scan_result: &ScanResult) -> Option<crate::security::config::SecurityNote> {
        self.service.create_security_note(scan_result, ContentType::UserMessage)
    }
    
    pub fn create_tool_result_note(&self, scan_result: &ScanResult) -> Option<crate::security::config::SecurityNote> {
        self.service.create_security_note(scan_result, ContentType::ToolResult)
    }
    
    pub fn log_user_feedback(&self, feedback_type: FeedbackType, content: &str, finding_id: &str) {
        self.service.log_user_feedback(feedback_type, content, finding_id);
    }
}

impl Clone for SecurityWrapper {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}