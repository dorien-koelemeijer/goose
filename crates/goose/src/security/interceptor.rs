/// Security Interceptor - Clean integration layer for security scanning
/// 
/// This module provides a clean way to integrate security scanning into the existing
/// agent workflow without modifying the core agent code extensively.

use anyhow::Result;
use rmcp::model::Content;
use crate::message::Message;
use crate::security::{SecurityManager, config::{ContentType, ActionPolicy}};
use crate::security::content_scanner::{ScanResult, ThreatLevel};

/// Security scan result with action recommendation
#[derive(Debug, Clone)]
pub struct SecurityDecision {
    pub action: SecurityAction,
    pub scan_result: Option<ScanResult>,
    pub security_note: Option<crate::security::config::SecurityNote>,
}

/// Actions the security system recommends
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityAction {
    /// Allow the content to proceed normally
    Allow,
    /// Allow but add a security note to the response
    AllowWithNote,
    /// Block the content entirely
    Block { reason: String },
    /// Ask user for confirmation
    AskUser { threat_details: String },
}

/// Security interceptor that can be easily integrated into existing workflows
pub struct SecurityInterceptor {
    manager: Option<SecurityManager>,
}

impl SecurityInterceptor {
    pub fn new(manager: Option<SecurityManager>) -> Self {
        Self { manager }
    }

    /// Check if security is enabled
    pub fn is_enabled(&self) -> bool {
        self.manager.as_ref().map_or(false, |m| m.is_enabled())
    }

    /// Scan user message and return a decision
    pub async fn scan_user_message(&self, message: &Message) -> Result<SecurityDecision> {
        let Some(manager) = &self.manager else {
            return Ok(SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: None,
                security_note: None,
            });
        };

        // Extract content for scanning
        let content = self.extract_content_for_scanning(message);
        if content.is_empty() {
            return Ok(SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: None,
                security_note: None,
            });
        }

        // Perform the scan
        match manager.scan_content_with_type(&content, ContentType::UserMessage).await? {
            Some(scan_result) => {
                let action_policy = manager.get_action_for_threat(ContentType::UserMessage, &scan_result.threat_level);
                let decision = self.policy_to_action(action_policy, &scan_result);
                
                // Create security note if needed
                let security_note = if matches!(decision.action, SecurityAction::AllowWithNote | SecurityAction::Block { .. }) {
                    manager.create_security_note(&scan_result, ContentType::UserMessage)
                } else {
                    None
                };

                Ok(SecurityDecision {
                    action: decision.action,
                    scan_result: Some(scan_result),
                    security_note,
                })
            }
            None => Ok(SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: None,
                security_note: None,
            }),
        }
    }

    /// Scan tool result and return a decision
    pub async fn scan_tool_result(&self, content: &[Content]) -> Result<SecurityDecision> {
        let Some(manager) = &self.manager else {
            return Ok(SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: None,
                security_note: None,
            });
        };

        match manager.scan_content_with_type(content, ContentType::ToolResult).await? {
            Some(scan_result) => {
                let action_policy = manager.get_action_for_threat(ContentType::ToolResult, &scan_result.threat_level);
                let decision = self.policy_to_action(action_policy, &scan_result);
                
                let security_note = if matches!(decision.action, SecurityAction::AllowWithNote | SecurityAction::Block { .. }) {
                    manager.create_security_note(&scan_result, ContentType::ToolResult)
                } else {
                    None
                };

                Ok(SecurityDecision {
                    action: decision.action,
                    scan_result: Some(scan_result),
                    security_note,
                })
            }
            None => Ok(SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: None,
                security_note: None,
            }),
        }
    }

    /// Convert security policy to action
    fn policy_to_action(&self, policy: ActionPolicy, scan_result: &ScanResult) -> SecurityDecision {
        match policy {
            ActionPolicy::Process => SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            ActionPolicy::ProcessWithNote => SecurityDecision {
                action: SecurityAction::AllowWithNote,
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            ActionPolicy::Block => SecurityDecision {
                action: SecurityAction::Block {
                    reason: format!("Security threat detected: {}", scan_result.explanation),
                },
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            ActionPolicy::BlockWithNote => SecurityDecision {
                action: SecurityAction::Block {
                    reason: format!("Security threat detected: {}", scan_result.explanation),
                },
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            ActionPolicy::AskUser => SecurityDecision {
                action: SecurityAction::AskUser {
                    threat_details: format!("{:?} threat: {}", scan_result.threat_level, scan_result.explanation),
                },
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            ActionPolicy::LogOnly => SecurityDecision {
                action: SecurityAction::Allow,
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
            // Legacy policies
            ActionPolicy::Sanitize | ActionPolicy::Warn => SecurityDecision {
                action: SecurityAction::AllowWithNote,
                scan_result: Some(scan_result.clone()),
                security_note: None,
            },
        }
    }

    /// Extract content from message for scanning
    fn extract_content_for_scanning(&self, message: &Message) -> Vec<Content> {
        let mut content = Vec::new();
        
        for msg_content in &message.content {
            if let Some(text) = msg_content.as_text() {
                content.push(Content::text(text.to_string()));
            }
            // Could add image content extraction here if needed
        }
        
        content
    }

    /// Create a security response message
    pub fn create_security_response(&self, decision: &SecurityDecision) -> Option<Message> {
        match &decision.action {
            SecurityAction::Block { reason } => {
                let mut message = Message::assistant().with_text(format!(
                    "🚨 **Security Alert: Request Blocked**\n\n{}\n\nPlease rephrase your request without potentially harmful content.",
                    reason
                ));

                // Add security note if available
                if let Some(note) = &decision.security_note {
                    message = message.with_security_note(
                        note.finding_id.clone(),
                        format!("{:?}", note.content_type).to_lowercase(),
                        format!("{:?}", note.threat_level).to_lowercase(),
                        note.explanation.clone(),
                        format!("{:?}", note.action_taken).to_lowercase(),
                        note.show_feedback_options,
                        note.timestamp.to_rfc3339(),
                    );
                }

                Some(message)
            }
            SecurityAction::AskUser { threat_details } => {
                // Create a confirmation request
                Some(Message::assistant().with_tool_confirmation_request(
                    format!("sec_{}", nanoid::nanoid!(8)),
                    "security_scanner".to_string(),
                    serde_json::json!({
                        "threat_details": threat_details,
                        "scan_result": decision.scan_result
                    }),
                    Some(format!("🚨 Security Alert: {}\n\nDo you want to proceed?", threat_details)),
                ))
            }
            _ => None,
        }
    }

    /// Create a security note message (for AllowWithNote action)
    pub fn create_security_note_message(&self, decision: &SecurityDecision) -> Option<Message> {
        if let Some(note) = &decision.security_note {
            Some(Message::assistant().with_security_note(
                note.finding_id.clone(),
                format!("{:?}", note.content_type).to_lowercase(),
                format!("{:?}", note.threat_level).to_lowercase(),
                note.explanation.clone(),
                format!("{:?}", note.action_taken).to_lowercase(),
                note.show_feedback_options,
                note.timestamp.to_rfc3339(),
            ))
        } else {
            None
        }
    }
}

/// Helper trait to add security methods to existing types without modification
pub trait SecurityIntegration {
    /// Add security scanning to message processing
    async fn with_security_scan(&self, interceptor: &SecurityInterceptor) -> Result<(SecurityDecision, Option<Message>)>;
}

impl SecurityIntegration for Message {
    async fn with_security_scan(&self, interceptor: &SecurityInterceptor) -> Result<(SecurityDecision, Option<Message>)> {
        let decision = interceptor.scan_user_message(self).await?;
        let response = interceptor.create_security_response(&decision);
        Ok((decision, response))
    }
}

impl SecurityIntegration for Vec<Content> {
    async fn with_security_scan(&self, interceptor: &SecurityInterceptor) -> Result<(SecurityDecision, Option<Message>)> {
        let decision = interceptor.scan_tool_result(self).await?;
        let response = interceptor.create_security_response(&decision);
        Ok((decision, response))
    }
}