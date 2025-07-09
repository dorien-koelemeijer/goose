use uuid::Uuid;

use crate::security::config::{
    FeedbackType, SecurityNote, ContentType
};
use crate::security::content_scanner::ScanResult;

/// Simple feedback manager that just logs user feedback
#[derive(Clone)]
pub struct SecurityFeedbackManager;

impl SecurityFeedbackManager {
    pub fn new() -> Self {
        Self
    }

    /// Create a security note for display to the user
    pub fn create_security_note(
        &self,
        content_type: ContentType,
        scan_result: &ScanResult,
        action_taken: crate::security::config::ActionPolicy,
        show_feedback_options: bool,
    ) -> SecurityNote {
        // Enhance explanation with feedback message if feedback options are available
        let enhanced_explanation = if show_feedback_options {
            format!(
                "{}\n\n💬 **Feedback options will be available soon** - you'll be able to report if this was incorrectly flagged.",
                scan_result.explanation
            )
        } else {
            scan_result.explanation.clone()
        };

        SecurityNote {
            note_id: Uuid::new_v4().to_string(),
            content_type,
            threat_level: scan_result.threat_level.clone(),
            explanation: enhanced_explanation,
            action_taken,
            show_feedback_options,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Log user feedback (simple logging approach for now)
    pub fn log_user_feedback(
        &self,
        note_id: &str,
        feedback_type: FeedbackType,
        content_type: ContentType,
        threat_level: &crate::security::content_scanner::ThreatLevel,
        user_comment: Option<&str>,
    ) {
        tracing::info!(
            note_id = %note_id,
            feedback_type = ?feedback_type,
            content_type = ?content_type,
            threat_level = ?threat_level,
            user_comment = ?user_comment,
            "User provided security feedback"
        );
    }
}