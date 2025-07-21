use uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::collections::HashMap;

use crate::security::config::{
    FeedbackType, SecurityNote, ContentType
};
use crate::security::content_scanner::ScanResult;

/// Training data entry for model fine-tuning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingDataEntry {
    pub finding_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub content_type: ContentType,
    pub content_text: String,
    pub original_threat_level: crate::security::content_scanner::ThreatLevel,
    pub original_confidence: f32,
    pub original_explanation: String,
    pub action_taken: crate::security::config::ActionPolicy,
    pub feedback_type: Option<FeedbackType>,
    pub user_comment: Option<String>,
    pub corrected_label: Option<bool>, // true = threat, false = safe, None = no feedback yet
}

/// Simple feedback manager that logs and stores training data
#[derive(Clone)]
pub struct SecurityFeedbackManager {
    training_data_path: String,
}

impl SecurityFeedbackManager {
    pub fn new() -> Self {
        Self {
            training_data_path: "security_training_data.jsonl".to_string(),
        }
    }

    pub fn with_training_data_path(path: String) -> Self {
        Self {
            training_data_path: path,
        }
    }

    /// Create a security note for display to the user and store initial training data
    pub fn create_security_note(
        &self,
        content_type: ContentType,
        scan_result: &ScanResult,
        action_taken: crate::security::config::ActionPolicy,
        show_feedback_options: bool,
        content_text: &str, // Add content text for training data
    ) -> SecurityNote {
        // Enhance explanation with feedback message if feedback options are available
        let enhanced_explanation = if show_feedback_options {
            format!(
                "{}\n\n💬 **Feedback options available!**",
                scan_result.explanation
            )
        } else {
            scan_result.explanation.clone()
        };

        let security_note = SecurityNote {
            finding_id: Uuid::new_v4().to_string(),
            content_type,
            threat_level: scan_result.threat_level.clone(),
            explanation: enhanced_explanation,
            action_taken: action_taken.clone(),
            show_feedback_options,
            timestamp: chrono::Utc::now(),
        };

        // Create initial training data entry
        let training_entry = TrainingDataEntry {
            finding_id: security_note.finding_id.clone(),
            timestamp: security_note.timestamp,
            content_type,
            content_text: content_text.to_string(),
            original_threat_level: scan_result.threat_level.clone(),
            original_confidence: scan_result.confidence,
            original_explanation: scan_result.explanation.clone(),
            action_taken: action_taken.clone(),
            feedback_type: None, // Will be updated when user provides feedback
            user_comment: None,
            corrected_label: None, // Will be set based on feedback
        };

        // Store training data
        if let Err(e) = self.store_training_data(&training_entry) {
            tracing::error!("Failed to store training data: {}", e);
        }

        // Log the initial security finding
        tracing::info!(
            finding_id = %security_note.finding_id,
            content_type = ?content_type,
            threat_level = ?scan_result.threat_level,
            action_taken = ?action_taken,
            confidence = scan_result.confidence,
            explanation = %scan_result.explanation,
            show_feedback_options = show_feedback_options,
            "Security finding created and stored for training"
        );

        security_note
    }

    /// Update training data with user feedback
    pub fn log_user_feedback(
        &self,
        finding_id: &str,
        feedback_type: FeedbackType,
        content_type: ContentType,
        threat_level: &crate::security::content_scanner::ThreatLevel,
        user_comment: Option<&str>,
    ) {
        // Determine corrected label based on feedback type
        let corrected_label = match feedback_type {
            FeedbackType::FalsePositive => Some(false), // Model said threat, user says safe
            FeedbackType::MissedThreat => Some(true),   // Model said safe, user says threat
            FeedbackType::CorrectFlag => None,          // Model was correct, no correction needed
            FeedbackType::Other => None,                // General feedback, no specific correction
        };

        // Try to update existing entry in-place by reading, modifying, and rewriting
        if let Err(e) = self.update_training_data_with_feedback(finding_id, feedback_type.clone(), user_comment, corrected_label) {
            tracing::error!("Failed to update existing training data with feedback: {}", e);
            
            // Fallback: create a new feedback-only entry
            let feedback_entry = TrainingDataEntry {
                finding_id: finding_id.to_string(),
                timestamp: chrono::Utc::now(),
                content_type,
                content_text: String::new(), // Will be merged later during export
                original_threat_level: threat_level.clone(),
                original_confidence: 0.0, // Will be merged later during export
                original_explanation: String::new(), // Will be merged later during export
                action_taken: crate::security::config::ActionPolicy::Process, // Placeholder
                feedback_type: Some(feedback_type.clone()),
                user_comment: user_comment.map(|s| s.to_string()),
                corrected_label,
            };

            if let Err(e) = self.store_training_data(&feedback_entry) {
                tracing::error!("Failed to store fallback feedback training data: {}", e);
            }
        }

        tracing::info!(
            finding_id = %finding_id,
            feedback_type = ?feedback_type,
            content_type = ?content_type,
            threat_level = ?threat_level,
            user_comment = ?user_comment,
            corrected_label = ?corrected_label,
            "User feedback stored for model training"
        );
    }

    /// Update existing training data entry with user feedback
    fn update_training_data_with_feedback(
        &self,
        finding_id: &str,
        feedback_type: FeedbackType,
        user_comment: Option<&str>,
        corrected_label: Option<bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        // Read all entries
        let file = File::open(&self.training_data_path)?;
        let reader = BufReader::new(file);
        
        let mut entries = Vec::new();
        let mut updated = false;
        
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                let mut entry: TrainingDataEntry = serde_json::from_str(&line)?;
                
                // Update the matching entry
                if entry.finding_id == finding_id && entry.feedback_type.is_none() {
                    entry.feedback_type = Some(feedback_type.clone());
                    entry.user_comment = user_comment.map(|s| s.to_string());
                    entry.corrected_label = corrected_label;
                    updated = true;
                }
                
                entries.push(entry);
            }
        }
        
        if !updated {
            return Err("No matching entry found to update".into());
        }
        
        // Rewrite the file with updated entries
        let mut file = std::fs::File::create(&self.training_data_path)?;
        for entry in entries {
            let json_line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", json_line)?;
        }
        
        Ok(())
    }

    /// Store training data entry to JSONL file
    fn store_training_data(&self, entry: &TrainingDataEntry) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.training_data_path)?;
        
        let json_line = serde_json::to_string(entry)?;
        writeln!(file, "{}", json_line)?;
        
        Ok(())
    }

    /// Export training data for model fine-tuning
    pub fn export_training_data(&self) -> Result<Vec<TrainingDataEntry>, Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(&self.training_data_path)?;
        let reader = BufReader::new(file);
        
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                let entry: TrainingDataEntry = serde_json::from_str(&line)?;
                entries.push(entry);
            }
        }
        
        Ok(entries)
    }

    /// Export training data in HuggingFace format for fine-tuning
    pub fn export_huggingface_training_data(&self, output_path: &str) -> Result<HuggingFaceExportStats, Box<dyn std::error::Error>> {
        let entries = self.export_training_data()?;
        
        // Group entries by finding_id to merge original findings with feedback
        let mut grouped_entries: HashMap<String, Vec<TrainingDataEntry>> = HashMap::new();
        for entry in entries {
            grouped_entries.entry(entry.finding_id.clone()).or_default().push(entry);
        }
        
        let mut hf_entries = Vec::new();
        let mut stats = HuggingFaceExportStats::default();
        
        for (_finding_id, mut entries_for_finding) in grouped_entries {
            // Sort by timestamp to get original entry first
            entries_for_finding.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            
            if let Some(original_entry) = entries_for_finding.first() {
                // Find the feedback entry (if any)
                let feedback_entry = entries_for_finding.iter()
                    .find(|e| e.feedback_type.is_some());
                
                // Create HuggingFace training entry
                let hf_entry = self.create_huggingface_entry(original_entry, feedback_entry)?;
                
                // Update stats
                match hf_entry.label {
                    0 => stats.safe_samples += 1,
                    1 => stats.threat_samples += 1,
                    _ => {}
                }
                
                match feedback_entry {
                    Some(fb) => {
                        stats.with_feedback += 1;
                        match fb.feedback_type.as_ref().unwrap() {
                            FeedbackType::FalsePositive => stats.false_positives += 1,
                            FeedbackType::MissedThreat => stats.missed_threats += 1,
                            FeedbackType::CorrectFlag => stats.correct_flags += 1,
                            FeedbackType::Other => {}, // Don't count "Other" in specific categories
                        }
                    }
                    None => stats.without_feedback += 1,
                }
                
                hf_entries.push(hf_entry);
            }
        }
        
        stats.total_samples = hf_entries.len();
        
        // Write to JSONL file
        let mut file = std::fs::File::create(output_path)?;
        for entry in hf_entries {
            let json_line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", json_line)?;
        }
        
        Ok(stats)
    }

    /// Create a HuggingFace-compatible training entry
    fn create_huggingface_entry(
        &self,
        original: &TrainingDataEntry,
        feedback: Option<&TrainingDataEntry>,
    ) -> Result<HuggingFaceTrainingEntry, Box<dyn std::error::Error>> {
        // Determine the correct label
        let label = if let Some(feedback) = feedback {
            // Use corrected label from feedback
            match feedback.corrected_label {
                Some(true) => 1,   // Threat
                Some(false) => 0,  // Safe
                None => {
                    // CorrectFlag - use original model prediction
                    match original.original_threat_level {
                        crate::security::content_scanner::ThreatLevel::Safe => 0,
                        _ => 1,
                    }
                }
            }
        } else {
            // No feedback - use original model prediction
            match original.original_threat_level {
                crate::security::content_scanner::ThreatLevel::Safe => 0,
                _ => 1,
            }
        };
        
        // Create metadata
        let metadata = HuggingFaceMetadata {
            finding_id: original.finding_id.clone(),
            content_type: original.content_type.clone(),
            original_threat_level: original.original_threat_level.clone(),
            original_confidence: original.original_confidence,
            has_feedback: feedback.is_some(),
            feedback_type: feedback.and_then(|f| f.feedback_type.clone()),
            user_comment: feedback.and_then(|f| f.user_comment.clone()),
            timestamp: original.timestamp,
        };
        
        Ok(HuggingFaceTrainingEntry {
            text: original.content_text.clone(),
            label,
            metadata,
        })
    }

    /// Export only entries with user feedback for focused fine-tuning
    pub fn export_feedback_only_training_data(&self, output_path: &str) -> Result<HuggingFaceExportStats, Box<dyn std::error::Error>> {
        let entries = self.export_training_data()?;
        
        // Group entries by finding_id
        let mut grouped_entries: HashMap<String, Vec<TrainingDataEntry>> = HashMap::new();
        for entry in entries {
            grouped_entries.entry(entry.finding_id.clone()).or_default().push(entry);
        }
        
        let mut hf_entries = Vec::new();
        let mut stats = HuggingFaceExportStats::default();
        
        for (_, mut entries_for_finding) in grouped_entries {
            entries_for_finding.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            
            if let Some(original_entry) = entries_for_finding.first() {
                // Only include entries that have feedback
                if let Some(feedback_entry) = entries_for_finding.iter().find(|e| e.feedback_type.is_some()) {
                    let hf_entry = self.create_huggingface_entry(original_entry, Some(feedback_entry))?;
                    
                    // Update stats
                    match hf_entry.label {
                        0 => stats.safe_samples += 1,
                        1 => stats.threat_samples += 1,
                        _ => {}
                    }
                    
                    stats.with_feedback += 1;
                    match feedback_entry.feedback_type.as_ref().unwrap() {
                        FeedbackType::FalsePositive => stats.false_positives += 1,
                        FeedbackType::MissedThreat => stats.missed_threats += 1,
                        FeedbackType::CorrectFlag => stats.correct_flags += 1,
                        FeedbackType::Other => {}, // Don't count "Other" in specific categories
                    }
                    
                    hf_entries.push(hf_entry);
                }
            }
        }
        
        stats.total_samples = hf_entries.len();
        
        // Write to JSONL file
        let mut file = std::fs::File::create(output_path)?;
        for entry in hf_entries {
            let json_line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", json_line)?;
        }
        
        Ok(stats)
    }
}

/// HuggingFace-compatible training entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuggingFaceTrainingEntry {
    pub text: String,
    pub label: i32, // 0 = safe, 1 = threat
    pub metadata: HuggingFaceMetadata,
}

/// Metadata for HuggingFace training entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuggingFaceMetadata {
    pub finding_id: String,
    pub content_type: ContentType,
    pub original_threat_level: crate::security::content_scanner::ThreatLevel,
    pub original_confidence: f32,
    pub has_feedback: bool,
    pub feedback_type: Option<FeedbackType>,
    pub user_comment: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Statistics from HuggingFace export
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HuggingFaceExportStats {
    pub total_samples: usize,
    pub safe_samples: usize,
    pub threat_samples: usize,
    pub with_feedback: usize,
    pub without_feedback: usize,
    pub false_positives: usize,
    pub missed_threats: usize,
    pub correct_flags: usize,
}