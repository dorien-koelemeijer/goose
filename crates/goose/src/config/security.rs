use serde::{Deserialize, Serialize};

/// Security configuration settings that can be set via config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Whether security scanning is enabled
    #[serde(default)]
    pub enabled: bool,
    
    /// Confidence threshold for threat detection (0.0-1.0)
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,
    
    /// Deepset DeBERTa model confidence threshold
    #[serde(default = "default_deepset_threshold")]
    pub deepset_threshold: f32,
    
    /// ProtectAI DeBERTa model confidence threshold  
    #[serde(default = "default_protectai_threshold")]
    pub protectai_threshold: f32,
    
    /// Threat threshold level (Any, Low, Medium, High, Critical)
    #[serde(default = "default_threat_threshold")]
    pub threat_threshold: String,
}

fn default_confidence_threshold() -> f32 { 0.5 }
fn default_deepset_threshold() -> f32 { 0.7 }
fn default_protectai_threshold() -> f32 { 0.5 }
fn default_threat_threshold() -> String { "Medium".to_string() }

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            confidence_threshold: default_confidence_threshold(),
            deepset_threshold: default_deepset_threshold(),
            protectai_threshold: default_protectai_threshold(),
            threat_threshold: default_threat_threshold(),
        }
    }
}

impl SecuritySettings {
    /// Convert settings to the internal SecurityConfig used by the security system
    pub fn to_security_config(&self) -> crate::security::config::SecurityConfig {
        use crate::security::config::*;
        
        if !self.enabled {
            return SecurityConfig {
                enabled: false,
                scanner_type: ScannerType::None,
                ollama_endpoint: "http://localhost:11434".to_string(),
                action_policy: ActionPolicy::LogOnly,
                scan_threshold: ThreatThreshold::Medium,
                confidence_threshold: 0.7,
                ensemble_config: None,
                hybrid_config: None,
            };
        }
        
        // Parse threat threshold
        let scan_threshold = match self.threat_threshold.to_lowercase().as_str() {
            "any" => ThreatThreshold::Any,
            "low" => ThreatThreshold::Low,
            "medium" => ThreatThreshold::Medium,
            "high" => ThreatThreshold::High,
            "critical" => ThreatThreshold::Critical,
            _ => ThreatThreshold::Medium, // Default fallback
        };
        
        // When enabled, use ONNX ensemble with configurable thresholds
        SecurityConfig {
            enabled: true,
            scanner_type: ScannerType::ParallelEnsemble,
            ollama_endpoint: "http://localhost:11434".to_string(),
            action_policy: ActionPolicy::AskUser, // Ask user for confirmation on threats
            scan_threshold,
            confidence_threshold: self.confidence_threshold,
            ensemble_config: Some(EnsembleConfig {
                voting_strategy: VotingStrategy::WeightedVote, // Use weighted voting to favor ProtectAI
                member_configs: vec![
                    EnsembleMember {
                        scanner_type: ScannerType::RustDeepsetDeberta,
                        confidence_threshold: self.deepset_threshold,
                        weight: 0.1, // Very low weight - only contributes when ProtectAI is uncertain
                    },
                    EnsembleMember {
                        scanner_type: ScannerType::RustProtectAiDeberta,
                        confidence_threshold: self.protectai_threshold,
                        weight: 0.9, // Dominant weight - ProtectAI drives the decision
                    },
                ],
                max_scan_time_ms: Some(800),     // 800ms timeout
                min_models_required: Some(1),    // At least one model must respond
                early_exit_threshold: Some(0.8), // Early exit threshold
            }),
            hybrid_config: None, // No hybrid configuration
        }
    }
}