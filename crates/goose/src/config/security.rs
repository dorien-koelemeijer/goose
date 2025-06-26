use serde::{Deserialize, Serialize};

/// Security configuration settings that can be set via config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Whether security scanning is enabled
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            enabled: false,
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
        
        // When enabled, always use ONNX ensemble with Deepset + ProtectAI DeBERTa
        SecurityConfig {
            enabled: true,
            scanner_type: ScannerType::ParallelEnsemble,
            ollama_endpoint: "http://localhost:11434".to_string(),
            action_policy: ActionPolicy::AskUser, // Ask user for confirmation on threats
            scan_threshold: ThreatThreshold::Medium, // Medium and above threats
            confidence_threshold: 0.7, // 70% confidence threshold
            ensemble_config: Some(EnsembleConfig {
                voting_strategy: VotingStrategy::AnyDetection, // Flag if any model detects threat
                member_configs: vec![
                    EnsembleMember {
                        scanner_type: ScannerType::RustDeepsetDeberta,
                        confidence_threshold: 0.7,
                        weight: 1.0,
                    },
                    EnsembleMember {
                        scanner_type: ScannerType::RustProtectAiDeberta,
                        confidence_threshold: 0.7,
                        weight: 1.0,
                    },
                ],
                max_scan_time_ms: Some(800),     // 800ms timeout
                min_models_required: Some(1),    // At least one model must respond
                early_exit_threshold: Some(0.9), // If one model is very confident, exit early
            }),
            hybrid_config: None, // No hybrid configuration
        }
    }
}