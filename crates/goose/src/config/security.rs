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
                user_messages: None,
                file_content: None,
                tool_results: None,
                extensions: None,
                agent_responses: None,
            };
        }
        
        // Hardcoded security policies - controlled by security engineers, not users
        SecurityConfig {
            enabled: true,
            scanner_type: ScannerType::ParallelEnsemble,
            ollama_endpoint: "http://localhost:11434".to_string(),
            action_policy: ActionPolicy::ProcessWithNote, // Default fallback
            scan_threshold: ThreatThreshold::Medium,
            confidence_threshold: 0.5,
            ensemble_config: Some(EnsembleConfig {
                voting_strategy: VotingStrategy::WeightedVote,
                member_configs: vec![
                    EnsembleMember {
                        scanner_type: ScannerType::RustDeepsetDeberta,
                        confidence_threshold: 0.95, // Much higher - only flag when extremely confident
                        weight: 0.1, // Very low weight - minimal influence on final decision
                    },
                    EnsembleMember {
                        scanner_type: ScannerType::RustProtectAiDeberta,
                        confidence_threshold: 0.5, // Keep reasonable threshold
                        weight: 0.9, // High weight - ProtectAI drives the decision
                    },
                ],
                max_scan_time_ms: Some(800),
                min_models_required: Some(1),
                early_exit_threshold: Some(0.8),
            }),
            hybrid_config: None,
            
            // Hardcoded content-type-specific policies
            user_messages: Some(ContentTypeConfig {
                confidence_threshold: None, // Use global default (0.5)
                scan_threshold: None, // Use global default
                action_policy: None, // Use severity-specific policies
                low_action: Some(ActionPolicy::Process),
                medium_action: Some(ActionPolicy::ProcessWithNote),
                high_action: Some(ActionPolicy::BlockWithNote),
                critical_action: Some(ActionPolicy::Block),
            }),
            
            file_content: Some(ContentTypeConfig {
                confidence_threshold: Some(0.45), // Slightly more sensitive for files but not too low
                scan_threshold: None, // Use global default
                action_policy: None, // Use severity-specific policies
                low_action: Some(ActionPolicy::ProcessWithNote),
                medium_action: Some(ActionPolicy::BlockWithNote),
                high_action: Some(ActionPolicy::BlockWithNote),
                critical_action: Some(ActionPolicy::BlockWithNote),
            }),
            
            tool_results: Some(ContentTypeConfig {
                confidence_threshold: Some(0.4), // Reasonable threshold for tool results
                scan_threshold: None, // Use global default
                action_policy: None, // Use severity-specific policies
                low_action: Some(ActionPolicy::Process),
                medium_action: Some(ActionPolicy::BlockWithNote),
                high_action: Some(ActionPolicy::BlockWithNote),
                critical_action: Some(ActionPolicy::BlockWithNote),
            }),
            
            extensions: Some(ContentTypeConfig {
                confidence_threshold: Some(0.5), // Keep extensions sensitive but reasonable
                scan_threshold: Some(ThreatThreshold::Low),
                action_policy: None, // Use severity-specific policies
                low_action: Some(ActionPolicy::BlockWithNote),
                medium_action: Some(ActionPolicy::Block),
                high_action: Some(ActionPolicy::Block),
                critical_action: Some(ActionPolicy::Block),
            }),
            
            agent_responses: Some(ContentTypeConfig {
                confidence_threshold: Some(0.75), // Less sensitive for agent responses
                scan_threshold: Some(ThreatThreshold::High),
                action_policy: None, // Use severity-specific policies
                low_action: Some(ActionPolicy::Process),
                medium_action: Some(ActionPolicy::Process),
                high_action: Some(ActionPolicy::ProcessWithNote),
                critical_action: Some(ActionPolicy::LogOnly),
            }),
        }
    }
}