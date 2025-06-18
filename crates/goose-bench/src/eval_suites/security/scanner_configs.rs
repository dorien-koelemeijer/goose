use goose::security::config::{ActionPolicy, EnsembleConfig, EnsembleMember, ScannerType, SecurityConfig, ThreatThreshold, VotingStrategy};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub name: String,
    pub config: SecurityConfig,
}

impl ScannerConfig {
    pub fn get_all_configs() -> Vec<ScannerConfig> {
        // Use fast config for initial testing - just a few models
        Self::get_test_configs()
    }

    /// Quick testing with just the fastest model
    pub fn get_fast_configs() -> Vec<ScannerConfig> {
        vec![
            ScannerConfig {
                name: "protectai-deberta-block-medium-0.8".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ProtectAiDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.8,  // Higher confidence to reduce false positives
                    ensemble_config: None,
                },
            },
        ]
    }

    /// Test configuration with a few key models at different confidence levels
    pub fn get_test_configs() -> Vec<ScannerConfig> {
        vec![
            // Single model tests for comparison
//             ScannerConfig {
//                 name: "deepset-deberta-0.7".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::DeepsetDeberta,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: None,
//                 },
//             },
            // Parallel Ensemble with "Any Detection" strategy (most sensitive)
            ScannerConfig {
                name: "ensemble-any-detection".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ParallelEnsemble,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.7, // Not used for ensemble, but required
                    ensemble_config: Some(EnsembleConfig {
                        voting_strategy: VotingStrategy::AnyDetection,
                        member_configs: vec![
                            EnsembleMember {
                                scanner_type: ScannerType::DeepsetDeberta,
                                confidence_threshold: 0.7,
                                weight: 1.0,
                            },
                            EnsembleMember {
                                scanner_type: ScannerType::ProtectAiDeberta,
                                confidence_threshold: 0.6, // Lower threshold for secondary model
                                weight: 1.0,
                            },
                            EnsembleMember {
                                scanner_type: ScannerType::LlamaPromptGuard2,
                                confidence_threshold: 0.6, // Lower threshold for tertiary model
                                weight: 1.0,
                            },
                        ],
                    }),
                },
            },
            // Parallel Ensemble with "Majority Vote" strategy (more conservative)
            ScannerConfig {
                name: "ensemble-majority-vote".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ParallelEnsemble,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.7,
                    ensemble_config: Some(EnsembleConfig {
                        voting_strategy: VotingStrategy::MajorityVote,
                        member_configs: vec![
                            EnsembleMember {
                                scanner_type: ScannerType::DeepsetDeberta,
                                confidence_threshold: 0.7,
                                weight: 1.0,
                            },
                            EnsembleMember {
                                scanner_type: ScannerType::ProtectAiDeberta,
                                confidence_threshold: 0.7,
                                weight: 1.0,
                            },
                            EnsembleMember {
                                scanner_type: ScannerType::LlamaPromptGuard2,
                                confidence_threshold: 0.7,
                                weight: 1.0,
                            },
                        ],
                    }),
                },
            },
        ]
    }

    /// Comprehensive testing with multiple models and confidence thresholds
    pub fn get_comprehensive_configs() -> Vec<ScannerConfig> {
        vec![
            // ProtectAI DeBERTa with different confidence thresholds
            ScannerConfig {
                name: "protectai-deberta-0.7".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ProtectAiDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.7,
                    ensemble_config: None,
                },
            },
            ScannerConfig {
                name: "protectai-deberta-0.8".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ProtectAiDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.8,
                    ensemble_config: None,
                },
            },
            ScannerConfig {
                name: "protectai-deberta-0.9".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ProtectAiDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.9,
                    ensemble_config: None,
                },
            },
            // Deepset DeBERTa (often better precision)
            ScannerConfig {
                name: "deepset-deberta-0.7".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::DeepsetDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.7,
                    ensemble_config: None,
                },
            },
            ScannerConfig {
                name: "deepset-deberta-0.8".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::DeepsetDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.8,
                    ensemble_config: None,
                },
            },
            // Llama Prompt Guard 2 with higher confidence
            ScannerConfig {
                name: "llama-guard2-0.8".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::LlamaPromptGuard2,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.8,
                    ensemble_config: None,
                },
            },
            // ToxicBERT for comparison
            ScannerConfig {
                name: "toxic-bert-0.8".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ToxicBert,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.8,
                    ensemble_config: None,
                },
            },
        ]
    }
}