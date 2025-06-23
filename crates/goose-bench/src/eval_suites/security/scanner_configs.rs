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
                    hybrid_config: None,
                },
            },
        ]
    }

    /// Test configuration with individual ONNX scanners and ensembles
    pub fn get_test_configs() -> Vec<ScannerConfig> {
        vec![
            // Individual ONNX scanners
//             ScannerConfig {
//                 name: "onnx-deepset-deberta-0.7".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::RustDeepsetDeberta,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: None,
//                     hybrid_config: None,
//                 },
//             },
//             ScannerConfig {
//                 name: "onnx-protectai-deberta-0.7".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::RustProtectAiDeberta,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: None,
//                     hybrid_config: None,
//                 },
//             },
            // ONNX Ensemble with both models
            ScannerConfig {
                name: "onnx-ensemble-deepset-and-protectai-deberta".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ParallelEnsemble,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                    confidence_threshold: 0.7,
                    ensemble_config: Some(EnsembleConfig {
                        voting_strategy: VotingStrategy::AnyDetection,
                        max_scan_time_ms: Some(200),     // Fast timeout since ONNX is fast
                        min_models_required: Some(1),    // At least 1 model
                        early_exit_threshold: Some(0.9), // If model is >90% confident, exit early
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
                    }),
                    hybrid_config: None,
                },
            },
            // ONNX Ensemble with Majority Vote
//             ScannerConfig {
//                 name: "onnx-ensemble-majority-vote-deepset-and-protectai-deberta".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::ParallelEnsemble,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: Some(EnsembleConfig {
//                         voting_strategy: VotingStrategy::MajorityVote,
//                         max_scan_time_ms: Some(200),
//                         min_models_required: Some(2),
//                         early_exit_threshold: Some(0.85),
//                         member_configs: vec![
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustDeepsetDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustProtectAiDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                         ],
//                     }),
//                     hybrid_config: None,
//                 },
//             },
//             // Individual Llama Guard 2 ONNX scanner
//             ScannerConfig {
//                 name: "onnx-llama-guard2-0.7".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::RustLlamaPromptGuard2,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: None,
//                     hybrid_config: None,
//                 },
//             },
//             ScannerConfig {
//                 name: "onnx-ensemble-deepset-deberta-and-promptguard".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::ParallelEnsemble,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: Some(EnsembleConfig {
//                         voting_strategy: VotingStrategy::AnyDetection,
//                         max_scan_time_ms: Some(200),     // Fast timeout since ONNX is fast
//                         min_models_required: Some(1),    // At least 1 model
//                         early_exit_threshold: Some(0.9), // If model is >90% confident, exit early
//                         member_configs: vec![
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustDeepsetDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustLlamaPromptGuard2,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                         ],
//                     }),
//                     hybrid_config: None,
//                 },
//             },
//             ScannerConfig {
//                 name: "onnx-ensemble-deepset-protectai-and-promptguard".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::ParallelEnsemble,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: Some(EnsembleConfig {
//                         voting_strategy: VotingStrategy::AnyDetection,
//                         max_scan_time_ms: Some(200),     // Fast timeout since ONNX is fast
//                         min_models_required: Some(1),    // At least 1 model
//                         early_exit_threshold: Some(0.9), // If model is >90% confident, exit early
//                         member_configs: vec![
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustProtectAiDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustLlamaPromptGuard2,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                         ],
//                     }),
//                     hybrid_config: None,
//                 },
//             },
//             // ONNX Ensemble with all 3 models - Any Detection
//             ScannerConfig {
//                 name: "onnx-ensemble-all-three-models".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::ParallelEnsemble,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: Some(EnsembleConfig {
//                         voting_strategy: VotingStrategy::AnyDetection,
//                         max_scan_time_ms: Some(300),
//                         min_models_required: Some(1),
//                         early_exit_threshold: Some(0.9),
//                         member_configs: vec![
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustDeepsetDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustProtectAiDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustLlamaPromptGuard2,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                         ],
//                     }),
//                     hybrid_config: None,
//                 },
//             },
//             // ONNX Ensemble with all 3 models - Majority Vote
//             ScannerConfig {
//                 name: "onnx-ensemble-all-three-majority".to_string(),
//                 config: SecurityConfig {
//                     enabled: true,
//                     scanner_type: ScannerType::ParallelEnsemble,
//                     ollama_endpoint: "".to_string(),
//                     action_policy: ActionPolicy::Block,
//                     scan_threshold: ThreatThreshold::Medium,
//                     confidence_threshold: 0.7,
//                     ensemble_config: Some(EnsembleConfig {
//                         voting_strategy: VotingStrategy::MajorityVote,
//                         max_scan_time_ms: Some(300),
//                         min_models_required: Some(2),
//                         early_exit_threshold: Some(0.85),
//                         member_configs: vec![
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustDeepsetDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustProtectAiDeberta,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                             EnsembleMember {
//                                 scanner_type: ScannerType::RustLlamaPromptGuard2,
//                                 confidence_threshold: 0.7,
//                                 weight: 1.0,
//                             },
//                         ],
//                     }),
//                     hybrid_config: None,
//                 },
//             },
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
                    hybrid_config: None,
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
                    hybrid_config: None,
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
                    hybrid_config: None,
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
                    hybrid_config: None,
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
                    hybrid_config: None,
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
                    hybrid_config: None,
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
                    hybrid_config: None,
                },
            },
        ]
    }
}