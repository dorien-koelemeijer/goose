use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub scanner_type: ScannerType,
    pub ollama_endpoint: String,
    pub action_policy: ActionPolicy,
    pub scan_threshold: ThreatThreshold,
    pub confidence_threshold: f32, // Minimum confidence to flag as threat (0.0-1.0)
    pub ensemble_config: Option<EnsembleConfig>, // Configuration for ensemble scanning
    pub hybrid_config: Option<HybridTieredConfig>, // Configuration for hybrid tiered scanning
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleConfig {
    pub voting_strategy: VotingStrategy,
    pub member_configs: Vec<EnsembleMember>,
    pub max_scan_time_ms: Option<u64>, // Maximum time to wait for all models (e.g., 800ms)
    pub min_models_required: Option<usize>, // Minimum models needed for decision (e.g., 2 out of 3)
    pub early_exit_threshold: Option<f32>, // If enough models agree with high confidence, exit early
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridTieredConfig {
    pub primary_scanner: ScannerType,
    pub primary_confidence_threshold: f32,
    pub escalation_threshold: f32, // If primary confidence is below this, use ensemble
    pub ensemble_config: EnsembleConfig,
    pub background_learning: bool, // Run ensemble in background for all requests to improve tuning
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleMember {
    pub scanner_type: ScannerType,
    pub confidence_threshold: f32,
    pub weight: f32, // For weighted voting (1.0 = normal weight)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VotingStrategy {
    AnyDetection, // Flag if ANY model detects threat
    MajorityVote, // Flag if majority of models detect threat
    WeightedVote, // Weight by model confidence and member weight
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScannerType {
    None,
    MistralNemo,
    ProtectAiDeberta, // Renamed from LlamaPromptGuard for clarity
    LlamaPromptGuard2,
    DeepsetDeberta, // deepset/deberta-v3-base-injection-v2 - often better precision (Python-based)
    RustDeepsetDeberta, // Fast Rust implementation of deepset/deberta-v3-base-injection using ONNX
    RustProtectAiDeberta, // Fast Rust implementation of protectai/deberta-v3-base-prompt-injection-v2 using ONNX
    RustLlamaPromptGuard2, // Fast Rust implementation of meta-llama/Llama-Prompt-Guard-2-86M using ONNX
    OpenAiModeration,      // OpenAI Moderation API - very low false positives
    ToxicBert,             // unitary/toxic-bert - good at context understanding
    ParallelEnsemble,      // Combines multiple models in parallel for better accuracy
    HybridTiered,          // Fast primary + ensemble fallback for borderline cases
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionPolicy {
    Block,    // Block content above threshold
    Sanitize, // Use sanitized version if available
    Warn,     // Just warn but allow content
    LogOnly,  // Only log, no intervention
    AskUser,  // Ask user for confirmation on threats above threshold
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatThreshold {
    Any,      // Detect any threat level
    Low,      // Low and above
    Medium,   // Medium and above
    High,     // High and above
    Critical, // Only critical threats
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scanner_type: ScannerType::ParallelEnsemble, // Use the best performing ensemble
            ollama_endpoint: "http://localhost:11434".to_string(),
            action_policy: ActionPolicy::AskUser, // Ask user for confirmation by default
            scan_threshold: ThreatThreshold::Medium,
            confidence_threshold: 0.7, // Default to 70% confidence to reduce false positives
            ensemble_config: Some(EnsembleConfig {
                voting_strategy: VotingStrategy::MajorityVote, // Require majority to agree (reduces false positives)
                member_configs: vec![
                    EnsembleMember {
                        scanner_type: ScannerType::RustDeepsetDeberta,
                        confidence_threshold: 0.95, // Higher threshold for Deepset to reduce false positives
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
            hybrid_config: None, // No hybrid by default
        }
    }
}
