use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub scanner_type: ScannerType,
    pub ollama_endpoint: String,
    pub action_policy: ActionPolicy,
    pub scan_threshold: ThreatThreshold,
    pub confidence_threshold: f32,  // Minimum confidence to flag as threat (0.0-1.0)
    pub ensemble_config: Option<EnsembleConfig>,  // Configuration for ensemble scanning
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleConfig {
    pub voting_strategy: VotingStrategy,
    pub member_configs: Vec<EnsembleMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleMember {
    pub scanner_type: ScannerType,
    pub confidence_threshold: f32,
    pub weight: f32,  // For weighted voting (1.0 = normal weight)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VotingStrategy {
    AnyDetection,    // Flag if ANY model detects threat
    MajorityVote,    // Flag if majority of models detect threat  
    WeightedVote,    // Weight by model confidence and member weight
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScannerType {
    None,
    MistralNemo,
    ProtectAiDeberta,    // Renamed from LlamaPromptGuard for clarity
    LlamaPromptGuard2,
    DeepsetDeberta,      // deepset/deberta-v3-base-injection-v2 - often better precision
    OpenAiModeration,    // OpenAI Moderation API - very low false positives
    ToxicBert,           // unitary/toxic-bert - good at context understanding
    ParallelEnsemble,    // Combines multiple models in parallel for better accuracy
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionPolicy {
    Block,    // Block content above threshold
    Sanitize, // Use sanitized version if available
    Warn,     // Just warn but allow content
    LogOnly,  // Only log, no intervention
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
            scanner_type: ScannerType::MistralNemo,
            ollama_endpoint: "http://localhost:11434".to_string(),
            action_policy: ActionPolicy::Block,
            scan_threshold: ThreatThreshold::Medium,
            confidence_threshold: 0.7,  // Default to 70% confidence to reduce false positives
            ensemble_config: None,  // No ensemble by default
        }
    }
}
