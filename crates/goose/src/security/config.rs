use serde::{Deserialize, Serialize};

/// Modular security configuration with separate concerns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModularSecurityConfig {
    pub scanner_config: ScannerConfig,
    pub policy_config: PolicyConfig,
    pub ui_config: UIConfig,
}

/// Scanner-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub scanner_type: ScannerType,
    pub confidence_threshold: f32,
    pub ollama_endpoint: String,
    pub ensemble_config: Option<EnsembleConfig>,
    pub hybrid_config: Option<HybridTieredConfig>,
}

/// Policy configuration for different threat levels and content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub default_action_policy: ActionPolicy,
    pub scan_threshold: ThreatThreshold,
    
    // Content-type-specific configurations
    pub user_messages: Option<ContentTypeConfig>,
    pub file_content: Option<ContentTypeConfig>,
    pub tool_results: Option<ContentTypeConfig>,
    pub extensions: Option<ContentTypeConfig>,
    pub agent_responses: Option<ContentTypeConfig>,
}

/// UI and user experience configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIConfig {
    pub show_security_notes: bool,
    pub enable_user_feedback: bool,
    pub auto_hide_safe_notifications: bool,
    pub notification_timeout_ms: Option<u64>,
}

impl ModularSecurityConfig {
    /// Convert to the legacy SecurityConfig for backward compatibility
    pub fn to_legacy_config(&self) -> SecurityConfig {
        SecurityConfig {
            enabled: self.scanner_config.enabled,
            scanner_type: self.scanner_config.scanner_type.clone(),
            ollama_endpoint: self.scanner_config.ollama_endpoint.clone(),
            action_policy: self.policy_config.default_action_policy.clone(),
            scan_threshold: self.policy_config.scan_threshold.clone(),
            confidence_threshold: self.scanner_config.confidence_threshold,
            ensemble_config: self.scanner_config.ensemble_config.clone(),
            hybrid_config: self.scanner_config.hybrid_config.clone(),
            user_messages: self.policy_config.user_messages.clone(),
            file_content: self.policy_config.file_content.clone(),
            tool_results: self.policy_config.tool_results.clone(),
            extensions: self.policy_config.extensions.clone(),
            agent_responses: self.policy_config.agent_responses.clone(),
        }
    }
    
    /// Create from legacy SecurityConfig
    pub fn from_legacy_config(legacy: SecurityConfig) -> Self {
        Self {
            scanner_config: ScannerConfig {
                enabled: legacy.enabled,
                scanner_type: legacy.scanner_type,
                confidence_threshold: legacy.confidence_threshold,
                ollama_endpoint: legacy.ollama_endpoint,
                ensemble_config: legacy.ensemble_config,
                hybrid_config: legacy.hybrid_config,
            },
            policy_config: PolicyConfig {
                default_action_policy: legacy.action_policy,
                scan_threshold: legacy.scan_threshold,
                user_messages: legacy.user_messages,
                file_content: legacy.file_content,
                tool_results: legacy.tool_results,
                extensions: legacy.extensions,
                agent_responses: legacy.agent_responses,
            },
            ui_config: UIConfig {
                show_security_notes: true,
                enable_user_feedback: true,
                auto_hide_safe_notifications: true,
                notification_timeout_ms: Some(5000),
            },
        }
    }
    
    /// Create a disabled configuration
    pub fn disabled() -> Self {
        Self {
            scanner_config: ScannerConfig {
                enabled: false,
                scanner_type: ScannerType::None,
                confidence_threshold: 0.7,
                ollama_endpoint: "http://localhost:11434".to_string(),
                ensemble_config: None,
                hybrid_config: None,
            },
            policy_config: PolicyConfig {
                default_action_policy: ActionPolicy::LogOnly,
                scan_threshold: ThreatThreshold::Medium,
                user_messages: None,
                file_content: None,
                tool_results: None,
                extensions: None,
                agent_responses: None,
            },
            ui_config: UIConfig {
                show_security_notes: false,
                enable_user_feedback: false,
                auto_hide_safe_notifications: true,
                notification_timeout_ms: None,
            },
        }
    }
}

/// Original SecurityConfig for backward compatibility

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
    
    // Content-type-specific configurations
    pub user_messages: Option<ContentTypeConfig>,
    pub file_content: Option<ContentTypeConfig>,
    pub tool_results: Option<ContentTypeConfig>,
    pub extensions: Option<ContentTypeConfig>,
    pub agent_responses: Option<ContentTypeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeConfig {
    pub confidence_threshold: Option<f32>,
    pub scan_threshold: Option<ThreatThreshold>,
    // Legacy single action policy (deprecated)
    pub action_policy: Option<ActionPolicy>,
    // Severity-specific action policies (new approach)
    pub low_action: Option<ActionPolicy>,
    pub medium_action: Option<ActionPolicy>,
    pub high_action: Option<ActionPolicy>,
    pub critical_action: Option<ActionPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    UserMessage,
    FileContent,
    ToolResult,
    Extension,
    AgentResponse,
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
    SimpleTest,             // Simple pattern-based scanner for testing
    ProtectAiDeberta, // Renamed from LlamaPromptGuard for clarity
    DeepsetDeberta, // deepset/deberta-v3-base-injection-v2 - often better precision (Python-based)
    RustDeepsetDeberta, // Fast Rust implementation of deepset/deberta-v3-base-injection using ONNX
    RustProtectAiDeberta, // Fast Rust implementation of protectai/deberta-v3-base-prompt-injection-v2 using ONNX
    OpenAiModeration,      // OpenAI Moderation API - very low false positives
    ToxicBert,             // unitary/toxic-bert - good at context understanding
    ParallelEnsemble,      // Combines multiple models in parallel for better accuracy
    HybridTiered,          // Fast primary + ensemble fallback for borderline cases
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionPolicy {
    Process,           // Process without any notification
    ProcessWithNote,   // Process but inform user about the detection
    Block,            // Block with explanation
    BlockWithNote,    // Block but allow user to provide feedback
    LogOnly,          // Only log, no intervention
    // Legacy policies for backward compatibility
    Sanitize,         // Use sanitized version if available (deprecated)
    Warn,             // Just warn but allow content (deprecated)
    AskUser,          // Ask user for confirmation (deprecated)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatThreshold {
    Any,      // Detect any threat level
    Low,      // Low and above
    Medium,   // Medium and above
    High,     // High and above
    Critical, // Only critical threats
}

impl SecurityConfig {
    /// Create a disabled security configuration
    pub fn disabled() -> Self {
        Self {
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
        }
    }

    /// Get the effective configuration for a specific content type
    pub fn get_config_for_type(&self, content_type: ContentType) -> EffectiveConfig {
        let type_config = match content_type {
            ContentType::UserMessage => &self.user_messages,
            ContentType::FileContent => &self.file_content,
            ContentType::ToolResult => &self.tool_results,
            ContentType::Extension => &self.extensions,
            ContentType::AgentResponse => &self.agent_responses,
        };

        EffectiveConfig {
            confidence_threshold: type_config
                .as_ref()
                .and_then(|c| c.confidence_threshold)
                .unwrap_or(self.confidence_threshold),
            scan_threshold: type_config
                .as_ref()
                .and_then(|c| c.scan_threshold.clone())
                .unwrap_or(self.scan_threshold.clone()),
            action_policy: type_config
                .as_ref()
                .and_then(|c| c.action_policy.clone())
                .unwrap_or(self.action_policy.clone()),
            content_type_config: type_config.clone(),
        }
    }

    /// Get the action policy for a specific threat level and content type
    pub fn get_action_for_threat(&self, content_type: ContentType, threat_level: &crate::security::content_scanner::ThreatLevel) -> ActionPolicy {
        let type_config = match content_type {
            ContentType::UserMessage => &self.user_messages,
            ContentType::FileContent => &self.file_content,
            ContentType::ToolResult => &self.tool_results,
            ContentType::Extension => &self.extensions,
            ContentType::AgentResponse => &self.agent_responses,
        };

        tracing::debug!(
            content_type = ?content_type,
            threat_level = ?threat_level,
            type_config_exists = type_config.is_some(),
            "🔒 SECURITY CONFIG: Determining action policy for threat"
        );

        // Try to get severity-specific action policy first
        if let Some(config) = type_config {
            tracing::debug!(
                content_type = ?content_type,
                low_action = ?config.low_action,
                medium_action = ?config.medium_action,
                high_action = ?config.high_action,
                critical_action = ?config.critical_action,
                legacy_action_policy = ?config.action_policy,
                "🔒 SECURITY CONFIG: Available content-type-specific actions"
            );

            let severity_action = match threat_level {
                crate::security::content_scanner::ThreatLevel::Low => {
                    tracing::debug!("🔒 SECURITY CONFIG: Checking low_action: {:?}", config.low_action);
                    config.low_action.clone()
                },
                crate::security::content_scanner::ThreatLevel::Medium => {
                    tracing::debug!("🔒 SECURITY CONFIG: Checking medium_action: {:?}", config.medium_action);
                    config.medium_action.clone()
                },
                crate::security::content_scanner::ThreatLevel::High => {
                    tracing::debug!("🔒 SECURITY CONFIG: Checking high_action: {:?}", config.high_action);
                    config.high_action.clone()
                },
                crate::security::content_scanner::ThreatLevel::Critical => {
                    tracing::debug!("🔒 SECURITY CONFIG: Checking critical_action: {:?}", config.critical_action);
                    config.critical_action.clone()
                },
                crate::security::content_scanner::ThreatLevel::Safe => {
                    tracing::debug!("🔒 SECURITY CONFIG: Threat level is Safe, using Process policy");
                    Some(ActionPolicy::Process)
                },
            };

            if let Some(action) = severity_action {
                tracing::debug!(
                    content_type = ?content_type,
                    threat_level = ?threat_level,
                    selected_action = ?action,
                    "🔒 SECURITY CONFIG: Using severity-specific action policy"
                );
                return action;
            }

            // Fall back to legacy action_policy if severity-specific not set
            if let Some(action) = config.action_policy.clone() {
                tracing::debug!(
                    content_type = ?content_type,
                    threat_level = ?threat_level,
                    selected_action = ?action,
                    "🔒 SECURITY CONFIG: Using legacy content-type action policy"
                );
                return action;
            }
        }

        // Fall back to global action policy
        tracing::debug!(
            content_type = ?content_type,
            threat_level = ?threat_level,
            selected_action = ?self.action_policy,
            "🔒 SECURITY CONFIG: Using global action policy (fallback)"
        );
        self.action_policy.clone()
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub confidence_threshold: f32,
    pub scan_threshold: ThreatThreshold,
    pub action_policy: ActionPolicy,
    pub content_type_config: Option<ContentTypeConfig>,
}

// Security Feedback System (Simple logging approach)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedbackType {
    FalsePositive,  // User says this was incorrectly flagged
    MissedThreat,   // User says this should have been flagged
    CorrectFlag,    // User confirms the flag was correct
    Other,          // User provided general feedback/comment
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityNote {
    pub finding_id: String,
    pub content_type: ContentType,
    pub threat_level: crate::security::content_scanner::ThreatLevel,
    pub explanation: String,
    pub action_taken: ActionPolicy,
    pub show_feedback_options: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
