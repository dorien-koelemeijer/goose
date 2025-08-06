use serde::{Deserialize, Serialize};
fn default_enable_false_positive_reporting() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq)]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelType {
    SequenceClassification,
    TokenClassification,
    TextGeneration,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelTask {
    PromptInjectionDetection,
    ToxicityDetection,
    SentimentAnalysis,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArchitecture {
    pub model_type: ModelType,
    pub task: ModelTask,
    pub input_names: Vec<String>,
    pub output_names: Vec<String>,
    pub max_sequence_length: Option<usize>,
    pub num_labels: Option<usize>,
    pub label_mapping: Option<std::collections::HashMap<String, usize>>,
}

impl Default for ModelArchitecture {
    fn default() -> Self {
        Self {
            model_type: ModelType::SequenceClassification,
            task: ModelTask::PromptInjectionDetection,
            input_names: vec!["input_ids".to_string(), "attention_mask".to_string()],
            output_names: vec!["logits".to_string()],
            max_sequence_length: Some(512),
            num_labels: Some(2),
            label_mapping: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScannerType {
    Simple,
    SingleOnnx,
    DualOnnx, // Default: uses both deepset and protectai models
    Ensemble, // Future: multiple models with voting
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContentType {
    UserMessage,
    UserUploadedFile,
    ExtensionDefinition,
    AgentResponse,
    AgentToolCall,   // NEW: Agent-proposed tool calls (LLM wants to execute tools)
    ToolResult,
    ExternalContent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseMode {
    Warn,  // Process but warn user (initial mode)
    Block, // Actually block content (future mode)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum ModelBackend {
    #[default]
    Onnx,
    HuggingFaceApi,
    OpenAiModeration,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model: String, // Model identifier (HuggingFace name, etc.)
    #[serde(default)]
    pub backend: ModelBackend, // Which backend to use
    pub threshold: f32, // Default confidence threshold for this model
    pub weight: Option<f32>, // Weight in ensemble voting
    pub architecture: Option<ModelArchitecture>, // Model architecture info (auto-detected if None)
    pub content_types: Option<ModelContentTypes>, // Per-content-type configuration (optional)

    // Backend-specific configuration
    pub api_key: Option<String>,                 // For API-based backends
    pub endpoint: Option<String>,                // Custom endpoint URL
    pub timeout: Option<u64>,                    // Request timeout in seconds
    pub extra_config: Option<serde_json::Value>, // Backend-specific extra config
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model: String::new(), // No default model - must be configured explicitly
            backend: ModelBackend::Onnx,
            threshold: 0.8,
            weight: Some(1.0),
            architecture: None,
            content_types: None,
            api_key: None,
            endpoint: None,
            timeout: Some(30),
            extra_config: None,
        }
    }
}

impl ModelConfig {
    /// Check if this model should scan the given content type
    pub fn should_scan_content_type(&self, content_type: &ContentType) -> bool {
        let default_content_types = ModelContentTypes::default();
        let content_types = self
            .content_types
            .as_ref()
            .unwrap_or(&default_content_types);

        match content_type {
            ContentType::UserMessage => content_types.user_messages.enabled,
            ContentType::UserUploadedFile => content_types.user_files.enabled,
            ContentType::ExtensionDefinition => content_types.extensions.enabled,
            ContentType::AgentResponse => false, // Not included for now
            ContentType::AgentToolCall => content_types.agent_tool_calls.enabled,
            ContentType::ToolResult => content_types.tool_results.enabled,
            ContentType::ExternalContent => content_types.external_content.enabled,
        }
    }

    /// Get the effective threshold for this model and content type
    pub fn get_threshold_for_content_type(&self, content_type: &ContentType) -> f32 {
        let default_content_types = ModelContentTypes::default();
        let content_types = self
            .content_types
            .as_ref()
            .unwrap_or(&default_content_types);

        let content_config = match content_type {
            ContentType::UserMessage => &content_types.user_messages,
            ContentType::UserUploadedFile => &content_types.user_files,
            ContentType::ExtensionDefinition => &content_types.extensions,
            ContentType::AgentResponse => return self.threshold, // Not configured, use default
            ContentType::AgentToolCall => &content_types.agent_tool_calls,
            ContentType::ToolResult => &content_types.tool_results,
            ContentType::ExternalContent => &content_types.external_content,
        };

        content_config.threshold.unwrap_or(self.threshold)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeConfig {
    pub enabled: bool,
    pub threshold_override: Option<f32>, // Override global threshold for this content type
}

impl Default for ContentTypeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_override: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelContentTypeConfig {
    pub enabled: bool,
    pub threshold: Option<f32>, // Override model's default threshold for this content type
}

impl Default for ModelContentTypeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelContentTypes {
    pub user_messages: ModelContentTypeConfig,
    pub user_files: ModelContentTypeConfig,
    pub extensions: ModelContentTypeConfig,
    pub agent_tool_calls: ModelContentTypeConfig,  // NEW: Agent-proposed tool calls
    pub tool_results: ModelContentTypeConfig,
    pub external_content: ModelContentTypeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub threat_level: ThreatLevel,
    pub confidence: f32,
    pub explanation: String,
    pub scanner_type: String,
    pub finding_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub content_type: ContentType,
    pub should_warn: bool,
    pub should_block: bool,
    pub details: Option<serde_json::Value>, // For additional scanner-specific info
}

impl ScanResult {
    pub fn safe(scanner_type: String, content_type: ContentType) -> Self {
        Self {
            threat_level: ThreatLevel::Safe,
            confidence: 1.0,
            explanation: "Content appears safe".to_string(),
            scanner_type,
            finding_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_type,
            should_warn: false,
            should_block: false,
            details: None,
        }
    }

    pub fn threat(
        threat_level: ThreatLevel,
        confidence: f32,
        explanation: String,
        scanner_type: String,
        content_type: ContentType,
        should_warn: bool,
        should_block: bool,
    ) -> Self {
        Self {
            threat_level,
            confidence,
            explanation,
            scanner_type,
            finding_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_type,
            should_warn,
            should_block,
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub mode: ResponseMode,       // "warn" or "block"
    pub models: Vec<ModelConfig>, // Per-model configuration
    #[serde(default = "default_enable_false_positive_reporting")]
    pub enable_false_positive_reporting: bool,

    // Content-specific settings with per-type thresholds (OPTIONAL - legacy compatibility)
    #[serde(default)]
    pub user_messages: ContentTypeConfig,
    #[serde(default)]
    pub user_files: ContentTypeConfig,
    #[serde(default)]
    pub extensions: ContentTypeConfig,
    #[serde(default)]
    pub agent_responses: ContentTypeConfig,
    #[serde(default)]
    pub tool_results: ContentTypeConfig,
    #[serde(default)]
    pub external_content: ContentTypeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ResponseMode::Warn,
            models: vec![], // No default models - must be configured explicitly
            enable_false_positive_reporting: true,

            // Enable all scanning by default with sensible thresholds
            user_messages: ContentTypeConfig::default(),
            user_files: ContentTypeConfig::default(),
            extensions: ContentTypeConfig::default(),
            agent_responses: ContentTypeConfig::default(),
            tool_results: ContentTypeConfig::default(),
            external_content: ContentTypeConfig::default(),
        }
    }
}

impl SecurityConfig {
    pub fn should_scan_content_type(&self, content_type: &ContentType) -> bool {
        match content_type {
            ContentType::UserMessage => self.user_messages.enabled,
            ContentType::UserUploadedFile => self.user_files.enabled,
            ContentType::ExtensionDefinition => self.extensions.enabled,
            ContentType::AgentResponse => self.agent_responses.enabled,
            ContentType::AgentToolCall => self.user_messages.enabled, // TODO: Add agent_tool_calls field to SecurityConfig
            ContentType::ToolResult => self.tool_results.enabled,
            ContentType::ExternalContent => self.external_content.enabled,
        }
    }

    pub fn get_threshold_for_content_type(
        &self,
        content_type: &ContentType,
        model_threshold: f32,
    ) -> f32 {
        let content_config = match content_type {
            ContentType::UserMessage => &self.user_messages,
            ContentType::UserUploadedFile => &self.user_files,
            ContentType::ExtensionDefinition => &self.extensions,
            ContentType::AgentResponse => &self.agent_responses,
            ContentType::AgentToolCall => &self.user_messages, // Use user_messages config for now
            ContentType::ToolResult => &self.tool_results,
            ContentType::ExternalContent => &self.external_content,
        };

        content_config.threshold_override.unwrap_or(model_threshold)
    }

    /// Legacy compatibility - get first model's threshold
    pub fn confidence_threshold(&self) -> f32 {
        self.models.first().map(|m| m.threshold).unwrap_or(0.8)
    }

    /// Legacy compatibility - get response mode
    pub fn response_mode(&self) -> ResponseMode {
        self.mode.clone()
    }

    /// Legacy compatibility - get model names
    pub fn model_names(&self) -> Vec<String> {
        self.models.iter().map(|m| m.model.clone()).collect()
    }
}
