use std::sync::Arc;
use anyhow::Result;
use rmcp::model::Content;
use goose_security::{SecurityScanner, SecurityConfig, ScanResult, ContentType, create_scanner};
use std::path::Path;
use tokio::fs;

pub mod integration;
pub mod example_integration_clean;

pub use integration::SecurityIntegration;

/// Security manager that wraps the security scanner with a clean interface
/// This is the only security-related code in the main crate
pub struct SecurityManager {
    scanner: Arc<dyn SecurityScanner>,
    config: SecurityConfig,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            scanner: create_scanner(config.clone()),
            config,
        }
    }

    pub fn disabled() -> Self {
        Self {
            scanner: create_scanner(SecurityConfig { enabled: false, ..SecurityConfig::default() }),
            config: SecurityConfig::default(),
        }
    }

    /// Load security configuration from file, with fallback to default
    pub async fn from_config_file<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config = if config_path.as_ref().exists() {
            let config_content = fs::read_to_string(&config_path).await?;
            if config_path.as_ref().extension().and_then(|s| s.to_str()) == Some("toml") {
                toml::from_str(&config_content)?
            } else {
                serde_json::from_str(&config_content)?
            }
        } else {
            SecurityConfig::default()
        };
        
        Ok(Self::new(config))
    }

    /// Create with default configuration (security disabled by default)
    pub fn default() -> Self {
        Self::disabled()
    }

    /// Scan content with automatic content type detection
    pub async fn scan_content(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::UserMessage).await
    }

    /// Scan content with explicit content type
    pub async fn scan_content_with_type(&self, content: &[Content], content_type: ContentType) -> Result<Option<ScanResult>> {
        // Check if we should scan this content type
        // First check global config, then check if any model is configured for this content type
        let should_scan_global = self.config.should_scan_content_type(&content_type);
        let should_scan_any_model = self.config.models.iter()
            .any(|model| model.should_scan_content_type(&content_type));
        
        if !should_scan_global && !should_scan_any_model {
            tracing::debug!(
                content_type = ?content_type,
                "🚫 Content type disabled in both global and per-model settings"
            );
            return Ok(None);
        }

        tracing::info!(
            content_type = ?content_type,
            global_enabled = should_scan_global,
            models_enabled = should_scan_any_model,
            "🔍 Starting security scan for content type"
        );

        self.scanner.scan_content(content, content_type).await
    }

    /// Convenience methods for different content types
    pub async fn scan_user_message(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::UserMessage).await
    }

    pub async fn scan_user_file(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::UserUploadedFile).await
    }

    pub async fn scan_extension(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::ExtensionDefinition).await
    }

    pub async fn scan_agent_response(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::AgentResponse).await
    }

    pub async fn scan_tool_result(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::ToolResult).await
    }

    pub async fn scan_external_content(&self, content: &[Content]) -> Result<Option<ScanResult>> {
        self.scan_content_with_type(content, ContentType::ExternalContent).await
    }

    pub fn is_enabled(&self) -> bool {
        self.scanner.is_enabled()
    }

    pub fn get_config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Create a SecurityIntegration helper for easy use throughout the codebase
    pub fn create_integration(self) -> SecurityIntegration {
        SecurityIntegration::new(Arc::new(self))
    }

    /// Create a SecurityIntegration helper from an Arc<SecurityManager>
    pub fn integration_from_arc(manager: Arc<SecurityManager>) -> SecurityIntegration {
        SecurityIntegration::new(manager)
    }
}

impl Clone for SecurityManager {
    fn clone(&self) -> Self {
        Self {
            scanner: Arc::clone(&self.scanner),
            config: self.config.clone(),
        }
    }
}