use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::stream::BoxStream;
use futures::{FutureExt, Stream, TryStreamExt};
use futures_util::stream;
use futures_util::stream::StreamExt;
use mcp_core::protocol::JsonRpcMessage;

use crate::agents::sub_recipe_manager::SubRecipeManager;
use crate::config::{Config, ExtensionConfigManager, PermissionManager};
use crate::message::{Message, MessageContent};
use mcp_core::role::Role;
use crate::permission::permission_judge::check_tool_permissions;
use crate::permission::{PermissionConfirmation, SecurityConfirmation};
use crate::providers::base::Provider;
use crate::providers::errors::ProviderError;
use crate::recipe::{Author, Recipe, Settings, SubRecipe};
use crate::scheduler_trait::SchedulerTrait;
use crate::security::SecurityManager;
use crate::tool_monitor::{ToolCall, ToolMonitor};
use regex::Regex;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, instrument};

use crate::agents::extension::{ExtensionConfig, ExtensionError, ExtensionResult, ToolInfo};
use crate::agents::extension_manager::{get_parameter_names, ExtensionManager};
use crate::agents::platform_tools::{
    PLATFORM_LIST_RESOURCES_TOOL_NAME, PLATFORM_MANAGE_EXTENSIONS_TOOL_NAME,
    PLATFORM_MANAGE_SCHEDULE_TOOL_NAME, PLATFORM_READ_RESOURCE_TOOL_NAME,
    PLATFORM_SEARCH_AVAILABLE_EXTENSIONS_TOOL_NAME,
};
use crate::agents::prompt_manager::PromptManager;
use crate::agents::router_tool_selector::{
    create_tool_selector, RouterToolSelectionStrategy, RouterToolSelector,
};
use crate::agents::router_tools::{ROUTER_LLM_SEARCH_TOOL_NAME, ROUTER_VECTOR_SEARCH_TOOL_NAME};
use crate::agents::tool_router_index_manager::ToolRouterIndexManager;
use crate::agents::tool_vectordb::generate_table_id;
use crate::agents::types::SessionConfig;
use crate::agents::types::{FrontendTool, ToolResultReceiver};
use mcp_core::{
    prompt::Prompt, protocol::GetPromptResult, tool::Tool, Content, ToolError, ToolResult,
};

use super::platform_tools;
use super::router_tools;
use super::tool_execution::{ToolCallResult, CHAT_MODE_TOOL_SKIPPED_RESPONSE, DECLINED_RESPONSE};

/// The main goose Agent
pub struct Agent {
    pub(super) provider: Mutex<Option<Arc<dyn Provider>>>,
    pub(super) extension_manager: Mutex<ExtensionManager>,
    pub(super) sub_recipe_manager: Mutex<SubRecipeManager>,
    pub(super) frontend_tools: Mutex<HashMap<String, FrontendTool>>,
    pub(super) frontend_instructions: Mutex<Option<String>>,
    pub(super) prompt_manager: Mutex<PromptManager>,
    pub(super) confirmation_tx: mpsc::Sender<(String, PermissionConfirmation)>,
    pub(super) confirmation_rx: Mutex<mpsc::Receiver<(String, PermissionConfirmation)>>,
    pub(super) security_confirmation_tx: mpsc::Sender<(String, SecurityConfirmation)>,
    pub(super) security_confirmation_rx: Mutex<mpsc::Receiver<(String, SecurityConfirmation)>>,
    pub(super) tool_result_tx: mpsc::Sender<(String, ToolResult<Vec<Content>>)>,
    pub(super) tool_result_rx: ToolResultReceiver,
    pub(super) tool_monitor: Mutex<Option<ToolMonitor>>,
    pub(super) router_tool_selector: Mutex<Option<Arc<Box<dyn RouterToolSelector>>>>,
    pub(super) scheduler_service: Mutex<Option<Arc<dyn SchedulerTrait>>>,
    pub(super) security_manager: Mutex<Option<SecurityManager>>,
    pub(super) approved_security_messages: Mutex<std::collections::HashSet<String>>, // Cache of approved message hashes
    pub(super) denied_security_messages: Mutex<std::collections::HashSet<String>>, // Cache of denied message hashes
    pub(super) pending_security_requests: Mutex<std::collections::HashMap<String, String>>, // request_id -> flagged_content
}

#[derive(Clone, Debug)]
pub enum AgentEvent {
    Message(Message),
    McpNotification((String, JsonRpcMessage)),
    ModelChange { model: String, mode: String },
}

impl Agent {
    /// Create a hash of message content for tracking approved security messages
    fn hash_message_content(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Check if a message is obviously safe and doesn't need security scanning
    fn is_obviously_safe_message(text: &str) -> bool {
        let text_lower = text.to_lowercase();
        let text_len = text.len();
        
        // Very short messages with only safe characters
        if text_len <= 15 && text.chars().all(|c| c.is_alphabetic() || c.is_whitespace() || ".,!?👋🎉".contains(c)) {
            return true;
        }
        
        // Common greetings and safe patterns
        let safe_patterns = [
            "hey", "hi", "hello", "hiya", "heya", "heyy", "heyyy",
            "good morning", "good afternoon", "good evening",
            "how are you", "what's up", "whats up",
            "thanks", "thank you", "thx",
            "ok", "okay", "sure", "yes", "no",
            "goose", "nice", "great", "awesome",
            "👋", "🎉", "😊", "🙂", "😄",
        ];
        
        // Check if the message is primarily composed of safe patterns
        if safe_patterns.iter().any(|pattern| {
            text_lower.contains(pattern) && 
            text_len <= 50 && // Keep it short to avoid false negatives
            !text_lower.contains("ignore") && 
            !text_lower.contains("forget") &&
            !text_lower.contains("system") &&
            !text_lower.contains("prompt") &&
            !text_lower.contains("instruction")
        }) {
            return true;
        }
        
        false
    }

    pub fn new() -> Self {
        // Create channels with buffer size 32 (adjust if needed)
        let (confirm_tx, confirm_rx) = mpsc::channel(32);
        let (security_confirm_tx, security_confirm_rx) = mpsc::channel(32);
        let (tool_tx, tool_rx) = mpsc::channel(32);

        Self {
            provider: Mutex::new(None),
            extension_manager: Mutex::new(ExtensionManager::new()),
            sub_recipe_manager: Mutex::new(SubRecipeManager::new()),
            frontend_tools: Mutex::new(HashMap::new()),
            frontend_instructions: Mutex::new(None),
            prompt_manager: Mutex::new(PromptManager::new()),
            confirmation_tx: confirm_tx,
            confirmation_rx: Mutex::new(confirm_rx),
            security_confirmation_tx: security_confirm_tx,
            security_confirmation_rx: Mutex::new(security_confirm_rx),
            tool_result_tx: tool_tx,
            tool_result_rx: Arc::new(Mutex::new(tool_rx)),
            tool_monitor: Mutex::new(None),
            router_tool_selector: Mutex::new(None),
            scheduler_service: Mutex::new(None),
            security_manager: Mutex::new(None),
            approved_security_messages: Mutex::new(std::collections::HashSet::new()),
            denied_security_messages: Mutex::new(std::collections::HashSet::new()),
            pending_security_requests: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub async fn configure_tool_monitor(&self, max_repetitions: Option<u32>) {
        let mut tool_monitor = self.tool_monitor.lock().await;
        *tool_monitor = Some(ToolMonitor::new(max_repetitions));
    }

    pub async fn get_tool_stats(&self) -> Option<HashMap<String, u32>> {
        let tool_monitor = self.tool_monitor.lock().await;
        tool_monitor.as_ref().map(|monitor| monitor.get_stats())
    }

    pub async fn reset_tool_monitor(&self) {
        if let Some(monitor) = self.tool_monitor.lock().await.as_mut() {
            monitor.reset();
        }
    }

    /// Set the scheduler service for this agent
    pub async fn set_scheduler(&self, scheduler: Arc<dyn SchedulerTrait>) {
        let mut scheduler_service = self.scheduler_service.lock().await;
        *scheduler_service = Some(scheduler);
    }
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

pub enum ToolStreamItem<T> {
    Message(JsonRpcMessage),
    Result(T),
}

pub type ToolStream = Pin<Box<dyn Stream<Item = ToolStreamItem<ToolResult<Vec<Content>>>> + Send>>;

// tool_stream combines a stream of JsonRpcMessages with a future representing the
// final result of the tool call. MCP notifications are not request-scoped, but
// this lets us capture all notifications emitted during the tool call for
// simpler consumption
pub fn tool_stream<S, F>(rx: S, done: F) -> ToolStream
where
    S: Stream<Item = JsonRpcMessage> + Send + Unpin + 'static,
    F: Future<Output = ToolResult<Vec<Content>>> + Send + 'static,
{
    Box::pin(async_stream::stream! {
        tokio::pin!(done);
        let mut rx = rx;

        loop {
            tokio::select! {
                Some(msg) = rx.next() => {
                    yield ToolStreamItem::Message(msg);
                }
                r = &mut done => {
                    yield ToolStreamItem::Result(r);
                    break;
                }
            }
        }
    })
}

impl Agent {
    /// Get a reference count clone to the provider
    pub async fn provider(&self) -> Result<Arc<dyn Provider>, anyhow::Error> {
        match &*self.provider.lock().await {
            Some(provider) => Ok(Arc::clone(provider)),
            None => Err(anyhow!("Provider not set")),
        }
    }

    /// Check if a tool is a frontend tool
    pub async fn is_frontend_tool(&self, name: &str) -> bool {
        self.frontend_tools.lock().await.contains_key(name)
    }

    /// Get a reference to a frontend tool
    pub async fn get_frontend_tool(&self, name: &str) -> Option<FrontendTool> {
        self.frontend_tools.lock().await.get(name).cloned()
    }

    /// Get all tools from all clients with proper prefixing
    /// Includes security scanning of MCP tool definitions
    pub async fn get_prefixed_tools(&self) -> ExtensionResult<Vec<Tool>> {
        // For already-enabled extensions, don't re-scan them - just get the tools
        // Security scanning only happens when extensions are first added
        let security_manager = self.security_manager.lock().await;
        let _security_manager_ref = security_manager.as_ref();
        
        let mut tools = self
            .extension_manager
            .lock()
            .await
            .get_prefixed_tools(None) // Use the non-security version for already-enabled extensions
            .await?;

        // Add frontend tools directly - they don't need prefixing since they're already uniquely named
        // Frontend tools are trusted and don't need security scanning
        let frontend_tools = self.frontend_tools.lock().await;
        for frontend_tool in frontend_tools.values() {
            tools.push(frontend_tool.tool.clone());
        }

        Ok(tools)
    }

    pub async fn add_sub_recipes(&self, sub_recipes: Vec<SubRecipe>) {
        let mut sub_recipe_manager = self.sub_recipe_manager.lock().await;
        sub_recipe_manager.add_sub_recipe_tools(sub_recipes);
    }

    /// Dispatch a single tool call to the appropriate client
    #[instrument(skip(self, tool_call, request_id), fields(input, output))]
    pub async fn dispatch_tool_call(
        &self,
        tool_call: mcp_core::tool::ToolCall,
        request_id: String,
    ) -> (String, Result<ToolCallResult, ToolError>) {
        // 🔒 SECURITY GATE: Pre-execution security scanning
        if let Some(security_manager) = &*self.security_manager.lock().await {
            // 1. Pre-scan file content for file-reading tools
            if self.is_file_reading_tool(&tool_call) {
                if let Some(file_path) = self.extract_file_path_from_tool_call(&tool_call) {
                    tracing::info!(
                        tool_name = %tool_call.name,
                        file_path = %file_path,
                        "🔒 SECURITY: Pre-scanning file content before tool execution"
                    );
                    
                    // Try to read and scan the file content before executing the tool
                    match self.pre_scan_file_content(&file_path, security_manager).await {
                        Ok(Some(scan_result)) => {
                            // Check if the file actually contains threats that should be blocked
                            let action_policy = security_manager.get_action_for_threat(crate::security::config::ContentType::FileContent, &scan_result.threat_level);
                            if matches!(action_policy, crate::security::config::ActionPolicy::Block | crate::security::config::ActionPolicy::BlockWithNote) {
                                // File contains malicious content - block the tool execution entirely
                                tracing::error!(
                                    tool_name = %tool_call.name,
                                    file_path = %file_path,
                                    threat_level = ?scan_result.threat_level,
                                    explanation = %scan_result.explanation,
                                    "🚨 SECURITY: Blocking file-reading tool due to malicious file content"
                                );
                                
                                return (
                                    request_id,
                                    Ok(ToolCallResult::from(Ok(vec![Content::text(format!(
                                        "🚨 **Security Alert: Malicious File Content Detected**\n\n\
                                        The file you're trying to access contains potentially malicious content that could be used for prompt injection or other security attacks.\n\n\
                                        **File:** {}\n\
                                        **Threat Level:** {:?}\n\
                                        **Details:** {}\n\n\
                                        For your safety, access to this file has been automatically blocked. Please review the file content and ensure it's safe before trying again.",
                                        file_path,
                                        scan_result.threat_level,
                                        scan_result.explanation
                                    ))])))
                                );
                            } else {
                                // File was scanned and found to be safe, continue with tool execution
                                tracing::info!(
                                    tool_name = %tool_call.name,
                                    file_path = %file_path,
                                    threat_level = ?scan_result.threat_level,
                                    "🔒 SECURITY: File pre-scan completed - file is safe, proceeding with tool execution"
                                );
                            }
                        }
                        Ok(None) => {
                            // Security scanning disabled or file is safe, continue with tool execution
                            tracing::info!(
                                tool_name = %tool_call.name,
                                file_path = %file_path,
                                "🔒 SECURITY: File pre-scan completed - safe to proceed"
                            );
                        }
                        Err(e) => {
                            // Failed to pre-scan file (maybe file doesn't exist, permission issues, etc.)
                            // Log the error but continue with tool execution - the tool itself will handle file access errors
                            tracing::warn!(
                                tool_name = %tool_call.name,
                                file_path = %file_path,
                                error = %e,
                                "🔒 SECURITY: Failed to pre-scan file content, continuing with tool execution"
                            );
                        }
                    }
                }
            }

            // 2. Pre-scan tool arguments for malicious content
            tracing::info!(
                tool_name = %tool_call.name,
                "🔒 SECURITY: Pre-scanning tool arguments before execution"
            );
            
            // Create content from tool arguments for scanning
            let tool_args_text = serde_json::to_string_pretty(&tool_call.arguments)
                .unwrap_or_else(|_| "Failed to serialize tool arguments".to_string());
            let tool_content_for_scanning = vec![Content::text(format!(
                "Tool: {}\nArguments: {}",
                tool_call.name,
                tool_args_text
            ))];
            
            match security_manager.scan_content_with_type(&tool_content_for_scanning, crate::security::config::ContentType::ToolResult).await {
                Ok(Some(scan_result)) => {
                    let action_policy = security_manager.get_action_for_threat(crate::security::config::ContentType::ToolResult, &scan_result.threat_level);
                    
                    match action_policy {
                        crate::security::config::ActionPolicy::Block | 
                        crate::security::config::ActionPolicy::BlockWithNote => {
                            tracing::error!(
                                tool_name = %tool_call.name,
                                threat_level = ?scan_result.threat_level,
                                explanation = %scan_result.explanation,
                                "🚨 SECURITY: Blocking tool execution due to malicious arguments"
                            );
                            
                            return (
                                request_id,
                                Ok(ToolCallResult::from(Ok(vec![Content::text(format!(
                                    "🚨 **Security Alert: Malicious Tool Arguments Detected**\n\n\
                                    The tool arguments contain potentially malicious content that could be used for prompt injection or other security attacks.\n\n\
                                    **Tool:** {}\n\
                                    **Threat Level:** {:?}\n\
                                    **Details:** {}\n\n\
                                    For your safety, this tool execution has been automatically blocked. Please review the tool arguments and try again with safe parameters.",
                                    tool_call.name,
                                    scan_result.threat_level,
                                    scan_result.explanation
                                ))])))
                            );
                        }
                        _ => {
                            tracing::info!(
                                tool_name = %tool_call.name,
                                threat_level = ?scan_result.threat_level,
                                action_policy = ?action_policy,
                                "🔒 SECURITY: Tool arguments scanned - proceeding with execution"
                            );
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!(
                        tool_name = %tool_call.name,
                        "🔒 SECURITY: Tool arguments scanning disabled or safe"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        tool_name = %tool_call.name,
                        error = %e,
                        "🔒 SECURITY: Failed to scan tool arguments, continuing with execution"
                    );
                }
            }
        }

        // Check if this tool call should be allowed based on repetition monitoring
        if let Some(monitor) = self.tool_monitor.lock().await.as_mut() {
            let tool_call_info = ToolCall::new(tool_call.name.clone(), tool_call.arguments.clone());

            if !monitor.check_tool_call(tool_call_info) {
                return (
                    request_id,
                    Err(ToolError::ExecutionError(
                        "Tool call rejected: exceeded maximum allowed repetitions".to_string(),
                    )),
                );
            }
        }

        if tool_call.name == PLATFORM_MANAGE_SCHEDULE_TOOL_NAME {
            let result = self
                .handle_schedule_management(tool_call.arguments, request_id.clone())
                .await;
            return (request_id, Ok(ToolCallResult::from(result)));
        }

        if tool_call.name == PLATFORM_MANAGE_EXTENSIONS_TOOL_NAME {
            let extension_name = tool_call
                .arguments
                .get("extension_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let action = tool_call
                .arguments
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let (request_id, result) = self
                .manage_extensions(action, extension_name, request_id)
                .await;

            return (request_id, Ok(ToolCallResult::from(result)));
        }

        let extension_manager = self.extension_manager.lock().await;
        let sub_recipe_manager = self.sub_recipe_manager.lock().await;

        let result: ToolCallResult = if sub_recipe_manager.is_sub_recipe_tool(&tool_call.name) {
            sub_recipe_manager
                .dispatch_sub_recipe_tool_call(&tool_call.name, tool_call.arguments.clone())
                .await
        } else if tool_call.name == PLATFORM_READ_RESOURCE_TOOL_NAME {
            // Check if the tool is read_resource and handle it separately
            ToolCallResult::from(
                extension_manager
                    .read_resource(tool_call.arguments.clone())
                    .await,
            )
        } else if tool_call.name == PLATFORM_LIST_RESOURCES_TOOL_NAME {
            ToolCallResult::from(
                extension_manager
                    .list_resources(tool_call.arguments.clone())
                    .await,
            )
        } else if tool_call.name == PLATFORM_SEARCH_AVAILABLE_EXTENSIONS_TOOL_NAME {
            ToolCallResult::from(extension_manager.search_available_extensions().await)
        } else if self.is_frontend_tool(&tool_call.name).await {
            // For frontend tools, return an error indicating we need frontend execution
            ToolCallResult::from(Err(ToolError::ExecutionError(
                "Frontend tool execution required".to_string(),
            )))
        } else if tool_call.name == ROUTER_VECTOR_SEARCH_TOOL_NAME
            || tool_call.name == ROUTER_LLM_SEARCH_TOOL_NAME
        {
            let selector = self.router_tool_selector.lock().await.clone();
            let selected_tools = match selector.as_ref() {
                Some(selector) => match selector.select_tools(tool_call.arguments.clone()).await {
                    Ok(tools) => tools,
                    Err(e) => {
                        return (
                            request_id,
                            Err(ToolError::ExecutionError(format!(
                                "Failed to select tools: {}",
                                e
                            ))),
                        )
                    }
                },
                None => {
                    return (
                        request_id,
                        Err(ToolError::ExecutionError(
                            "No tool selector available".to_string(),
                        )),
                    )
                }
            };
            ToolCallResult::from(Ok(selected_tools))
        } else {
            // Clone the result to ensure no references to extension_manager are returned
            let result = extension_manager
                .dispatch_tool_call(tool_call.clone())
                .await;
            match result {
                Ok(call_result) => call_result,
                Err(e) => ToolCallResult::from(Err(ToolError::ExecutionError(e.to_string()))),
            }
        };

        (
            request_id,
            Ok(ToolCallResult {
                notification_stream: result.notification_stream,
                result: Box::new(
                    result
                        .result
                        .map(super::large_response_handler::process_tool_response),
                ),
            }),
        )
    }

    pub(super) async fn manage_extensions(
        &self,
        action: String,
        extension_name: String,
        request_id: String,
    ) -> (String, Result<Vec<Content>, ToolError>) {
        let mut extension_manager = self.extension_manager.lock().await;

        let selector = self.router_tool_selector.lock().await.clone();
        if ToolRouterIndexManager::is_tool_router_enabled(&selector) {
            if let Some(selector) = selector {
                let selector_action = if action == "disable" { "remove" } else { "add" };
                let extension_manager = self.extension_manager.lock().await;
                let selector = Arc::new(selector);
                if let Err(e) = ToolRouterIndexManager::update_extension_tools(
                    &selector,
                    &extension_manager,
                    &extension_name,
                    selector_action,
                )
                .await
                {
                    return (
                        request_id,
                        Err(ToolError::ExecutionError(format!(
                            "Failed to update vector index: {}",
                            e
                        ))),
                    );
                }
            }
        }

        if action == "disable" {
            let result = extension_manager
                .remove_extension(&extension_name)
                .await
                .map(|_| {
                    vec![Content::text(format!(
                        "The extension '{}' has been disabled successfully",
                        extension_name
                    ))]
                })
                .map_err(|e| ToolError::ExecutionError(e.to_string()));
            return (request_id, result);
        }

        let config = match ExtensionConfigManager::get_config_by_name(&extension_name) {
            Ok(Some(config)) => config,
            Ok(None) => {
                return (
                    request_id,
                    Err(ToolError::ExecutionError(format!(
                        "Extension '{}' not found. Please check the extension name and try again.",
                        extension_name
                    ))),
                )
            }
            Err(e) => {
                return (
                    request_id,
                    Err(ToolError::ExecutionError(format!(
                        "Failed to get extension config: {}",
                        e
                    ))),
                )
            }
        };

        let security_manager = self.security_manager.lock().await;
        let security_manager_ref = security_manager.as_ref();
        let result = extension_manager
            .add_extension_with_security(config, security_manager_ref)
            .await
            .map(|_| {
                vec![Content::text(format!(
                    "The extension '{}' has been installed successfully",
                    extension_name
                ))]
            })
            .map_err(|e| {
                // Handle security threats specially - they need user confirmation
                if let ExtensionError::SecurityThreat { tool_name, threat_level, explanation } = &e {
                    tracing::warn!(
                        extension_name = %extension_name,
                        tool_name = %tool_name,
                        threat_level = %threat_level,
                        explanation = %explanation,
                        "Security threat detected in extension, user confirmation needed"
                    );
                    // For now, return a descriptive error message
                    // TODO: Implement proper user confirmation flow for extension security threats
                    ToolError::ExecutionError(format!(
                        "🚨 Security Alert: Extension '{}' contains a suspicious tool '{}' with {} threat level.\n\n{}\n\nExtension installation blocked for security reasons.",
                        extension_name, tool_name, threat_level, explanation
                    ))
                } else {
                    ToolError::ExecutionError(e.to_string())
                }
            });

        (request_id, result)
    }

    pub async fn add_extension(&self, extension: ExtensionConfig) -> ExtensionResult<()> {
        match &extension {
            ExtensionConfig::Frontend {
                name: _,
                tools,
                instructions,
                bundled: _,
            } => {
                // For frontend tools, just store them in the frontend_tools map
                let mut frontend_tools = self.frontend_tools.lock().await;
                for tool in tools {
                    let frontend_tool = FrontendTool {
                        name: tool.name.clone(),
                        tool: tool.clone(),
                    };
                    frontend_tools.insert(tool.name.clone(), frontend_tool);
                }
                // Store instructions if provided, using "frontend" as the key
                let mut frontend_instructions = self.frontend_instructions.lock().await;
                if let Some(instructions) = instructions {
                    *frontend_instructions = Some(instructions.clone());
                } else {
                    // Default frontend instructions if none provided
                    *frontend_instructions = Some(
                        "The following tools are provided directly by the frontend and will be executed by the frontend when called.".to_string(),
                    );
                }
            }
            _ => {
                let security_manager = self.security_manager.lock().await;
                let security_manager_ref = security_manager.as_ref();
                let mut extension_manager = self.extension_manager.lock().await;
                
                // Handle security threats from extension scanning
                match extension_manager.add_extension_with_security(extension.clone(), security_manager_ref).await {
                    Ok(_) => {
                        // Extension added successfully
                    }
                    Err(ExtensionError::SecurityThreat { tool_name, threat_level, explanation }) => {
                        tracing::warn!(
                            extension_name = %extension.name(),
                            tool_name = %tool_name,
                            threat_level = %threat_level,
                            explanation = %explanation,
                            "Security threat detected in extension during add_extension"
                        );
                        // For now, return the security error - in the future this could trigger a confirmation UI
                        return Err(ExtensionError::SecurityThreat { tool_name, threat_level, explanation });
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        // If vector tool selection is enabled, index the tools
        let selector = self.router_tool_selector.lock().await.clone();
        if ToolRouterIndexManager::is_tool_router_enabled(&selector) {
            if let Some(selector) = selector {
                let extension_manager = self.extension_manager.lock().await;
                let selector = Arc::new(selector);
                if let Err(e) = ToolRouterIndexManager::update_extension_tools(
                    &selector,
                    &extension_manager,
                    &extension.name(),
                    "add",
                )
                .await
                {
                    return Err(ExtensionError::SetupError(format!(
                        "Failed to index tools for extension {}: {}",
                        extension.name(),
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    pub async fn list_tools(&self, extension_name: Option<String>) -> Vec<Tool> {
        // For listing tools, don't re-scan already-enabled extensions
        let extension_manager = self.extension_manager.lock().await;
        let mut prefixed_tools = extension_manager
            .get_prefixed_tools(extension_name.clone()) // Use non-security version
            .await
            .unwrap_or_default();

        if extension_name.is_none() || extension_name.as_deref() == Some("platform") {
            // Add platform tools
            prefixed_tools.extend([
                platform_tools::search_available_extensions_tool(),
                platform_tools::manage_extensions_tool(),
                platform_tools::manage_schedule_tool(),
            ]);

            // Add resource tools if supported
            if extension_manager.supports_resources() {
                prefixed_tools.extend([
                    platform_tools::read_resource_tool(),
                    platform_tools::list_resources_tool(),
                ]);
            }
        }

        if extension_name.is_none() {
            let sub_recipe_manager = self.sub_recipe_manager.lock().await;
            prefixed_tools.extend(sub_recipe_manager.sub_recipe_tools.values().cloned());
        }

        prefixed_tools
    }

    pub async fn list_tools_for_router(
        &self,
        strategy: Option<RouterToolSelectionStrategy>,
    ) -> Vec<Tool> {
        let mut prefixed_tools = vec![];
        match strategy {
            Some(RouterToolSelectionStrategy::Vector) => {
                prefixed_tools.push(router_tools::vector_search_tool());
            }
            Some(RouterToolSelectionStrategy::Llm) => {
                prefixed_tools.push(router_tools::llm_search_tool());
            }
            None => {}
        }

        // Get recent tool calls from router tool selector if available
        let selector = self.router_tool_selector.lock().await.clone();
        if let Some(selector) = selector {
            if let Ok(recent_calls) = selector.get_recent_tool_calls(20).await {
                let extension_manager = self.extension_manager.lock().await;
                // Add recent tool calls to the list, avoiding duplicates
                for tool_name in recent_calls {
                    // Find the tool in the extension manager's tools - no security scanning needed
                    if let Ok(extension_tools) = extension_manager.get_prefixed_tools(None).await {
                        if let Some(tool) = extension_tools.iter().find(|t| t.name == tool_name) {
                            // Only add if not already in prefixed_tools
                            if !prefixed_tools.iter().any(|t| t.name == tool.name) {
                                prefixed_tools.push(tool.clone());
                            }
                        }
                    }
                }
            }
        }

        prefixed_tools
    }

    pub async fn remove_extension(&self, name: &str) -> Result<()> {
        // If vector tool selection is enabled, remove tools from the index
        let selector = self.router_tool_selector.lock().await.clone();
        if ToolRouterIndexManager::is_tool_router_enabled(&selector) {
            if let Some(selector) = selector {
                let extension_manager = self.extension_manager.lock().await;
                ToolRouterIndexManager::update_extension_tools(
                    &selector,
                    &extension_manager,
                    name,
                    "remove",
                )
                .await?;
            }
        }

        let mut extension_manager = self.extension_manager.lock().await;
        extension_manager.remove_extension(name).await?;

        Ok(())
    }

    pub async fn list_extensions(&self) -> Vec<String> {
        let extension_manager = self.extension_manager.lock().await;
        extension_manager
            .list_extensions()
            .await
            .expect("Failed to list extensions")
    }

    /// Handle a confirmation response for a tool request
    pub async fn handle_confirmation(
        &self,
        request_id: String,
        confirmation: PermissionConfirmation,
    ) {
        tracing::info!("handle_confirmation called with request_id: {}, permission: {:?}", request_id, confirmation.permission);
        
        // Check if this is a security scanner confirmation (user messages or tool results)
        if request_id.starts_with("sec_") || request_id.starts_with("tool_sec_") {
            let is_tool_result = request_id.starts_with("tool_sec_");
            tracing::info!("Processing {} security confirmation for request_id: {}", 
                if is_tool_result { "tool result" } else { "user message" }, request_id);
            
            // Get the flagged content from pending requests
            let flagged_content = {
                let mut pending_requests = self.pending_security_requests.lock().await;
                let content = pending_requests.remove(&request_id);
                tracing::info!("Retrieved flagged content for {}: {:?}", request_id, content.is_some());
                content
            };
            
            if let Some(content) = flagged_content {
                if is_tool_result {
                    // For tool results, we handle the confirmation differently
                    // The content is serialized JSON of the tool result
                    match confirmation.permission {
                        crate::permission::Permission::AllowOnce |
                        crate::permission::Permission::AlwaysAllow => {
                            tracing::info!("User approved security-flagged tool result, content will be shown");
                            // TODO: We could store approved tool result patterns for future reference
                            // For now, the tool result will be processed normally when user re-runs the tool
                        },
                        crate::permission::Permission::DenyOnce |
                        crate::permission::Permission::Cancel => {
                            tracing::info!("User denied security-flagged tool result, content will be blocked");
                            // TODO: We could store denied tool result patterns for future reference
                        }
                    }
                } else {
                    // For user messages, use the existing hash-based caching
                    let message_hash = Self::hash_message_content(&content);
                    tracing::info!("Generated hash for content: {}", message_hash);
                    
                    match confirmation.permission {
                        crate::permission::Permission::AllowOnce |
                        crate::permission::Permission::AlwaysAllow => {
                            tracing::info!("User approved security-flagged message, adding to approved cache");
                            let mut approved_messages = self.approved_security_messages.lock().await;
                            approved_messages.insert(message_hash.clone());
                            drop(approved_messages);
                            tracing::info!("Message hash {} added to approved cache for request_id: {}", message_hash, request_id);
                        },
                        crate::permission::Permission::DenyOnce |
                        crate::permission::Permission::Cancel => {
                            tracing::info!("User denied security-flagged message, adding to denied cache");
                            let mut denied_messages = self.denied_security_messages.lock().await;
                            denied_messages.insert(message_hash.clone());
                            drop(denied_messages);
                            tracing::info!("Message hash {} added to denied cache for request_id: {}", message_hash, request_id);
                        }
                    }
                }
            } else {
                tracing::warn!("No flagged content found for security request_id: {}", request_id);
            }
        }
        
        if let Err(e) = self.confirmation_tx.send((request_id, confirmation)).await {
            error!("Failed to send confirmation: {}", e);
        }
    }

    pub async fn configure_security(&self, config: crate::security::config::SecurityConfig) -> Result<Vec<Message>> {
        let security_manager = SecurityManager::new(config);
        let mut initialization_messages = Vec::new();
        
        // Set up security manager without pre-warming models
        if security_manager.is_enabled() {
            tracing::info!("Security is enabled, models will be loaded on first use");
            
            // Check if models need to be downloaded (but don't download them yet)
            let needs_download = security_manager.check_models_need_download().await;
            
            if needs_download {
                tracing::info!("Security models will be downloaded on first message");
                initialization_messages.push(
                    Message::assistant().with_text(
                        "🔒 **Security System Ready**\n\nSecurity models will be initialized when you send your first message. This may take up to a minute on first run."
                    )
                );
            } else {
                tracing::info!("Security models are already cached");
                initialization_messages.push(
                    Message::assistant().with_text(
                        "🔒 **Security System Ready**\n\nPrompt injection detection is active and ready to protect your conversations."
                    )
                );
            }
        }
        
        let mut manager_lock = self.security_manager.lock().await;
        *manager_lock = Some(security_manager);
        
        Ok(initialization_messages)
    }

    /// Configure security without returning initialization messages (for backward compatibility)
    pub async fn configure_security_silent(&self, config: crate::security::config::SecurityConfig) {
        let _ = self.configure_security(config).await;
    }

    pub async fn handle_security_confirmation(
        &self,
        request_id: String,
        confirmation: SecurityConfirmation,
    ) {
        match confirmation.permission {
            crate::permission::SecurityPermission::AllowOnce |
            crate::permission::SecurityPermission::AlwaysAllow => {
                tracing::info!("User approved security-flagged message");
                // Note: SecurityConfirmation doesn't include flagged_content
                // The message will be re-scanned when user resends it, but will be allowed through
                // TODO: Need to modify SecurityConfirmation to include flagged_content for proper caching
            },
            crate::permission::SecurityPermission::DenyOnce |
            crate::permission::SecurityPermission::NeverAllow => {
                tracing::info!("User denied security-flagged message");
                // TODO: Need to modify SecurityConfirmation to include flagged_content for proper caching
            }
        }
        
        if let Err(e) = self.security_confirmation_tx.send((request_id, confirmation)).await {
            error!("Failed to send security confirmation: {}", e);
        }
    }

    /// Log security feedback from the user (simple logging approach)
    pub async fn log_security_feedback(
        &self,
        finding_id: &str,
        feedback_type: crate::security::config::FeedbackType,
        user_comment: Option<&str>,
    ) {
        // For now, we just log the feedback
        // In the future, this could be enhanced to store feedback for model improvement
        tracing::info!(
            finding_id = %finding_id,
            feedback_type = ?feedback_type,
            user_comment = ?user_comment,
            "User provided security feedback"
        );

        // If we have a security manager, we could also log through it
        if let Some(security_manager) = self.security_manager.lock().await.as_ref() {
            // We don't have the full context here, so we'll use placeholder values
            // In a more complete implementation, we'd store note context and retrieve it
            security_manager.log_user_feedback(
                finding_id,
                feedback_type,
                crate::security::config::ContentType::UserMessage, // Placeholder
                &crate::security::content_scanner::ThreatLevel::Medium, // Placeholder
                user_comment,
            );
        }
    }

    /// Clear the security message caches (for testing or reset purposes)
    pub async fn clear_security_caches(&self) {
        let mut approved = self.approved_security_messages.lock().await;
        let mut denied = self.denied_security_messages.lock().await;
        let mut pending = self.pending_security_requests.lock().await;
        approved.clear();
        denied.clear();
        pending.clear();
        tracing::info!("Cleared security message caches and pending requests");
    }

    /// Debug: Print current security cache contents
    pub async fn debug_security_caches(&self) {
        let approved = self.approved_security_messages.lock().await;
        let denied = self.denied_security_messages.lock().await;
        tracing::info!("Security cache debug - Approved: {} entries, Denied: {} entries", 
            approved.len(), denied.len());
        
        for (i, hash) in approved.iter().enumerate() {
            tracing::info!("Approved[{}]: {}", i, hash);
        }
        
        for (i, hash) in denied.iter().enumerate() {
            tracing::info!("Denied[{}]: {}", i, hash);
        }
    }

    /// Check if a tool call is a file-reading tool that should be pre-scanned
    fn is_file_reading_tool(&self, tool_call: &mcp_core::tool::ToolCall) -> bool {
        // List of known file-reading tools that should be pre-scanned
        let file_reading_tools = [
            "developer__text_editor", // When command is "view"
            "developer__file_reader",
            "file_reader",
            "read_file",
            "view_file",
            "cat_file",
            // Add more file-reading tool patterns as needed
        ];
        
        // Check if the tool name matches any known file-reading tools
        if file_reading_tools.iter().any(|&pattern| tool_call.name.contains(pattern)) {
            // For developer__text_editor, only pre-scan if command is "view"
            if tool_call.name.contains("text_editor") {
                if let Some(command) = tool_call.arguments.get("command") {
                    return command.as_str() == Some("view");
                }
                return false;
            }
            return true;
        }
        
        false
    }

    /// Extract file path from a file-reading tool call
    fn extract_file_path_from_tool_call(&self, tool_call: &mcp_core::tool::ToolCall) -> Option<String> {
        // Try different common parameter names for file paths
        let path_params = ["path", "file_path", "filepath", "file", "filename"];
        
        for param in &path_params {
            if let Some(value) = tool_call.arguments.get(param) {
                if let Some(path_str) = value.as_str() {
                    return Some(path_str.to_string());
                }
            }
        }
        
        None
    }

    /// Pre-scan file content before tool execution
    async fn pre_scan_file_content(
        &self,
        file_path: &str,
        security_manager: &crate::security::SecurityManager,
    ) -> Result<Option<crate::security::content_scanner::ScanResult>, anyhow::Error> {
        use std::path::Path;
        use tokio::fs;
        
        let path = Path::new(file_path);
        
        // Check if file exists and is readable
        if !path.exists() {
            return Err(anyhow::anyhow!("File does not exist: {}", file_path));
        }
        
        if !path.is_file() {
            return Err(anyhow::anyhow!("Path is not a file: {}", file_path));
        }
        
        // Read file content
        let file_content = match fs::read_to_string(path).await {
            Ok(content) => content,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to read file {}: {}", file_path, e));
            }
        };
        
        // Skip scanning very large files to avoid performance issues
        const MAX_FILE_SIZE_FOR_SCANNING: usize = 1024 * 1024; // 1MB
        if file_content.len() > MAX_FILE_SIZE_FOR_SCANNING {
            tracing::warn!(
                file_path = %file_path,
                file_size = file_content.len(),
                max_size = MAX_FILE_SIZE_FOR_SCANNING,
                "Skipping security scan of large file"
            );
            return Ok(None);
        }
        
        // Skip scanning obviously safe files (empty or very short)
        if file_content.trim().is_empty() || file_content.len() < 10 {
            tracing::debug!(
                file_path = %file_path,
                file_size = file_content.len(),
                "Skipping security scan of empty/tiny file"
            );
            return Ok(None);
        }
        
        tracing::info!(
            file_path = %file_path,
            content_length = file_content.len(),
            content_preview = %if file_content.len() > 200 {
                format!("{}...", &file_content[..200])
            } else {
                file_content.clone()
            },
            "Scanning file content for security threats"
        );
        
        // Scan the file content
        let content_for_scanning = vec![mcp_core::Content::text(file_content)];
        security_manager.scan_content_with_type(&content_for_scanning, crate::security::config::ContentType::FileContent).await
    }

    #[instrument(skip(self, messages, session), fields(user_message))]
    pub async fn reply(
        &self,
        messages: &[Message],
        session: Option<SessionConfig>,
    ) -> anyhow::Result<BoxStream<'_, anyhow::Result<AgentEvent>>> {
        let mut messages = messages.to_vec();
        let reply_span = tracing::Span::current();
        
        // Store security note to add after AI response (for ProcessWithNote policy)
        let mut pending_security_note: Option<crate::security::config::SecurityNote> = None;

        // 🔒 SECURITY GATE: Complete content isolation for blocked messages
        if let Some(security_manager) = &*self.security_manager.lock().await {
            // Find the last user message (the new one we need to scan)
            if let Some(latest_user_message) = messages.iter().rev().find(|msg| msg.role == Role::User) {
                tracing::info!("🔒 SECURITY: Starting comprehensive security scan of latest user message");
                
                // Extract ALL content from the latest user message (text, files, images)
                let mut all_content_for_scanning = Vec::new();
                let mut text_contents = Vec::new();
                let has_file_content = false;
                let mut has_image_content = false;
                
                for content in &latest_user_message.content {
                    match content {
                        MessageContent::Text(text_content) => {
                            text_contents.push(text_content.text.clone());
                            all_content_for_scanning.push(Content::text(text_content.text.clone()));
                        }
                        MessageContent::Image(image_content) => {
                            has_image_content = true;
                            tracing::info!(
                                mime_type = %image_content.mime_type,
                                data_length = image_content.data.len(),
                                "Found image content in user message for security scanning"
                            );
                            // For now, we'll scan image data as text (base64 or similar)
                            // TODO: Could implement specialized image content analysis
                            all_content_for_scanning.push(Content::text(format!(
                                "Image data ({}): {}", 
                                image_content.mime_type,
                                if image_content.data.len() > 200 {
                                    format!("{}...", &image_content.data[..200])
                                } else {
                                    image_content.data.clone()
                                }
                            )));
                        }
                        // Handle other message content types that might contain file data
                        // Note: File content typically comes through tool responses or resources
                        // For now, we'll focus on text and image content in user messages
                        _ => {
                            // Check if this content can be converted to text for scanning
                            if let Some(text) = content.as_text() {
                                text_contents.push(text.to_string());
                                all_content_for_scanning.push(Content::text(text.to_string()));
                            }
                        }
                    }
                }
                
                // TODO: Add file content scanning when files are uploaded
                // This would require detecting when user messages contain file references
                // and extracting the actual file content for scanning
                
                if !all_content_for_scanning.is_empty() {
                    // Create a combined text representation for hashing and caching
                    let combined_text = text_contents.join("\n");
                    let message_hash = Self::hash_message_content(&combined_text);
                    
                    tracing::info!(
                        text_content_count = text_contents.len(),
                        file_content = has_file_content,
                        image_content = has_image_content,
                        total_content_items = all_content_for_scanning.len(),
                        hash = %message_hash,
                        "Prepared content for security scanning"
                    );
                    
                    // Check if this message was previously approved or denied (based on text content hash)
                    let approved_messages = self.approved_security_messages.lock().await;
                    let denied_messages = self.denied_security_messages.lock().await;
                    
                    let is_approved = approved_messages.contains(&message_hash);
                    let is_denied = denied_messages.contains(&message_hash);
                    
                    tracing::info!("🔒 SECURITY: Cache check - approved: {}, denied: {}, approved_count: {}, denied_count: {}", 
                        is_approved, is_denied, approved_messages.len(), denied_messages.len());
                    
                    drop(approved_messages); // Release the locks early
                    drop(denied_messages);
                    
                    if is_approved {
                        tracing::info!(
                            content_preview = %if combined_text.len() > 100 { 
                                format!("{}...", &combined_text[..100]) 
                            } else { 
                                combined_text.clone() 
                            },
                            "🔒 SECURITY: Message was previously approved by user - skipping security scan"
                        );
                        
                        // Skip security scanning entirely for approved messages
                        // Continue with normal message processing
                    } else if is_denied {
                        tracing::info!(
                            content_preview = %if combined_text.len() > 100 { 
                                format!("{}...", &combined_text[..100]) 
                            } else { 
                                combined_text.clone() 
                            },
                            "🔒 SECURITY: Message was previously denied by user - COMPLETE ISOLATION"
                        );
                        
                        // 🚨 COMPLETE CONTENT ISOLATION: Return immediately without any trace of the blocked content
                        return Ok(Box::pin(async_stream::try_stream! {
                            yield AgentEvent::Message(
                                Message::assistant().with_text("This message was previously blocked due to security concerns.")
                            );
                        }));
                    } else {
                        // Only scan messages that haven't been approved or denied
                        
                        // Skip scanning obviously safe messages to reduce false positives (only for text-only messages)
                        let is_obviously_safe = !has_file_content && !has_image_content && 
                            text_contents.len() == 1 && 
                            Self::is_obviously_safe_message(&text_contents[0]);
                        
                        if !is_obviously_safe {
                            tracing::info!(
                                "Scanning user message content for security threats (including files and images)"
                            );
                            
                            match security_manager.scan_content_with_type(&all_content_for_scanning, crate::security::config::ContentType::UserMessage).await {
                                Ok(Some(scan_result)) => {
                                    // For file content, always auto-block without user confirmation
                                    // Users may not know what's in files, so it's safer to block automatically
                                    let action_policy = security_manager.get_action_for_threat(crate::security::config::ContentType::UserMessage, &scan_result.threat_level);
                                    if has_file_content && matches!(action_policy, crate::security::config::ActionPolicy::Block | crate::security::config::ActionPolicy::BlockWithNote) {
                                        tracing::error!(
                                            threat_level = ?scan_result.threat_level,
                                            explanation = %scan_result.explanation,
                                            "Security threat detected in uploaded file content - auto-blocking without user confirmation"
                                        );
                                        
                                        return Ok(Box::pin(async_stream::try_stream! {
                                            yield AgentEvent::Message(
                                                Message::assistant().with_text(format!(
                                                    "🚨 **Security Alert: Malicious File Content Detected**\n\n\
                                                    Your uploaded file contains potentially malicious content that could be used for prompt injection or other security attacks.\n\n\
                                                    **Threat Level:** {:?}\n\
                                                    **Details:** {}\n\n\
                                                    For your safety, this request has been automatically blocked. Please review your file content and try again with a safe file.",
                                                    scan_result.threat_level,
                                                    scan_result.explanation
                                                ))
                                            );
                                        }));
                                    }
                                    
                                    // NEW SMOOTH PROCESSING FLOW 🎯
                                    // Get the action policy for this threat level and content type
                                    let action_policy = security_manager.get_action_for_threat(
                                        crate::security::config::ContentType::UserMessage, 
                                        &scan_result.threat_level
                                    );
                                    
                                    match action_policy {
                                        crate::security::config::ActionPolicy::Block => {
                                            tracing::error!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "🚨 SECURITY: Threat detected in user message - COMPLETE ISOLATION (blocking)"
                                            );
                                            
                                            // 🚨 COMPLETE CONTENT ISOLATION: Return immediately without any trace of the blocked content
                                            let security_note = security_manager.create_security_note(
                                                &scan_result, 
                                                crate::security::config::ContentType::UserMessage
                                            );
                                            
                                            let mut response_message = Message::assistant().with_text(format!(
                                                "🚨 **Security Alert: Request Blocked**\n\n\
                                                Your message contains potentially malicious content and has been blocked for security reasons.\n\n\
                                                **Threat Level:** {:?}\n\
                                                **Details:** {}\n\n\
                                                Please rephrase your request without potentially harmful content.",
                                                scan_result.threat_level,
                                                scan_result.explanation
                                            ));
                                            
                                            // Add security note if available
                                            if let Some(note) = security_note {
                                                response_message = response_message.with_security_note(
                                                    note.finding_id,
                                                    format!("{:?}", note.content_type).to_lowercase(),
                                                    format!("{:?}", note.threat_level).to_lowercase(),
                                                    note.explanation,
                                                    format!("{:?}", note.action_taken).to_lowercase(),
                                                    note.show_feedback_options,
                                                    note.timestamp.to_rfc3339(),
                                                );
                                            }
                                            
                                            return Ok(Box::pin(async_stream::try_stream! {
                                                yield AgentEvent::Message(response_message);
                                            }));
                                        }
                                        crate::security::config::ActionPolicy::BlockWithNote => {
                                            tracing::error!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "🚨 SECURITY: Threat detected in user message - COMPLETE ISOLATION (blocking with feedback)"
                                            );
                                            
                                            // 🚨 COMPLETE CONTENT ISOLATION: Return immediately without any trace of the blocked content
                                            let security_note = security_manager.create_security_note(
                                                &scan_result, 
                                                crate::security::config::ContentType::UserMessage
                                            );
                                            
                                            let mut response_message = Message::assistant().with_text(format!(
                                                "🚨 **Security Alert: Request Blocked**\n\n\
                                                Your message contains potentially malicious content and has been blocked for security reasons.\n\n\
                                                **Threat Level:** {:?}\n\
                                                **Details:** {}\n\n\
                                                Please rephrase your request without potentially harmful content.",
                                                scan_result.threat_level,
                                                scan_result.explanation
                                            ));
                                            
                                            // Add security note if available
                                            if let Some(note) = security_note {
                                                response_message = response_message.with_security_note(
                                                    note.finding_id,
                                                    format!("{:?}", note.content_type).to_lowercase(),
                                                    format!("{:?}", note.threat_level).to_lowercase(),
                                                    note.explanation,
                                                    format!("{:?}", note.action_taken).to_lowercase(),
                                                    note.show_feedback_options,
                                                    note.timestamp.to_rfc3339(),
                                                );
                                            }
                                            
                                            return Ok(Box::pin(async_stream::try_stream! {
                                                yield AgentEvent::Message(response_message);
                                            }));
                                        }
                                        crate::security::config::ActionPolicy::ProcessWithNote => {
                                            tracing::info!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "Security threat detected in user message, processing with note"
                                            );
                                            
                                            // Create and store the security note to add after the AI response
                                            if let Some(note) = security_manager.create_security_note(
                                                &scan_result, 
                                                crate::security::config::ContentType::UserMessage
                                            ) {
                                                pending_security_note = Some(note);
                                            }
                                            // Continue processing - the note will be added after the AI response
                                        }
                                        crate::security::config::ActionPolicy::Process => {
                                            tracing::info!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "Security threat detected in user message, processing silently"
                                            );
                                            // Continue processing silently
                                        }
                                        crate::security::config::ActionPolicy::LogOnly => {
                                            tracing::info!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "Security threat detected in user message, logging only"
                                            );
                                            // Continue processing, just log
                                        }
                                        // Legacy support for old policies
                                        crate::security::config::ActionPolicy::AskUser => {
                                            tracing::warn!(
                                                threat_level = ?scan_result.threat_level,
                                                explanation = %scan_result.explanation,
                                                "Security threat detected in user message, using legacy confirmation flow"
                                            );
                                            
                                            // Generate unique request ID
                                            let request_id = format!("sec_{}", nanoid::nanoid!(8));
                                            let threat_level_str = format!("{:?}", scan_result.threat_level);
                                            
                                            // Store the flagged content for this request
                                            {
                                                let mut pending_requests = self.pending_security_requests.lock().await;
                                                pending_requests.insert(request_id.clone(), combined_text.clone());
                                            }
                                            
                                            // Create tool confirmation request that looks like a security tool
                                            let security_message = Message::assistant()
                                                .with_tool_confirmation_request(
                                                    request_id.clone(),
                                                    "security_scanner".to_string(),
                                                    serde_json::json!({
                                                        "threat_level": threat_level_str,
                                                        "explanation": scan_result.explanation,
                                                        "flagged_content": combined_text.clone(),
                                                        "has_file_content": has_file_content,
                                                        "has_image_content": has_image_content
                                                    }),
                                                    Some(format!(
                                                        "🚨 Security Alert: {} threat detected{}\n\n{}\n\nDo you want to proceed with this message?", 
                                                        threat_level_str,
                                                        if has_image_content { " in message with image content" } else { "" },
                                                        scan_result.explanation
                                                    )),
                                                );
                                            
                                            return Ok(Box::pin(async_stream::try_stream! {
                                                yield AgentEvent::Message(security_message);
                                            }));
                                        }
                                        _ => {
                                            // Default: continue processing
                                            tracing::info!(
                                                threat_level = ?scan_result.threat_level,
                                                action_policy = ?action_policy,
                                                "Security threat detected, using default processing"
                                            );
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // Security scanning is disabled, continue normally
                                }
                                Err(e) => {
                                    let error_msg = e.to_string();
                                    if error_msg.contains("SECURITY_NOT_READY:") {
                                        // Extract the user-friendly message and clone it
                                        let user_message = error_msg.strip_prefix("SECURITY_NOT_READY: ")
                                            .unwrap_or("Initialising Goose, this may take up to a minute")
                                            .to_string(); // Clone to owned string
                                        
                                        tracing::info!("Security system not ready, blocking user message: {}", user_message);
                                        
                                        // Return a message telling the user to wait
                                        return Ok(Box::pin(async_stream::try_stream! {
                                            yield AgentEvent::Message(
                                                Message::assistant().with_text(format!("🔒 {}", user_message))
                                            );
                                        }));
                                    } else {
                                        // Other security errors should be logged but not block the user
                                        tracing::warn!("Security scanning failed: {}", e);
                                    }
                                }
                            }
                        } else {
                            tracing::debug!(
                                content = %combined_text,
                                "Skipping security scan of obviously safe short text-only message"
                            );
                            // Continue - this message is safe
                        }
                    }
                }
            }
            
            // 🔒 SECURITY: Filter out denied messages from conversation history BEFORE processing
            // This ensures the LLM never sees blocked content at all
            let denied_messages = self.denied_security_messages.lock().await;
            let original_message_count = messages.len();
            messages.retain(|message| {
                if message.role == Role::User {
                    // Check if this user message was denied
                    let text_contents: Vec<String> = message.content.iter()
                        .filter_map(|c| c.as_text().map(String::from))
                        .collect();
                    if !text_contents.is_empty() {
                        let combined_text = text_contents.join("\n");
                        let message_hash = Self::hash_message_content(&combined_text);
                        let is_denied = denied_messages.contains(&message_hash);
                        if is_denied {
                            tracing::info!(
                                content_preview = %if combined_text.len() > 100 { 
                                    format!("{}...", &combined_text[..100]) 
                                } else { 
                                    combined_text.clone() 
                                },
                                "🔒 SECURITY: COMPLETE ISOLATION - Filtering out denied message from conversation history"
                            );
                            return false; // Remove this message - LLM will never see it
                        }
                    }
                }
                true // Keep this message
            });
            drop(denied_messages);
            
            if messages.len() != original_message_count {
                tracing::info!("🔒 SECURITY: COMPLETE ISOLATION - Filtered out {} denied messages from conversation history", 
                    original_message_count - messages.len());
            }
        }

        // Load settings from config
        let config = Config::global();

        // Setup tools and prompt
        let (mut tools, mut toolshim_tools, mut system_prompt) =
            self.prepare_tools_and_prompt().await?;

        // Get goose_mode from config, but override with execution_mode if provided in session config
        let mut goose_mode = config.get_param("GOOSE_MODE").unwrap_or("auto".to_string());

        // If this is a scheduled job with an execution_mode, override the goose_mode
        if let Some(session_config) = &session {
            if let Some(execution_mode) = &session_config.execution_mode {
                // Map "foreground" to "auto" and "background" to "chat"
                goose_mode = match execution_mode.as_str() {
                    "foreground" => "auto".to_string(),
                    "background" => "chat".to_string(),
                    _ => goose_mode,
                };
                tracing::info!(
                    "Using execution_mode '{}' which maps to goose_mode '{}'",
                    execution_mode,
                    goose_mode
                );
            }
        }

        let (tools_with_readonly_annotation, tools_without_annotation) =
            Self::categorize_tools_by_annotation(&tools);

        if let Some(content) = messages
            .last()
            .and_then(|msg| msg.content.first())
            .and_then(|c| c.as_text())
        {
            debug!("user_message" = &content);
        }

        Ok(Box::pin(async_stream::try_stream! {
            let _ = reply_span.enter();
            loop {
                match Self::generate_response_from_provider(
                    self.provider().await?,
                    &system_prompt,
                    &messages,
                    &tools,
                    &toolshim_tools,
                ).await {
                    Ok((response, usage)) => {
                        // NOTE: Agent response scanning disabled - causes too many false positives
                        // Only scan user input messages, not agent responses
                        let safe_response = response.clone();
                        // Emit model change event if provider is lead-worker
                        let provider = self.provider().await?;
                        if let Some(lead_worker) = provider.as_lead_worker() {
                            // The actual model used is in the usage
                            let active_model = usage.model.clone();
                            let (lead_model, worker_model) = lead_worker.get_model_info();
                            let mode = if active_model == lead_model {
                                "lead"
                            } else if active_model == worker_model {
                                "worker"
                            } else {
                                "unknown"
                            };

                            yield AgentEvent::ModelChange {
                                model: active_model,
                                mode: mode.to_string(),
                            };
                        }

                        // record usage for the session in the session file
                        if let Some(session_config) = session.clone() {
                            Self::update_session_metrics(session_config, &usage, messages.len()).await?;
                        }

                        // categorize the type of requests we need to handle
                        let (frontend_requests,
                            remaining_requests,
                            filtered_response) =
                            self.categorize_tool_requests(&safe_response).await;

                        // Record tool calls in the router selector
                        let selector = self.router_tool_selector.lock().await.clone();
                        if let Some(selector) = selector {
                            // Record frontend tool calls
                            for request in &frontend_requests {
                                if let Ok(tool_call) = &request.tool_call {
                                    if let Err(e) = selector.record_tool_call(&tool_call.name).await {
                                        tracing::error!("Failed to record frontend tool call: {}", e);
                                    }
                                }
                            }
                            // Record remaining tool calls
                            for request in &remaining_requests {
                                if let Ok(tool_call) = &request.tool_call {
                                    if let Err(e) = selector.record_tool_call(&tool_call.name).await {
                                        tracing::error!("Failed to record tool call: {}", e);
                                    }
                                }
                            }
                        }
                        // Yield the assistant's response with frontend tool requests filtered out
                        yield AgentEvent::Message(filtered_response.clone());

                        // Add security note if we have one (for ProcessWithNote policy)
                        if let Some(security_note) = pending_security_note.take() {
                            let security_note_message = Message::assistant().with_security_note(
                                security_note.finding_id,
                                format!("{:?}", security_note.content_type).to_lowercase(),
                                format!("{:?}", security_note.threat_level).to_lowercase(),
                                security_note.explanation,
                                format!("{:?}", security_note.action_taken).to_lowercase(),
                                security_note.show_feedback_options,
                                security_note.timestamp.to_rfc3339(),
                            );
                            yield AgentEvent::Message(security_note_message);
                        }

                        tokio::task::yield_now().await;

                        let num_tool_requests = frontend_requests.len() + remaining_requests.len();
                        if num_tool_requests == 0 {
                            break;
                        }

                        // Process tool requests depending on frontend tools and then goose_mode
                        let message_tool_response = Arc::new(Mutex::new(Message::user()));

                        // First handle any frontend tool requests
                        let mut frontend_tool_stream = self.handle_frontend_tool_requests(
                            &frontend_requests,
                            message_tool_response.clone()
                        );

                        // we have a stream of frontend tools to handle, inside the stream
                        // execution is yeield back to this reply loop, and is of the same Message
                        // type, so we can yield that back up to be handled
                        while let Some(msg) = frontend_tool_stream.try_next().await? {
                            yield AgentEvent::Message(msg);
                        }

                        // Clone goose_mode once before the match to avoid move issues
                        let mode = goose_mode.clone();
                        if mode.as_str() == "chat" {
                            // Skip all tool calls in chat mode
                            for request in remaining_requests {
                                let mut response = message_tool_response.lock().await;
                                *response = response.clone().with_tool_response(
                                    request.id.clone(),
                                    Ok(vec![Content::text(CHAT_MODE_TOOL_SKIPPED_RESPONSE)]),
                                );
                            }
                        } else {
                            // At this point, we have handled the frontend tool requests and know goose_mode != "chat"
                            // What remains is handling the remaining tool requests (enable extension,
                            // regular tool calls) in goose_mode == ["auto", "approve" or "smart_approve"]
                            let mut permission_manager = PermissionManager::default();
                            let (permission_check_result, enable_extension_request_ids) = check_tool_permissions(
                                &remaining_requests,
                                &mode,
                                tools_with_readonly_annotation.clone(),
                                tools_without_annotation.clone(),
                                &mut permission_manager,
                                self.provider().await?).await;

                            // Handle pre-approved and read-only tools in parallel
                            let mut tool_futures: Vec<(String, ToolStream)> = Vec::new();

                            // Skip the confirmation for approved tools
                            for request in &permission_check_result.approved {
                                if let Ok(tool_call) = request.tool_call.clone() {
                                    let (req_id, tool_result) = self.dispatch_tool_call(tool_call, request.id.clone()).await;

                                    tool_futures.push((req_id, match tool_result {
                                        Ok(result) => tool_stream(
                                            result.notification_stream.unwrap_or_else(|| Box::new(stream::empty())),
                                            result.result,
                                        ),
                                        Err(e) => tool_stream(
                                            Box::new(stream::empty()),
                                            futures::future::ready(Err(e)),
                                        ),
                                    }));
                                }
                            }

                            for request in &permission_check_result.denied {
                                let mut response = message_tool_response.lock().await;
                                *response = response.clone().with_tool_response(
                                    request.id.clone(),
                                    Ok(vec![Content::text(DECLINED_RESPONSE)]),
                                );
                            }

                            // We need interior mutability in handle_approval_tool_requests
                            let tool_futures_arc = Arc::new(Mutex::new(tool_futures));

                            // Process tools requiring approval (enable extension, regular tool calls)
                            let mut tool_approval_stream = self.handle_approval_tool_requests(
                                &permission_check_result.needs_approval,
                                tool_futures_arc.clone(),
                                &mut permission_manager,
                                message_tool_response.clone()
                            );

                            // We have a stream of tool_approval_requests to handle
                            // Execution is yielded back to this reply loop, and is of the same Message
                            // type, so we can yield the Message back up to be handled and grab any
                            // confirmations or denials
                            while let Some(msg) = tool_approval_stream.try_next().await? {
                                yield AgentEvent::Message(msg);
                            }

                            tool_futures = {
                                // Lock the mutex asynchronously
                                let mut futures_lock = tool_futures_arc.lock().await;
                                // Drain the vector and collect into a new Vec
                                futures_lock.drain(..).collect::<Vec<_>>()
                            };

                            let with_id = tool_futures
                                .into_iter()
                                .map(|(request_id, stream)| {
                                    stream.map(move |item| (request_id.clone(), item))
                                })
                                .collect::<Vec<_>>();

                            let mut combined = stream::select_all(with_id);

                            let mut all_install_successful = true;

                            while let Some((request_id, item)) = combined.next().await {
                                match item {
                                    ToolStreamItem::Result(output) => {
                                        if enable_extension_request_ids.contains(&request_id) && output.is_err(){
                                            all_install_successful = false;
                                        }
                                        
                                        // 🔒 SECURITY: Post-execution output scanning (lighter since we pre-scanned inputs)
                                        let safe_output = if let Ok(ref content) = output {
                                            if let Some(security_manager) = &*self.security_manager.lock().await {
                                                tracing::debug!(
                                                    request_id = %request_id,
                                                    "🔒 SECURITY: Post-execution scanning of tool output content"
                                                );
                                                
                                                // Only scan output content that might contain external/untrusted data
                                                // Since we already pre-scanned inputs, focus on output threats
                                                if let Ok(Some(scan_result)) = security_manager.scan_content_with_type(content, crate::security::config::ContentType::ToolResult).await {
                                                    let action_policy = security_manager.get_action_for_threat(crate::security::config::ContentType::ToolResult, &scan_result.threat_level);
                                                    
                                                    // Create security note if needed (for ProcessWithNote, Block, or BlockWithNote actions)
                                                    if let Some(security_note) = security_manager.create_security_note(&scan_result, crate::security::config::ContentType::ToolResult) {
                                                        tracing::info!(
                                                            threat_level = ?scan_result.threat_level,
                                                            action = ?action_policy,
                                                            explanation = %scan_result.explanation,
                                                            "🔒 SECURITY: Threat detected in tool output, creating security note"
                                                        );
                                                        
                                                        // Create a message with the security note
                                                        let security_note_message = Message::assistant().with_security_note(
                                                            security_note.finding_id.clone(),
                                                            "tool_result".to_string(),
                                                            format!("{:?}", scan_result.threat_level),
                                                            scan_result.explanation.clone(),
                                                            format!("{:?}", action_policy),
                                                            security_note.show_feedback_options,
                                                            security_note.timestamp.to_rfc3339(),
                                                        );
                                                        
                                                        // Yield the security note message
                                                        yield AgentEvent::Message(security_note_message);
                                                    }
                                                    
                                                    // Apply the action policy to output content
                                                    match action_policy {
                                                        crate::security::config::ActionPolicy::Block | 
                                                        crate::security::config::ActionPolicy::BlockWithNote => {
                                                            tracing::warn!(
                                                                threat_level = ?scan_result.threat_level,
                                                                explanation = %scan_result.explanation,
                                                                "🚨 SECURITY: Blocking tool output due to security threat"
                                                            );
                                                            // Replace with safe content
                                                            let safe_content = security_manager.get_safe_content(content, &scan_result, crate::security::config::ContentType::ToolResult);
                                                            Ok(safe_content)
                                                        },
                                                        crate::security::config::ActionPolicy::ProcessWithNote => {
                                                            tracing::info!(
                                                                threat_level = ?scan_result.threat_level,
                                                                explanation = %scan_result.explanation,
                                                                "🔒 SECURITY: Processing tool output with security note"
                                                            );
                                                            // Process the content but note was already created above
                                                            output
                                                        },
                                                        _ => {
                                                            // Process, LogOnly, or other policies - just pass through
                                                            output
                                                        }
                                                    }
                                                } else {
                                                    output
                                                }
                                            } else {
                                                output
                                            }
                                        } else {
                                            output
                                        };
                                        
                                        let mut response = message_tool_response.lock().await;
                                        *response = response.clone().with_tool_response(request_id, safe_output);
                                    },
                                    ToolStreamItem::Message(msg) => {
                                        yield AgentEvent::McpNotification((request_id, msg))
                                    }
                                }
                            }

                            // Update system prompt and tools if installations were successful
                            if all_install_successful {
                                (tools, toolshim_tools, system_prompt) = self.prepare_tools_and_prompt().await?;
                            }
                        }

                        let final_message_tool_resp = message_tool_response.lock().await.clone();
                        yield AgentEvent::Message(final_message_tool_resp.clone());

                        messages.push(safe_response);
                        messages.push(final_message_tool_resp);
                    },
                    Err(ProviderError::ContextLengthExceeded(_)) => {
                        // At this point, the last message should be a user message
                        // because call to provider led to context length exceeded error
                        // Immediately yield a special message and break
                        yield AgentEvent::Message(Message::assistant().with_context_length_exceeded(
                            "The context length of the model has been exceeded. Please start a new session and try again.",
                        ));
                        break;
                    },
                    Err(e) => {
                        // Create an error message & terminate the stream
                        error!("Error: {}", e);
                        yield AgentEvent::Message(Message::assistant().with_text(format!("Ran into this error: {e}.\n\nPlease retry if you think this is a transient or recoverable error.")));
                        break;
                    }
                }

                // Yield control back to the scheduler to prevent blocking
                tokio::task::yield_now().await;
            }
        }))
    }

    /// Extend the system prompt with one line of additional instruction
    pub async fn extend_system_prompt(&self, instruction: String) {
        let mut prompt_manager = self.prompt_manager.lock().await;
        prompt_manager.add_system_prompt_extra(instruction);
    }

    /// Update the provider used by this agent
    pub async fn update_provider(&self, provider: Arc<dyn Provider>) -> Result<()> {
        *self.provider.lock().await = Some(provider.clone());
        self.update_router_tool_selector(Some(provider), None)
            .await?;
        Ok(())
    }

    pub async fn update_router_tool_selector(
        &self,
        provider: Option<Arc<dyn Provider>>,
        reindex_all: Option<bool>,
    ) -> Result<()> {
        let config = Config::global();
        let extension_manager = self.extension_manager.lock().await;
        let provider = match provider {
            Some(p) => p,
            None => self.provider().await?,
        };

        let router_tool_selection_strategy = config
            .get_param("GOOSE_ROUTER_TOOL_SELECTION_STRATEGY")
            .unwrap_or_else(|_| "default".to_string());

        let strategy = match router_tool_selection_strategy.to_lowercase().as_str() {
            "vector" => Some(RouterToolSelectionStrategy::Vector),
            "llm" => Some(RouterToolSelectionStrategy::Llm),
            _ => None,
        };

        let selector = match strategy {
            Some(RouterToolSelectionStrategy::Vector) => {
                let table_name = generate_table_id();
                let selector = create_tool_selector(strategy, provider.clone(), Some(table_name))
                    .await
                    .map_err(|e| anyhow!("Failed to create tool selector: {}", e))?;
                Arc::new(selector)
            }
            Some(RouterToolSelectionStrategy::Llm) => {
                let selector = create_tool_selector(strategy, provider.clone(), None)
                    .await
                    .map_err(|e| anyhow!("Failed to create tool selector: {}", e))?;
                Arc::new(selector)
            }
            None => return Ok(()),
        };

        // First index platform tools
        ToolRouterIndexManager::index_platform_tools(&selector, &extension_manager).await?;

        if reindex_all.unwrap_or(false) {
            let enabled_extensions = extension_manager.list_extensions().await?;
            for extension_name in enabled_extensions {
                if let Err(e) = ToolRouterIndexManager::update_extension_tools(
                    &selector,
                    &extension_manager,
                    &extension_name,
                    "add",
                )
                .await
                {
                    tracing::error!(
                        "Failed to index tools for extension {}: {}",
                        extension_name,
                        e
                    );
                }
            }
        }

        // Update the selector
        *self.router_tool_selector.lock().await = Some(selector.clone());
        Ok(())
    }

    /// Override the system prompt with a custom template
    pub async fn override_system_prompt(&self, template: String) {
        let mut prompt_manager = self.prompt_manager.lock().await;
        prompt_manager.set_system_prompt_override(template);
    }

    pub async fn list_extension_prompts(&self) -> HashMap<String, Vec<Prompt>> {
        let extension_manager = self.extension_manager.lock().await;
        extension_manager
            .list_prompts()
            .await
            .expect("Failed to list prompts")
    }

    pub async fn get_prompt(&self, name: &str, arguments: Value) -> Result<GetPromptResult> {
        let extension_manager = self.extension_manager.lock().await;

        // First find which extension has this prompt
        let prompts = extension_manager
            .list_prompts()
            .await
            .map_err(|e| anyhow!("Failed to list prompts: {}", e))?;

        if let Some(extension) = prompts
            .iter()
            .find(|(_, prompt_list)| prompt_list.iter().any(|p| p.name == name))
            .map(|(extension, _)| extension)
        {
            return extension_manager
                .get_prompt(extension, name, arguments)
                .await
                .map_err(|e| anyhow!("Failed to get prompt: {}", e));
        }

        Err(anyhow!("Prompt '{}' not found", name))
    }

    pub async fn get_plan_prompt(&self) -> anyhow::Result<String> {
        // For plan prompt, don't re-scan already-enabled extensions
        let extension_manager = self.extension_manager.lock().await;
        let tools = extension_manager.get_prefixed_tools(None).await?;
        let tools_info = tools
            .into_iter()
            .map(|tool| {
                ToolInfo::new(
                    &tool.name,
                    &tool.description,
                    get_parameter_names(&tool),
                    None,
                )
            })
            .collect();

        let plan_prompt = extension_manager.get_planning_prompt(tools_info).await;

        Ok(plan_prompt)
    }

    pub async fn handle_tool_result(&self, id: String, result: ToolResult<Vec<Content>>) {
        if let Err(e) = self.tool_result_tx.send((id, result)).await {
            tracing::error!("Failed to send tool result: {}", e);
        }
    }

    pub async fn create_recipe(&self, mut messages: Vec<Message>) -> Result<Recipe> {
        let extension_manager = self.extension_manager.lock().await;
        let extensions_info = extension_manager.get_extensions_info().await;

        // Get model name from provider
        let provider = self.provider().await?;
        let model_config = provider.get_model_config();
        let model_name = &model_config.model_name;

        let prompt_manager = self.prompt_manager.lock().await;
        let system_prompt = prompt_manager.build_system_prompt(
            extensions_info,
            self.frontend_instructions.lock().await.clone(),
            extension_manager.suggest_disable_extensions_prompt().await,
            Some(model_name),
            None,
        );

        let recipe_prompt = prompt_manager.get_recipe_prompt().await;
        let tools = extension_manager.get_prefixed_tools(None).await?;

        messages.push(Message::user().with_text(recipe_prompt));

        let (result, _usage) = self
            .provider
            .lock()
            .await
            .as_ref()
            .unwrap()
            .complete(&system_prompt, &messages, &tools)
            .await?;

        let content = result.as_concat_text();

        // the response may be contained in ```json ```, strip that before parsing json
        let re = Regex::new(r"(?s)```[^\n]*\n(.*?)\n```").unwrap();
        let clean_content = re
            .captures(&content)
            .and_then(|caps| caps.get(1).map(|m| m.as_str()))
            .unwrap_or(&content)
            .trim()
            .to_string();

        // try to parse json response from the LLM
        let (instructions, activities) =
            if let Ok(json_content) = serde_json::from_str::<Value>(&clean_content) {
                let instructions = json_content
                    .get("instructions")
                    .ok_or_else(|| anyhow!("Missing 'instructions' in json response"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("instructions' is not a string"))?
                    .to_string();

                let activities = json_content
                    .get("activities")
                    .ok_or_else(|| anyhow!("Missing 'activities' in json response"))?
                    .as_array()
                    .ok_or_else(|| anyhow!("'activities' is not an array'"))?
                    .iter()
                    .map(|act| {
                        act.as_str()
                            .map(|s| s.to_string())
                            .ok_or(anyhow!("'activities' array element is not a string"))
                    })
                    .collect::<Result<_, _>>()?;

                (instructions, activities)
            } else {
                // If we can't get valid JSON, try string parsing
                // Use split_once to get the content after "Instructions:".
                let after_instructions = content
                    .split_once("instructions:")
                    .map(|(_, rest)| rest)
                    .unwrap_or(&content);

                // Split once more to separate instructions from activities.
                let (instructions_part, activities_text) = after_instructions
                    .split_once("activities:")
                    .unwrap_or((after_instructions, ""));

                let instructions = instructions_part
                    .trim_end_matches(|c: char| c.is_whitespace() || c == '#')
                    .trim()
                    .to_string();
                let activities_text = activities_text.trim();

                // Regex to remove bullet markers or numbers with an optional dot.
                let bullet_re = Regex::new(r"^[•\-\*\d]+\.?\s*").expect("Invalid regex");

                // Process each line in the activities section.
                let activities: Vec<String> = activities_text
                    .lines()
                    .map(|line| bullet_re.replace(line, "").to_string())
                    .map(|s| s.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();

                (instructions, activities)
            };

        let extensions = ExtensionConfigManager::get_all().unwrap_or_default();
        let extension_configs: Vec<_> = extensions
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.config.clone())
            .collect();

        let author = Author {
            contact: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            metadata: None,
        };

        // Ideally we'd get the name of the provider we are using from the provider itself
        // but it doesn't know and the plumbing looks complicated.
        let config = Config::global();
        let provider_name: String = config
            .get_param("GOOSE_PROVIDER")
            .expect("No provider configured. Run 'goose configure' first");

        let settings = Settings {
            goose_provider: Some(provider_name.clone()),
            goose_model: Some(model_name.clone()),
            temperature: Some(model_config.temperature.unwrap_or(0.0)),
        };

        let recipe = Recipe::builder()
            .title("Custom recipe from chat")
            .description("a custom recipe instance from this chat session")
            .instructions(instructions)
            .activities(activities)
            .extensions(extension_configs)
            .settings(settings)
            .author(author)
            .build()
            .expect("valid recipe");

        Ok(recipe)
    }
}
