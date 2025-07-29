/// Type conversion utilities for handling compatibility between different MCP type systems
use std::sync::Arc;
use std::borrow::Cow;
use serde_json::Value;
use anyhow::Result;
use futures::Stream;
use futures::StreamExt;

use mcp_core::tool::{Tool as McpCoreTool, ToolAnnotations as McpCoreToolAnnotations};
use mcp_core::protocol::JsonRpcMessage;
use rmcp::model::{Tool as RmcpTool, ToolAnnotations as RmcpToolAnnotations, ServerNotification};

/// Convert from rmcp::model::Tool to mcp_core::Tool
pub fn rmcp_tool_to_mcp_core(tool: &RmcpTool) -> McpCoreTool {
    let annotations = tool.annotations.as_ref().map(|a| McpCoreToolAnnotations {
        title: a.title.clone(),
        read_only_hint: a.read_only_hint.unwrap_or(false),
        destructive_hint: a.destructive_hint.unwrap_or(true),
        idempotent_hint: a.idempotent_hint.unwrap_or(false),
        open_world_hint: a.open_world_hint.unwrap_or(true),
    });

    // Convert Arc<JsonObject> to Value
    let input_schema = serde_json::to_value(&**tool.input_schema)
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

    McpCoreTool::new(
        tool.name.to_string(),
        tool.description.as_deref().unwrap_or("").to_string(),
        input_schema,
        annotations,
    )
}

/// Convert from mcp_core::Tool to rmcp::model::Tool
pub fn mcp_core_tool_to_rmcp(tool: &McpCoreTool) -> RmcpTool {
    let annotations = tool.annotations.as_ref().map(|a| RmcpToolAnnotations {
        title: a.title.clone(),
        read_only_hint: Some(a.read_only_hint),
        destructive_hint: Some(a.destructive_hint),
        idempotent_hint: Some(a.idempotent_hint),
        open_world_hint: Some(a.open_world_hint),
    });

    // Convert Value to Arc<JsonObject>
    let input_schema = match &tool.input_schema {
        Value::Object(map) => Arc::new(map.clone()),
        _ => {
            // If it's not an object, create an empty object
            Arc::new(serde_json::Map::new())
        }
    };

    RmcpTool {
        name: Cow::Owned(tool.name.clone()),
        description: if tool.description.is_empty() {
            None
        } else {
            Some(Cow::Owned(tool.description.clone()))
        },
        input_schema,
        annotations,
    }
}

/// Convert a vector of rmcp tools to mcp_core tools
pub fn rmcp_tools_to_mcp_core(tools: &[RmcpTool]) -> Vec<McpCoreTool> {
    tools.iter().map(rmcp_tool_to_mcp_core).collect()
}

/// Convert a vector of mcp_core tools to rmcp tools
pub fn mcp_core_tools_to_rmcp(tools: &[McpCoreTool]) -> Vec<RmcpTool> {
    tools.iter().map(mcp_core_tool_to_rmcp).collect()
}

/// Convert ServerNotification to JsonRpcMessage
/// This is a simple conversion - in a real implementation you might need more sophisticated mapping
pub fn server_notification_to_jsonrpc(notification: ServerNotification) -> JsonRpcMessage {
    // For now, we'll serialize the ServerNotification and create a JsonRpcMessage
    // This is a placeholder implementation - you may need to adjust based on actual types
    match serde_json::to_value(&notification) {
        Ok(value) => JsonRpcMessage::Notification {
            method: "server_notification".to_string(),
            params: Some(value),
        },
        Err(_) => JsonRpcMessage::Notification {
            method: "server_notification".to_string(),
            params: None,
        },
    }
}

/// Convert a stream of ServerNotification to a stream of JsonRpcMessage
pub fn convert_notification_stream<S>(stream: S) -> impl Stream<Item = JsonRpcMessage> + Send + Unpin + 'static
where
    S: Stream<Item = ServerNotification> + Send + Unpin + 'static,
{
    stream.map(server_notification_to_jsonrpc)
}