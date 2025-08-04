use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::{DateTime, Utc};
use crate::types::{ScanResult, ContentType};

/// Security event that gets logged to external systems (e.g., Databricks)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for this security event
    pub event_id: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of content that was scanned
    pub content_type: ContentType,
    /// The actual content that was scanned (truncated for storage)
    pub scanned_content: String,
    /// Full length of the original content
    pub content_length: usize,
    /// Security scan result details
    pub scan_result: SecurityScanDetails,
    /// User context (if available)
    pub user_context: Option<UserContext>,
    /// Session context (if available)
    pub session_context: Option<SessionContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanDetails {
    /// Overall threat level determined by ensemble
    pub threat_level: String,
    /// Final confidence score (weighted ensemble result)
    pub confidence: f32,
    /// Whether the content was flagged for warning
    pub should_warn: bool,
    /// Whether the content was blocked
    pub should_block: bool,
    /// Human-readable explanation
    pub explanation: String,
    /// Scanner that produced this result
    pub scanner_type: String,
    /// Finding ID for tracking false positives
    pub finding_id: String,
    /// Individual model results
    pub model_results: Vec<ModelScanResult>,
    /// Ensemble details
    pub ensemble_details: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelScanResult {
    /// Model name/identifier
    pub model: String,
    /// Confidence score from this model
    pub confidence: f32,
    /// Threat level from this model
    pub threat_level: String,
    /// Weight of this model in ensemble
    pub weight: f32,
    /// Model-specific explanation
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User identifier (hashed/anonymized)
    pub user_id: Option<String>,
    /// IP address (if available)
    pub ip_address: Option<String>,
    /// User agent (if available)
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    /// Session identifier
    pub session_id: Option<String>,
    /// Number of messages in this session
    pub message_count: Option<u32>,
    /// Session duration so far
    pub session_duration: Option<i64>,
}

/// Trait for logging security events to external systems
#[async_trait::async_trait]
pub trait SecurityLogger: Send + Sync {
    /// Log a security event
    async fn log_security_event(&self, event: SecurityEvent) -> Result<()>;
    
    /// Flush any pending events
    async fn flush(&self) -> Result<()>;
    
    /// Check if the logger is enabled
    fn is_enabled(&self) -> bool;
}

/// Databricks-specific security logger
pub struct DatabricksSecurityLogger {
    /// Whether logging is enabled
    enabled: bool,
    /// Databricks connection details
    host: Option<String>,
    token: Option<String>,
    /// Table/database to log to
    table_name: String,
    /// HTTP client for API calls
    client: reqwest::Client,
    /// Buffer for batching events
    event_buffer: Arc<Mutex<Vec<SecurityEvent>>>,
    /// Maximum buffer size before auto-flush
    max_buffer_size: usize,
}

impl DatabricksSecurityLogger {
    pub fn new() -> Self {
        let enabled = std::env::var("DATABRICKS_SECURITY_LOGGING_ENABLED")
            .unwrap_or_default()
            .parse::<bool>()
            .unwrap_or(false);
            
        let host = std::env::var("DATABRICKS_HOST").ok();
        let token = std::env::var("DATABRICKS_TOKEN").ok();
        
        let table_name = std::env::var("DATABRICKS_SECURITY_TABLE")
            .unwrap_or_else(|_| "security.goose_security_events".to_string());

        Self {
            enabled: enabled && host.is_some() && token.is_some(),
            host,
            token,
            table_name,
            client: reqwest::Client::new(),
            event_buffer: Arc::new(Mutex::new(Vec::new())),
            max_buffer_size: 100, // Batch up to 100 events
        }
    }
    
    /// Convert security event to Databricks SQL insert format
    fn event_to_sql_values(&self, event: &SecurityEvent) -> String {
        format!(
            "('{}', '{}', '{}', '{}', {}, '{}', {}, {}, {}, '{}', '{}', '{}', '{}')",
            event.event_id,
            event.timestamp.to_rfc3339(),
            format!("{:?}", event.content_type),
            event.scanned_content.replace("'", "''"), // Escape single quotes
            event.content_length,
            event.scan_result.threat_level,
            event.scan_result.confidence,
            event.scan_result.should_warn,
            event.scan_result.should_block,
            event.scan_result.explanation.replace("'", "''"),
            event.scan_result.scanner_type,
            event.scan_result.finding_id,
            serde_json::to_string(&event.scan_result.model_results)
                .unwrap_or_default()
                .replace("'", "''")
        )
    }
    
    /// Send batched events to Databricks
    async fn send_batch(&self, events: Vec<SecurityEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        
        let host = self.host.as_ref().ok_or_else(|| anyhow::anyhow!("Databricks host not configured"))?;
        let token = self.token.as_ref().ok_or_else(|| anyhow::anyhow!("Databricks token not configured"))?;
        
        // Create SQL INSERT statement
        let values: Vec<String> = events.iter()
            .map(|event| self.event_to_sql_values(event))
            .collect();
            
        let sql = format!(
            "INSERT INTO {} (event_id, timestamp, content_type, scanned_content, content_length, threat_level, confidence, should_warn, should_block, explanation, scanner_type, finding_id, model_results) VALUES {}",
            self.table_name,
            values.join(", ")
        );
        
        // Send to Databricks SQL API
        let url = format!("{}/api/2.0/sql/statements", host);
        
        let payload = serde_json::json!({
            "statement": sql,
            "warehouse_id": std::env::var("DATABRICKS_WAREHOUSE_ID").ok(),
        });
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(
                "Failed to send security events to Databricks: {} - {}",
                response.status(),
                error_text
            );
            return Err(anyhow::anyhow!("Databricks API error: {}", error_text));
        }
        
        tracing::debug!("Successfully sent {} security events to Databricks", events.len());
        Ok(())
    }
}

#[async_trait::async_trait]
impl SecurityLogger for DatabricksSecurityLogger {
    async fn log_security_event(&self, event: SecurityEvent) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        // Add to buffer
        {
            let mut buffer = self.event_buffer.lock().await;
            buffer.push(event);
            
            // Auto-flush if buffer is full
            if buffer.len() >= self.max_buffer_size {
                let events = buffer.drain(..).collect();
                drop(buffer); // Release lock before async call
                
                if let Err(e) = self.send_batch(events).await {
                    tracing::error!("Failed to send security event batch: {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    async fn flush(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        let events = {
            let mut buffer = self.event_buffer.lock().await;
            buffer.drain(..).collect()
        };
        
        self.send_batch(events).await
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// No-op logger for when external logging is disabled
pub struct NoOpSecurityLogger;

#[async_trait::async_trait]
impl SecurityLogger for NoOpSecurityLogger {
    async fn log_security_event(&self, _event: SecurityEvent) -> Result<()> {
        Ok(())
    }
    
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
    
    fn is_enabled(&self) -> bool {
        false
    }
}

/// Create a security logger based on configuration
pub fn create_security_logger() -> Arc<dyn SecurityLogger> {
    // Check if Databricks logging is configured
    if std::env::var("DATABRICKS_SECURITY_LOGGING_ENABLED")
        .unwrap_or_default()
        .parse::<bool>()
        .unwrap_or(false)
    {
        Arc::new(DatabricksSecurityLogger::new())
    } else {
        Arc::new(NoOpSecurityLogger)
    }
}

/// Helper function to convert ScanResult to SecurityEvent
pub fn scan_result_to_security_event(
    scan_result: &ScanResult,
    content_type: ContentType,
    scanned_content: &str,
    user_context: Option<UserContext>,
    session_context: Option<SessionContext>,
) -> SecurityEvent {
    // Extract model results from scan result details if available
    let model_results = if let Some(details) = &scan_result.details {
        if let Some(individual_results) = details.get("individual_results") {
            if let Ok(results) = serde_json::from_value::<Vec<Value>>(individual_results.clone()) {
                results.into_iter().filter_map(|result| {
                    Some(ModelScanResult {
                        model: result.get("scanner")?.as_str()?.to_string(),
                        confidence: result.get("confidence")?.as_f64()? as f32,
                        threat_level: result.get("threat_level")?.as_str()?.to_string(),
                        weight: 1.0, // Default weight if not available
                        explanation: result.get("explanation")?.as_str()?.to_string(),
                    })
                }).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    SecurityEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: scan_result.timestamp,
        content_type,
        scanned_content: if scanned_content.len() > 1000 {
            format!("{}...", &scanned_content[..1000])
        } else {
            scanned_content.to_string()
        },
        content_length: scanned_content.len(),
        scan_result: SecurityScanDetails {
            threat_level: format!("{:?}", scan_result.threat_level),
            confidence: scan_result.confidence,
            should_warn: scan_result.should_warn,
            should_block: scan_result.should_block,
            explanation: scan_result.explanation.clone(),
            scanner_type: scan_result.scanner_type.clone(),
            finding_id: scan_result.finding_id.clone(),
            model_results,
            ensemble_details: scan_result.details.clone(),
        },
        user_context,
        session_context,
    }
}