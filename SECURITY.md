# Goose Security System

This document describes the prompt injection detection system implemented in Goose.

## Overview

The security system provides automated detection of prompt injection attempts and other security threats in content processed by Goose. It uses configurable threat detection models to analyze content and can take various actions based on the detected threat level.

## Architecture

The security system consists of several key components:

### Core Components

1. **SecurityManager** - Main orchestrator that manages scanning and policy enforcement
2. **ContentScanner** - Trait defining the interface for threat detection scanners
3. **MistralNemoScanner** - Implementation using Mistral Nemo model via Ollama
4. **SecurityConfig** - Configuration for security policies and thresholds

### Threat Levels

- `Safe` - No threats detected
- `Low` - Minor potential issues
- `Medium` - Moderate threat level
- `High` - Significant security concern
- `Critical` - Severe security threat

### Action Policies

- `Block` - Replace threatening content with security warnings
- `Sanitize` - Use sanitized version of content if available
- `Warn` - Log warnings but allow content through
- `LogOnly` - Only log detections, no content modification

### Threat Thresholds

- `Any` - Trigger on any threat level above Safe
- `Low` - Trigger on Low and above
- `Medium` - Trigger on Medium and above  
- `High` - Trigger on High and above
- `Critical` - Only trigger on Critical threats

## Configuration

```rust
use goose::security::{SecurityManager, config::SecurityConfig};

let config = SecurityConfig {
    enabled: true,
    scanner_type: ScannerType::MistralNemo,
    ollama_endpoint: "http://localhost:11434".to_string(),
    action_policy: ActionPolicy::Block,
    scan_threshold: ThreatThreshold::Medium,
};

let security_manager = SecurityManager::new(config);
```

## Usage

### Basic Content Scanning

```rust
use mcp_core::Content;

let content = vec![Content::text("User input to analyze")];

match security_manager.scan_content(&content).await {
    Ok(Some(scan_result)) => {
        // Process scan result
        let safe_content = security_manager.get_safe_content(&content, &scan_result);
        // Use safe_content instead of original
    }
    Ok(None) => {
        // Scanner disabled, use original content
    }
    Err(e) => {
        // Handle scanning error
    }
}
```

### Tool Result Scanning

```rust
use serde_json::json;

let tool_name = "shell";
let arguments = json!({"command": "ls -la"});
let result = vec![Content::text("file1.txt\nfile2.txt")];

match security_manager.scan_tool_result(tool_name, &arguments, &result).await {
    Ok(Some(scan_result)) => {
        let safe_result = security_manager.get_safe_content(&result, &scan_result);
        // Use safe_result
    }
    Ok(None) => {
        // Scanner disabled
    }
    Err(e) => {
        // Handle error
    }
}
```

## Setup Requirements

### Ollama Setup

1. Install Ollama from https://ollama.ai/
2. Pull the Mistral Nemo model:
   ```bash
   ollama pull mistral-nemo
   ```
3. Start the Ollama server (usually runs on http://localhost:11434)

### Environment Configuration

The security system can be configured through environment variables or programmatically:

- `GOOSE_SECURITY_ENABLED` - Enable/disable security scanning
- `GOOSE_SECURITY_ENDPOINT` - Ollama endpoint URL
- `GOOSE_SECURITY_THRESHOLD` - Threat threshold level
- `GOOSE_SECURITY_ACTION` - Action policy

## Integration Points

The security system is designed to integrate at key points in the Goose pipeline:

1. **User Input Processing** - Scan incoming user messages
2. **Tool Result Processing** - Scan outputs from tool executions
3. **Content Generation** - Scan generated responses before delivery

## Logging and Monitoring

The security system provides comprehensive logging:

- All scan operations are logged with structured data
- Threat detections include detailed explanations
- Policy actions (block/sanitize/warn) are logged
- Performance metrics for scan operations

## Testing

The security system includes comprehensive unit tests:

```bash
cargo test --lib --package goose security::
```

## Example

See `examples/security_demo.rs` for a complete example of using the security system.

## Future Enhancements

Potential future improvements:

1. **Additional Scanner Types** - Support for other threat detection models
2. **Custom Rules** - User-defined threat detection patterns
3. **Metrics Dashboard** - Real-time security monitoring
4. **Integration Hooks** - Custom callbacks for threat detection events
5. **Content Whitelisting** - Bypass scanning for trusted content sources