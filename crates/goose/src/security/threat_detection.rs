use super::content_scanner::{ContentScanner, ScanResult, ThreatLevel};
use crate::security::config::{EnsembleConfig, EnsembleMember, ScannerType, VotingStrategy};
use anyhow::{Context, Result};
use async_trait::async_trait;
use mcp_core::Content;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

pub struct MistralNemoScanner {
    ollama_endpoint: String,
    model_name: String,
    detection_prompt_template: String,
}

impl MistralNemoScanner {
    pub fn new(ollama_endpoint: String) -> Self {
        Self {
            ollama_endpoint,
            model_name: "mistral-nemo".to_string(),
            detection_prompt_template: include_str!("../prompts/threat_detection.md").to_string(),
        }
    }

    async fn analyze_content(
        &self,
        content: &str,
        tool_context: Option<(&str, &Value)>,
    ) -> Result<ScanResult> {
        // Prepare the prompt with content and optional tool context
        let prompt = self.prepare_detection_prompt(content, tool_context);

        // Log the prompt being sent to Ollama
        tracing::info!(
            "Security scanner sending prompt to Ollama ({}): {}",
            self.model_name,
            prompt.chars().take(200).collect::<String>() + "..."
        );

        // Call the Ollama API using the chat endpoint
        let client = reqwest::Client::new();

        let request_body = serde_json::json!({
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security expert analyzing content for prompt injection and other security threats."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "format": "json",
            "stream": false  // Disable streaming to get a complete response
        });

        tracing::info!(
            "Sending request to Ollama chat API: {}",
            serde_json::to_string(&request_body).unwrap_or_default()
        );

        let response = client
            .post(format!("{}/api/chat", self.ollama_endpoint))
            .json(&request_body)
            .send()
            .await
            .context("Failed to connect to Ollama server")?;

        // Parse the response
        let response_text = response.text().await?;
        tracing::info!("Security scanner received raw response: {}", response_text);

        // Check if we got a single JSON object or a stream of JSON objects
        let response_json: Value = if response_text.contains("\n") {
            // We got a stream of JSON objects, process line by line
            tracing::info!(
                "Detected streaming response despite stream:false, processing line by line"
            );

            let mut full_content = String::new();
            for line in response_text.lines() {
                if let Ok(json) = serde_json::from_str::<Value>(line) {
                    if let Some(content) = json
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                    {
                        full_content.push_str(content);
                    }
                }
            }

            tracing::info!("Assembled content from stream: {}", full_content);

            // Create a synthetic response object
            serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": full_content
                }
            })
        } else {
            // We got a single JSON object
            match serde_json::from_str(&response_text) {
                Ok(json) => json,
                Err(e) => {
                    tracing::error!("Failed to parse Ollama response as JSON: {}", e);
                    return Ok(ScanResult {
                        threat_level: ThreatLevel::Medium,
                        explanation: format!("Failed to parse Ollama response: {}", e),
                        sanitized_content: None,
                    });
                }
            }
        };

        // Extract the message content from the response
        let message_content = response_json
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or_default();

        tracing::info!(
            "Security scanner extracted message content: {}",
            message_content
        );

        // Try to parse the message content as JSON
        let analysis: Value = match serde_json::from_str(message_content) {
            Ok(json) => {
                tracing::info!("Successfully parsed message content as JSON");
                json
            }
            Err(e) => {
                // If parsing fails, try to extract JSON from the response
                // Sometimes the model might add text before or after the JSON
                tracing::warn!("Failed to parse message content as JSON: {}", e);

                // Try to extract JSON using regex
                let re = regex::Regex::new(r"(?s)\{.*\}").unwrap();
                if let Some(captures) = re.find(message_content) {
                    let json_str = captures.as_str();
                    tracing::info!("Extracted JSON from message content: {}", json_str);
                    match serde_json::from_str(json_str) {
                        Ok(json) => json,
                        Err(e) => {
                            tracing::error!("Failed to parse extracted JSON: {}", e);

                            // If we can't parse the JSON, return a default medium threat level
                            // This is a conservative approach - if we can't analyze it, treat it as potentially risky
                            return Ok(ScanResult {
                                threat_level: ThreatLevel::Medium,
                                explanation: format!("Failed to parse security analysis: {}", e),
                                sanitized_content: None,
                            });
                        }
                    }
                } else {
                    tracing::error!("Could not extract JSON from message content");

                    // If we can't find any JSON, assume a conservative medium threat level
                    return Ok(ScanResult {
                        threat_level: ThreatLevel::Low,
                        explanation: "Unable to analyze content - treating as low risk by default"
                            .to_string(),
                        sanitized_content: None,
                    });
                }
            }
        };

        // Extract threat assessment
        self.parse_threat_assessment(analysis, content)
    }

    fn prepare_detection_prompt(
        &self,
        content: &str,
        tool_context: Option<(&str, &Value)>,
    ) -> String {
        let mut prompt = self.detection_prompt_template.clone();

        // Add tool context if available
        if let Some((tool_name, arguments)) = tool_context {
            prompt = prompt.replace(
                "{{TOOL_CONTEXT}}",
                &format!(
                    "Tool name: {}\nTool arguments: {}",
                    tool_name,
                    serde_json::to_string_pretty(arguments).unwrap_or_default()
                ),
            );
        } else {
            prompt = prompt.replace("{{TOOL_CONTEXT}}", "No specific tool context available.");
        }

        // Add the content to analyze
        prompt.replace("{{CONTENT}}", content)
    }

    fn parse_threat_assessment(
        &self,
        analysis: Value,
        _original_content: &str,
    ) -> Result<ScanResult> {
        // Extract fields from the JSON response
        let threat_level_str = analysis
            .get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let explanation = analysis
            .get("explanation")
            .and_then(|v| v.as_str())
            .unwrap_or("No explanation provided")
            .to_string();

        // Convert string threat level to enum
        let threat_level = match threat_level_str.to_lowercase().as_str() {
            "safe" => ThreatLevel::Safe,
            "low" => ThreatLevel::Low,
            "medium" => ThreatLevel::Medium,
            "high" => ThreatLevel::High,
            "critical" => ThreatLevel::Critical,
            _ => ThreatLevel::Medium, // Default to Medium if unknown
        };

        // Get sanitized content if available
        let sanitized_content = if threat_level != ThreatLevel::Safe {
            analysis
                .get("sanitized_content")
                .and_then(|v| v.as_str())
                .map(|s| vec![Content::text(s.to_string())])
        } else {
            None
        };

        Ok(ScanResult {
            threat_level,
            explanation,
            sanitized_content,
        })
    }
}

#[async_trait]
impl ContentScanner for MistralNemoScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        // Combine all content into a single string for analysis
        let combined_content = content
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        self.analyze_content(&combined_content, None).await
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        // Combine all content into a single string for analysis
        let combined_content = result
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        self.analyze_content(&combined_content, Some((tool_name, arguments)))
            .await
    }
}

pub struct LlamaPromptGuard2Scanner {
    model_name: String,
    python_script_path: String,
    confidence_threshold: f32,
}

impl LlamaPromptGuard2Scanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            model_name: "meta-llama/Llama-Prompt-Guard-2-86M".to_string(),
            python_script_path: Self::create_python_script().unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to create Python script for Llama Prompt Guard 2: {}",
                    e
                );
                "llama_prompt_guard2_scanner.py".to_string()
            }),
            confidence_threshold,
        }
    }

    fn create_python_script() -> Result<String> {
        let script_content = r#"#!/usr/bin/env python3
"""
Llama Prompt Guard 2 Scanner for Goose Security System
This script provides a command-line interface to Meta's Llama Prompt Guard 2 model.
"""

import sys
import json
import argparse
import os
from typing import Dict, Any

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    from huggingface_hub import login
except ImportError:
    print(json.dumps({
        "error": "Required packages not installed. Run: pip install torch transformers huggingface_hub"
    }))
    sys.exit(1)

class LlamaPromptGuard2Scanner:
    def __init__(self, model_name: str = "meta-llama/Llama-Prompt-Guard-2-86M"):
        self.model_name = model_name
        self.classifier = None
        self._authenticate()
        self._load_model()
    
    def _authenticate(self):
        """Authenticate with Hugging Face using token from environment variable"""
        hf_token = os.getenv('HUGGINGFACE_TOKEN') or os.getenv('HF_TOKEN')
        if hf_token:
            try:
                login(token=hf_token, add_to_git_credential=False)
                print(f"Successfully authenticated with Hugging Face", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Failed to authenticate with Hugging Face: {e}", file=sys.stderr)
                print(f"Continuing without authentication - may fail for gated models", file=sys.stderr)
        else:
            print(f"No Hugging Face token found in environment variables", file=sys.stderr)
            print(f"Set HUGGINGFACE_TOKEN or HF_TOKEN environment variable for gated models", file=sys.stderr)
    
    def _load_model(self):
        try:
            device = 0 if torch.cuda.is_available() else -1
            self.classifier = pipeline(
                "text-classification",
                model=self.model_name,
                tokenizer=self.model_name,
                device=device,
                top_k=None,  # Get all class probabilities
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load model {self.model_name}: {e}")
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        try:
            # Get model prediction
            outputs = self.classifier([text])
            
            if not outputs or not outputs[0]:
                raise ValueError("No output from model")
            
            # outputs[0] is a list of dicts with 'label' and 'score'
            result = outputs[0]
            
            # Find the prediction with highest score
            if isinstance(result, list):
                best_pred = max(result, key=lambda x: x['score'])
            else:
                best_pred = result
            
            label = best_pred['label']
            confidence = best_pred['score']
            
            # Map Llama Prompt Guard 2 labels to our threat levels
            # LABEL_0 = safe, LABEL_1 = injection (typically)
            if 'LABEL_0' in label or 'safe' in label.lower():
                threat_level = "Safe"
                explanation = f"Content appears safe (confidence: {confidence:.3f})"
            else:
                # Map confidence to threat levels for injections
                if confidence >= 0.9:
                    threat_level = "High"
                elif confidence >= 0.7:
                    threat_level = "Medium"
                else:
                    threat_level = "Low"
                explanation = f"Potential prompt injection detected (confidence: {confidence:.3f})"
            
            return {
                "threat_level": threat_level,
                "explanation": explanation,
                "confidence": confidence,
                "raw_label": label,
                "sanitized_content": None  # Llama Prompt Guard 2 doesn't provide sanitization
            }
            
        except Exception as e:
            return {
                "threat_level": "Medium",
                "explanation": f"Error during analysis: {str(e)}",
                "confidence": 0.0,
                "raw_label": "error",
                "sanitized_content": None
            }

def main():
    parser = argparse.ArgumentParser(description="Llama Prompt Guard 2 Scanner")
    parser.add_argument("--text", required=True, help="Text to analyze")
    parser.add_argument("--model", default="meta-llama/Llama-Prompt-Guard-2-86M", help="Model name")
    args = parser.parse_args()
    
    try:
        scanner = LlamaPromptGuard2Scanner(args.model)
        result = scanner.scan_text(args.text)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "threat_level": "Medium",
            "explanation": f"Scanner initialization failed: {str(e)}",
            "confidence": 0.0,
            "raw_label": "error",
            "sanitized_content": None
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
"#;

        let temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
        let script_path = temp_file.path().with_extension("py");

        fs::write(&script_path, script_content).context("Failed to write Python script")?;

        // Make the script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        Ok(script_path.to_string_lossy().to_string())
    }

    async fn analyze_with_python(&self, text: &str) -> Result<ScanResult> {
        tracing::info!(
            "Analyzing text with Llama Prompt Guard 2: {}",
            text.chars().take(100).collect::<String>() + "..."
        );

        // Execute Python script with environment variables for authentication
        let mut cmd = Command::new("python3");
        cmd.arg(&self.python_script_path)
            .arg("--text")
            .arg(text)
            .arg("--model")
            .arg(&self.model_name);

        // Pass through Hugging Face token environment variables if they exist
        if let Ok(token) = std::env::var("HUGGINGFACE_TOKEN") {
            cmd.env("HUGGINGFACE_TOKEN", token);
        } else if let Ok(token) = std::env::var("HF_TOKEN") {
            cmd.env("HF_TOKEN", token);
        }

        let output = cmd.output().context("Failed to execute Python script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("Python script failed: {}", stderr);
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: format!("Llama Prompt Guard 2 execution failed: {}", stderr),
                sanitized_content: None,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::info!("Llama Prompt Guard 2 raw response: {}", stdout);

        // Parse JSON response
        let analysis: Value =
            serde_json::from_str(&stdout).context("Failed to parse Python script output")?;

        self.parse_analysis_result(analysis)
    }

    fn parse_analysis_result(&self, analysis: Value) -> Result<ScanResult> {
        let threat_level_str = analysis
            .get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("Medium");

        let confidence = analysis
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as f32;

        let explanation = analysis
            .get("explanation")
            .and_then(|v| v.as_str())
            .unwrap_or("No explanation provided")
            .to_string();

        // Apply confidence thresholding - if confidence is below threshold, treat as safe
        let threat_level = if confidence < self.confidence_threshold {
            ThreatLevel::Safe
        } else {
            match threat_level_str.to_lowercase().as_str() {
                "safe" => ThreatLevel::Safe,
                "low" => ThreatLevel::Low,
                "medium" => ThreatLevel::Medium,
                "high" => ThreatLevel::High,
                "critical" => ThreatLevel::Critical,
                _ => ThreatLevel::Medium,
            }
        };

        let final_explanation = if confidence < self.confidence_threshold {
            format!("{} (confidence {:.3} below threshold {:.3}, treating as safe)", 
                    explanation, confidence, self.confidence_threshold)
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult {
            threat_level,
            explanation: final_explanation,
            sanitized_content: None, // Llama Prompt Guard 2 doesn't provide sanitization
        })
    }
}

#[async_trait]
impl ContentScanner for LlamaPromptGuard2Scanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        self.analyze_with_python(&combined_content).await
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        // For tool results, we analyze the content with some context
        let combined_content = result
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        // Add tool context to the analysis
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );

        self.analyze_with_python(&contextual_content).await
    }
}

pub struct LlamaPromptGuardScanner {
    model_name: String,
    python_script_path: String,
    confidence_threshold: f32,
}

impl LlamaPromptGuardScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            model_name: "protectai/deberta-v3-base-prompt-injection-v2".to_string(),
            python_script_path: Self::create_python_script().unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to create Python script for Llama Prompt Guard: {}",
                    e
                );
                "llama_prompt_guard_scanner.py".to_string()
            }),
            confidence_threshold,
        }
    }

    fn create_python_script() -> Result<String> {
        let script_content = r#"#!/usr/bin/env python3
"""
Prompt Injection Detection Scanner for Goose Security System
This script provides a command-line interface to prompt injection detection models.
"""

import sys
import json
import argparse
from typing import Dict, Any

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:
    print(json.dumps({
        "error": "Required packages not installed. Run: pip install torch transformers"
    }))
    sys.exit(1)

class PromptInjectionScanner:
    def __init__(self, model_name: str = "protectai/deberta-v3-base-prompt-injection-v2"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.eval()
        except Exception as e:
            raise RuntimeError(f"Failed to load model {self.model_name}: {e}")
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        try:
            # Tokenize input
            inputs = self.tokenizer(
                text, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512,
                padding=True
            )
            
            # Get model prediction
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)
                predicted_class = torch.argmax(probabilities, dim=-1).item()
                confidence = torch.max(probabilities).item()
            
            # Map prediction to threat level
            # Most models: 0 = safe, 1 = injection
            if predicted_class == 0:
                threat_level = "Safe"
                explanation = f"Content appears safe (confidence: {confidence:.3f})"
            else:
                # Map confidence to threat levels
                if confidence >= 0.9:
                    threat_level = "High"
                elif confidence >= 0.7:
                    threat_level = "Medium"
                else:
                    threat_level = "Low"
                explanation = f"Potential prompt injection detected (confidence: {confidence:.3f})"
            
            return {
                "threat_level": threat_level,
                "explanation": explanation,
                "confidence": confidence,
                "predicted_class": predicted_class,
                "sanitized_content": None  # This model doesn't provide sanitization
            }
            
        except Exception as e:
            return {
                "threat_level": "Medium",
                "explanation": f"Error during analysis: {str(e)}",
                "confidence": 0.0,
                "predicted_class": -1,
                "sanitized_content": None
            }

def main():
    parser = argparse.ArgumentParser(description="Prompt Injection Detection Scanner")
    parser.add_argument("--text", required=True, help="Text to analyze")
    parser.add_argument("--model", default="protectai/deberta-v3-base-prompt-injection-v2", help="Model name")
    args = parser.parse_args()
    
    try:
        scanner = PromptInjectionScanner(args.model)
        result = scanner.scan_text(args.text)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "threat_level": "Medium",
            "explanation": f"Scanner initialization failed: {str(e)}",
            "confidence": 0.0,
            "predicted_class": -1,
            "sanitized_content": None
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
"#;

        let temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
        let script_path = temp_file.path().with_extension("py");

        fs::write(&script_path, script_content).context("Failed to write Python script")?;

        // Make the script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        Ok(script_path.to_string_lossy().to_string())
    }

    async fn analyze_with_python(&self, text: &str) -> Result<ScanResult> {
        tracing::info!(
            "Analyzing text with Prompt Injection Detection model: {}",
            text.chars().take(100).collect::<String>() + "..."
        );

        // Execute Python script
        let output = Command::new("python3")
            .arg(&self.python_script_path)
            .arg("--text")
            .arg(text)
            .arg("--model")
            .arg(&self.model_name)
            .output()
            .context("Failed to execute Python script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("Python script failed: {}", stderr);
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: format!("Prompt injection detection execution failed: {}", stderr),
                sanitized_content: None,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::info!("Prompt injection detection raw response: {}", stdout);

        // Parse JSON response
        let analysis: Value =
            serde_json::from_str(&stdout).context("Failed to parse Python script output")?;

        self.parse_analysis_result(analysis)
    }

    fn parse_analysis_result(&self, analysis: Value) -> Result<ScanResult> {
        let threat_level_str = analysis
            .get("threat_level")
            .and_then(|v| v.as_str())
            .unwrap_or("Medium");

        let confidence = analysis
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as f32;

        let explanation = analysis
            .get("explanation")
            .and_then(|v| v.as_str())
            .unwrap_or("No explanation provided")
            .to_string();

        // Apply confidence thresholding - if confidence is below threshold, treat as safe
        let threat_level = if confidence < self.confidence_threshold {
            ThreatLevel::Safe
        } else {
            match threat_level_str.to_lowercase().as_str() {
                "safe" => ThreatLevel::Safe,
                "low" => ThreatLevel::Low,
                "medium" => ThreatLevel::Medium,
                "high" => ThreatLevel::High,
                "critical" => ThreatLevel::Critical,
                _ => ThreatLevel::Medium,
            }
        };

        let final_explanation = if confidence < self.confidence_threshold {
            format!("{} (confidence {:.3} below threshold {:.3}, treating as safe)", 
                    explanation, confidence, self.confidence_threshold)
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult {
            threat_level,
            explanation: final_explanation,
            sanitized_content: None, // Llama Prompt Guard doesn't provide sanitization
        })
    }
}

#[async_trait]
impl ContentScanner for LlamaPromptGuardScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        self.analyze_with_python(&combined_content).await
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        // For tool results, we analyze the content with some context
        let combined_content = result
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        // Add tool context to the analysis
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );

        self.analyze_with_python(&contextual_content).await
    }
}


// New scanner implementations

pub struct DeepsetDebertaScanner {
    model_name: String,
    python_script_path: String,
    confidence_threshold: f32,
}

impl DeepsetDebertaScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            model_name: "deepset/deberta-v3-base-injection".to_string(),
            python_script_path: Self::create_python_script().unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to create Python script for Deepset DeBERTa: {}",
                    e
                );
                "deepset_deberta_scanner.py".to_string()
            }),
            confidence_threshold,
        }
    }

    fn create_python_script() -> Result<String> {
        let script_content = r#"#!/usr/bin/env python3
import sys
import json
import argparse
from typing import Dict, Any

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:
    print(json.dumps({"error": "Required packages not installed. Run: pip install torch transformers"}))
    sys.exit(1)

class DeepsetDebertaScanner:
    def __init__(self, model_name: str = "deepset/deberta-v3-base-injection"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.eval()
        except Exception as e:
            raise RuntimeError(f"Failed to load model {self.model_name}: {e}")
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)
                predicted_class = torch.argmax(probabilities, dim=-1).item()
                confidence = torch.max(probabilities).item()
            
            if predicted_class == 0:
                threat_level = "Safe"
                explanation = f"Content appears safe (confidence: {confidence:.3f})"
            else:
                if confidence >= 0.9:
                    threat_level = "High"
                elif confidence >= 0.7:
                    threat_level = "Medium"
                else:
                    threat_level = "Low"
                explanation = f"Potential prompt injection detected (confidence: {confidence:.3f})"
            
            return {
                "threat_level": threat_level,
                "explanation": explanation,
                "confidence": confidence,
                "predicted_class": predicted_class,
                "sanitized_content": None
            }
            
        except Exception as e:
            return {
                "threat_level": "Medium",
                "explanation": f"Error during analysis: {str(e)}",
                "confidence": 0.0,
                "predicted_class": -1,
                "sanitized_content": None
            }

def main():
    parser = argparse.ArgumentParser(description="Deepset DeBERTa Scanner")
    parser.add_argument("--text", required=True, help="Text to analyze")
    parser.add_argument("--model", default="deepset/deberta-v3-base-injection", help="Model name")
    args = parser.parse_args()
    
    try:
        scanner = DeepsetDebertaScanner(args.model)
        result = scanner.scan_text(args.text)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "threat_level": "Medium",
            "explanation": f"Scanner initialization failed: {str(e)}",
            "confidence": 0.0,
            "predicted_class": -1,
            "sanitized_content": None
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
"#;

        let temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
        let script_path = temp_file.path().with_extension("py");
        fs::write(&script_path, script_content).context("Failed to write Python script")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        Ok(script_path.to_string_lossy().to_string())
    }

    async fn analyze_with_python(&self, text: &str) -> Result<ScanResult> {
        let output = Command::new("python3")
            .arg(&self.python_script_path)
            .arg("--text")
            .arg(text)
            .arg("--model")
            .arg(&self.model_name)
            .output()
            .context("Failed to execute Python script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: format!("Deepset DeBERTa execution failed: {}", stderr),
                sanitized_content: None,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let analysis: Value = serde_json::from_str(&stdout).context("Failed to parse Python script output")?;
        self.parse_analysis_result(analysis)
    }

    fn parse_analysis_result(&self, analysis: Value) -> Result<ScanResult> {
        let threat_level_str = analysis.get("threat_level").and_then(|v| v.as_str()).unwrap_or("Medium");
        let confidence = analysis.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let explanation = analysis.get("explanation").and_then(|v| v.as_str()).unwrap_or("No explanation provided").to_string();

        let threat_level = if confidence < self.confidence_threshold {
            ThreatLevel::Safe
        } else {
            match threat_level_str.to_lowercase().as_str() {
                "safe" => ThreatLevel::Safe,
                "low" => ThreatLevel::Low,
                "medium" => ThreatLevel::Medium,
                "high" => ThreatLevel::High,
                "critical" => ThreatLevel::Critical,
                _ => ThreatLevel::Medium,
            }
        };

        let final_explanation = if confidence < self.confidence_threshold {
            format!("{} (confidence {:.3} below threshold {:.3}, treating as safe)", explanation, confidence, self.confidence_threshold)
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult {
            threat_level,
            explanation: final_explanation,
            sanitized_content: None,
        })
    }
}

#[async_trait]
impl ContentScanner for DeepsetDebertaScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        self.analyze_with_python(&combined_content).await
    }

    async fn scan_tool_result(&self, tool_name: &str, arguments: &Value, result: &[Content]) -> Result<ScanResult> {
        let combined_content = result.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        let contextual_content = format!("Tool: {}\nArguments: {}\nResult: {}", tool_name, serde_json::to_string(arguments).unwrap_or_default(), combined_content);
        self.analyze_with_python(&contextual_content).await
    }
}

pub struct ToxicBertScanner {
    model_name: String,
    python_script_path: String,
    confidence_threshold: f32,
}

impl ToxicBertScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            model_name: "unitary/toxic-bert".to_string(),
            python_script_path: Self::create_python_script().unwrap_or_else(|e| {
                tracing::error!("Failed to create Python script for ToxicBERT: {}", e);
                "toxic_bert_scanner.py".to_string()
            }),
            confidence_threshold,
        }
    }

    fn create_python_script() -> Result<String> {
        let script_content = r#"#!/usr/bin/env python3
import sys
import json
import argparse
from typing import Dict, Any

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:
    print(json.dumps({"error": "Required packages not installed. Run: pip install torch transformers"}))
    sys.exit(1)

class ToxicBertScanner:
    def __init__(self, model_name: str = "unitary/toxic-bert"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.eval()
        except Exception as e:
            raise RuntimeError(f"Failed to load model {self.model_name}: {e}")
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)
                predicted_class = torch.argmax(probabilities, dim=-1).item()
                confidence = torch.max(probabilities).item()
            
            if predicted_class == 0:
                threat_level = "Safe"
                explanation = f"Content appears safe (confidence: {confidence:.3f})"
            else:
                if confidence >= 0.9:
                    threat_level = "High"
                elif confidence >= 0.7:
                    threat_level = "Medium"
                else:
                    threat_level = "Low"
                explanation = f"Potentially harmful content detected (confidence: {confidence:.3f})"
            
            return {
                "threat_level": threat_level,
                "explanation": explanation,
                "confidence": confidence,
                "predicted_class": predicted_class,
                "sanitized_content": None
            }
            
        except Exception as e:
            return {
                "threat_level": "Medium",
                "explanation": f"Error during analysis: {str(e)}",
                "confidence": 0.0,
                "predicted_class": -1,
                "sanitized_content": None
            }

def main():
    parser = argparse.ArgumentParser(description="ToxicBERT Scanner")
    parser.add_argument("--text", required=True, help="Text to analyze")
    parser.add_argument("--model", default="unitary/toxic-bert", help="Model name")
    args = parser.parse_args()
    
    try:
        scanner = ToxicBertScanner(args.model)
        result = scanner.scan_text(args.text)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "threat_level": "Medium",
            "explanation": f"Scanner initialization failed: {str(e)}",
            "confidence": 0.0,
            "predicted_class": -1,
            "sanitized_content": None
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
"#;

        let temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
        let script_path = temp_file.path().with_extension("py");
        fs::write(&script_path, script_content).context("Failed to write Python script")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        Ok(script_path.to_string_lossy().to_string())
    }

    async fn analyze_with_python(&self, text: &str) -> Result<ScanResult> {
        let output = Command::new("python3")
            .arg(&self.python_script_path)
            .arg("--text")
            .arg(text)
            .arg("--model")
            .arg(&self.model_name)
            .output()
            .context("Failed to execute Python script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: format!("ToxicBERT execution failed: {}", stderr),
                sanitized_content: None,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let analysis: Value = serde_json::from_str(&stdout).context("Failed to parse Python script output")?;
        self.parse_analysis_result(analysis)
    }

    fn parse_analysis_result(&self, analysis: Value) -> Result<ScanResult> {
        let threat_level_str = analysis.get("threat_level").and_then(|v| v.as_str()).unwrap_or("Medium");
        let confidence = analysis.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let explanation = analysis.get("explanation").and_then(|v| v.as_str()).unwrap_or("No explanation provided").to_string();

        let threat_level = if confidence < self.confidence_threshold {
            ThreatLevel::Safe
        } else {
            match threat_level_str.to_lowercase().as_str() {
                "safe" => ThreatLevel::Safe,
                "low" => ThreatLevel::Low,
                "medium" => ThreatLevel::Medium,
                "high" => ThreatLevel::High,
                "critical" => ThreatLevel::Critical,
                _ => ThreatLevel::Medium,
            }
        };

        let final_explanation = if confidence < self.confidence_threshold {
            format!("{} (confidence {:.3} below threshold {:.3}, treating as safe)", explanation, confidence, self.confidence_threshold)
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult {
            threat_level,
            explanation: final_explanation,
            sanitized_content: None,
        })
    }
}

#[async_trait]
impl ContentScanner for ToxicBertScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        self.analyze_with_python(&combined_content).await
    }

    async fn scan_tool_result(&self, tool_name: &str, arguments: &Value, result: &[Content]) -> Result<ScanResult> {
        let combined_content = result.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        let contextual_content = format!("Tool: {}\nArguments: {}\nResult: {}", tool_name, serde_json::to_string(arguments).unwrap_or_default(), combined_content);
        self.analyze_with_python(&contextual_content).await
    }
}

pub struct OpenAiModerationScanner {
    api_key: String,
    confidence_threshold: f32,
}

impl OpenAiModerationScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| {
            tracing::warn!("OPENAI_API_KEY not set, OpenAI Moderation scanner will not work");
            String::new()
        });
        
        Self {
            api_key,
            confidence_threshold,
        }
    }

    async fn analyze_with_api(&self, text: &str) -> Result<ScanResult> {
        if self.api_key.is_empty() {
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: "OpenAI API key not configured".to_string(),
                sanitized_content: None,
            });
        }

        let client = reqwest::Client::new();
        let request_body = serde_json::json!({"input": text});

        let response = client
            .post("https://api.openai.com/v1/moderations")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .context("Failed to call OpenAI Moderation API")?;

        let response_text = response.text().await?;
        let analysis: Value = serde_json::from_str(&response_text)
            .context("Failed to parse OpenAI Moderation API response")?;

        self.parse_moderation_result(analysis)
    }

    fn parse_moderation_result(&self, analysis: Value) -> Result<ScanResult> {
        let empty_vec = vec![];
        let results = analysis.get("results").and_then(|r| r.as_array()).unwrap_or(&empty_vec);
        
        if results.is_empty() {
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: "No moderation results returned".to_string(),
                sanitized_content: None,
            });
        }

        let result = &results[0];
        let flagged = result.get("flagged").and_then(|f| f.as_bool()).unwrap_or(false);
        
        if !flagged {
            return Ok(ScanResult {
                threat_level: ThreatLevel::Safe,
                explanation: "Content passed OpenAI moderation".to_string(),
                sanitized_content: None,
            });
        }

        // Check category scores to determine threat level
        let empty_obj = serde_json::json!({});
        let categories = result.get("category_scores").unwrap_or(&empty_obj);
        let max_score = categories.as_object()
            .map(|obj| obj.values().filter_map(|v| v.as_f64()).fold(0.0, f64::max))
            .unwrap_or(0.0) as f32;

        let threat_level = if max_score < self.confidence_threshold {
            ThreatLevel::Safe
        } else if max_score >= 0.9 {
            ThreatLevel::High
        } else if max_score >= 0.7 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        let explanation = if max_score < self.confidence_threshold {
            format!("Content flagged by OpenAI but score {:.3} below threshold {:.3}, treating as safe", max_score, self.confidence_threshold)
        } else {
            format!("Content flagged by OpenAI moderation (max score: {:.3})", max_score)
        };

        Ok(ScanResult {
            threat_level,
            explanation,
            sanitized_content: None,
        })
    }
}

#[async_trait]
impl ContentScanner for OpenAiModerationScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        self.analyze_with_api(&combined_content).await
    }

    async fn scan_tool_result(&self, tool_name: &str, arguments: &Value, result: &[Content]) -> Result<ScanResult> {
        let combined_content = result.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        let contextual_content = format!("Tool: {}\nArguments: {}\nResult: {}", tool_name, serde_json::to_string(arguments).unwrap_or_default(), combined_content);
        self.analyze_with_api(&contextual_content).await
    }
}

// Parallel Ensemble Scanner Implementation
pub struct ParallelEnsembleScanner {
    members: Vec<(Box<dyn ContentScanner>, EnsembleMember)>,
    voting_strategy: VotingStrategy,
}

impl ParallelEnsembleScanner {
    pub fn new(ensemble_config: EnsembleConfig) -> Result<Self> {
        let mut members = Vec::new();
        
        for member_config in ensemble_config.member_configs {
            let scanner: Box<dyn ContentScanner> = match member_config.scanner_type {
                ScannerType::DeepsetDeberta => {
                    Box::new(DeepsetDebertaScanner::new(member_config.confidence_threshold))
                },
                ScannerType::RustDeepsetDeberta => {
                    Box::new(crate::security::rust_scanners::OnnxDeepsetDebertaScanner::new(member_config.confidence_threshold))
                },
                ScannerType::RustProtectAiDeberta => {
                    Box::new(crate::security::rust_scanners::OnnxProtectAiDebertaScanner::new(member_config.confidence_threshold))
                },
                ScannerType::RustLlamaPromptGuard2 => {
                    Box::new(crate::security::rust_scanners::OnnxLlamaPromptGuard2Scanner::new(member_config.confidence_threshold))
                },
                ScannerType::ProtectAiDeberta => {
                    Box::new(LlamaPromptGuardScanner::new(member_config.confidence_threshold))
                },
                ScannerType::LlamaPromptGuard2 => {
                    Box::new(LlamaPromptGuard2Scanner::new(member_config.confidence_threshold))
                },
                ScannerType::ToxicBert => {
                    Box::new(ToxicBertScanner::new(member_config.confidence_threshold))
                },
                ScannerType::OpenAiModeration => {
                    Box::new(OpenAiModerationScanner::new(member_config.confidence_threshold))
                },
                _ => return Err(anyhow::anyhow!("Scanner type {:?} not supported in ensemble", member_config.scanner_type)),
            };
            
            members.push((scanner, member_config));
        }
        
        Ok(Self {
            members,
            voting_strategy: ensemble_config.voting_strategy,
        })
    }
    
    async fn scan_with_ensemble(&self, content: &[Content]) -> Result<ScanResult> {
        // Run all scanners in parallel
        let scan_futures: Vec<_> = self.members.iter().map(|(scanner, _)| {
            scanner.scan_content(content)
        }).collect();
        
        // Wait for all scans to complete
        let scan_results: Vec<Result<ScanResult>> = futures::future::join_all(scan_futures).await;
        
        // Process results and apply voting strategy
        self.combine_results(scan_results)
    }
    
    fn combine_results(&self, results: Vec<Result<ScanResult>>) -> Result<ScanResult> {
        let mut successful_results = Vec::new();
        let mut explanations = Vec::new();
        
        // Collect successful results
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(scan_result) => {
                    let member_name = format!("{:?}", self.members[i].1.scanner_type);
                    explanations.push(format!("{}: {}", member_name, scan_result.explanation));
                    successful_results.push((scan_result, &self.members[i].1));
                },
                Err(e) => {
                    let member_name = format!("{:?}", self.members[i].1.scanner_type);
                    explanations.push(format!("{}: Error - {}", member_name, e));
                }
            }
        }
        
        if successful_results.is_empty() {
            return Ok(ScanResult {
                threat_level: ThreatLevel::Medium,
                explanation: "All ensemble members failed".to_string(),
                sanitized_content: None,
            });
        }
        
        // Apply voting strategy
        let (final_threat_level, voting_explanation) = match self.voting_strategy {
            VotingStrategy::AnyDetection => self.any_detection_vote(&successful_results),
            VotingStrategy::MajorityVote => self.majority_vote(&successful_results),
            VotingStrategy::WeightedVote => self.weighted_vote(&successful_results),
        };
        
        let combined_explanation = format!(
            "Ensemble result ({}): {} | Member results: [{}]",
            voting_explanation,
            match final_threat_level {
                ThreatLevel::Safe => "SAFE",
                ThreatLevel::Low => "LOW THREAT",
                ThreatLevel::Medium => "MEDIUM THREAT", 
                ThreatLevel::High => "HIGH THREAT",
                ThreatLevel::Critical => "CRITICAL THREAT",
            },
            explanations.join(" | ")
        );
        
        Ok(ScanResult {
            threat_level: final_threat_level,
            explanation: combined_explanation,
            sanitized_content: None, // Ensemble doesn't provide sanitization
        })
    }
    
    fn any_detection_vote(&self, results: &[(ScanResult, &EnsembleMember)]) -> (ThreatLevel, String) {
        let mut max_threat = ThreatLevel::Safe;
        let mut detections = 0;
        
        for (result, _) in results {
            if result.threat_level != ThreatLevel::Safe {
                detections += 1;
                if self.threat_level_priority(&result.threat_level) > self.threat_level_priority(&max_threat) {
                    max_threat = result.threat_level.clone();
                }
            }
        }
        
        let explanation = if detections > 0 {
            format!("{}/{} models detected threats", detections, results.len())
        } else {
            format!("0/{} models detected threats", results.len())
        };
        
        (max_threat, explanation)
    }
    
    fn majority_vote(&self, results: &[(ScanResult, &EnsembleMember)]) -> (ThreatLevel, String) {
        let total_members = results.len();
        let majority_threshold = (total_members / 2) + 1;
        
        let mut threat_detections = 0;
        let mut max_threat = ThreatLevel::Safe;
        
        for (result, _) in results {
            if result.threat_level != ThreatLevel::Safe {
                threat_detections += 1;
                if self.threat_level_priority(&result.threat_level) > self.threat_level_priority(&max_threat) {
                    max_threat = result.threat_level.clone();
                }
            }
        }
        
        let final_threat = if threat_detections >= majority_threshold {
            max_threat
        } else {
            ThreatLevel::Safe
        };
        
        let explanation = format!(
            "{}/{} models detected threats (majority: {})",
            threat_detections, total_members, majority_threshold
        );
        
        (final_threat, explanation)
    }
    
    fn weighted_vote(&self, results: &[(ScanResult, &EnsembleMember)]) -> (ThreatLevel, String) {
        let mut total_weight = 0.0;
        let mut threat_weight = 0.0;
        let mut max_threat = ThreatLevel::Safe;
        
        for (result, member) in results {
            total_weight += member.weight;
            
            if result.threat_level != ThreatLevel::Safe {
                threat_weight += member.weight;
                if self.threat_level_priority(&result.threat_level) > self.threat_level_priority(&max_threat) {
                    max_threat = result.threat_level.clone();
                }
            }
        }
        
        let threat_ratio = if total_weight > 0.0 { threat_weight / total_weight } else { 0.0 };
        
        let final_threat = if threat_ratio >= 0.5 {
            max_threat
        } else {
            ThreatLevel::Safe
        };
        
        let explanation = format!(
            "Weighted vote: {:.1}% threat confidence",
            threat_ratio * 100.0
        );
        
        (final_threat, explanation)
    }
    
    fn threat_level_priority(&self, threat_level: &ThreatLevel) -> u8 {
        match threat_level {
            ThreatLevel::Safe => 0,
            ThreatLevel::Low => 1,
            ThreatLevel::Medium => 2,
            ThreatLevel::High => 3,
            ThreatLevel::Critical => 4,
        }
    }
}

#[async_trait]
impl ContentScanner for ParallelEnsembleScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        self.scan_with_ensemble(content).await
    }

    async fn scan_tool_result(&self, tool_name: &str, arguments: &Value, result: &[Content]) -> Result<ScanResult> {
        // For tool results, we analyze the content with some context
        let combined_content = result.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        let contextual_content = format!("Tool: {}\nArguments: {}\nResult: {}", tool_name, serde_json::to_string(arguments).unwrap_or_default(), combined_content);
        let content_with_context = vec![Content::text(contextual_content)];
        self.scan_with_ensemble(&content_with_context).await
    }
}
// HybridTieredScanner implementation
