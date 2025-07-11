use super::content_scanner::{ContentScanner, ScanResult, ThreatLevel};
use crate::security::config::{EnsembleConfig, EnsembleMember, ScannerType, VotingStrategy};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::future;
use mcp_core::Content;
use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use tempfile::NamedTempFile;

// Simple test scanner that detects obvious threats for testing
pub struct SimpleTestScanner {
    confidence_threshold: f32,
}

impl SimpleTestScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            confidence_threshold,
        }
    }

    fn analyze_content(&self, text: &str) -> ScanResult {
        let text_lower = text.to_lowercase();
        
        // Check for obvious malicious patterns
        let malicious_patterns = [
            "rm -rf",
            "curl -X POST",
            "chmod 777",
            "sudo chmod",
            "execute this",
            "run this command",
            "system(",
            "exec(",
            "shell_exec",
            "eval(",
            "ignore previous instructions",
            "forget previous instructions",
            "disregard",
            "override",
            "bypass",
            "jailbreak",
            "prompt injection",
            "system prompt",
        ];
        
        let mut threat_score: f32 = 0.0;
        let mut found_patterns = Vec::new();
        
        for pattern in &malicious_patterns {
            if text_lower.contains(pattern) {
                found_patterns.push(*pattern);
                threat_score += match *pattern {
                    "rm -rf" | "chmod 777" | "sudo chmod" => 0.9, // Very dangerous
                    "curl -X POST" | "execute this" | "run this command" => 0.8, // Dangerous
                    "system(" | "exec(" | "shell_exec" | "eval(" => 0.85, // Code execution
                    "ignore previous instructions" | "forget previous instructions" => 0.7, // Prompt injection
                    _ => 0.5, // Suspicious
                };
            }
        }
        
        // Cap at 1.0
        threat_score = threat_score.min(1.0);
        
        let (threat_level, explanation) = if threat_score >= 0.8 {
            (ThreatLevel::High, format!("High threat detected (score: {:.2}). Found patterns: {:?}", threat_score, found_patterns))
        } else if threat_score >= 0.6 {
            (ThreatLevel::Medium, format!("Medium threat detected (score: {:.2}). Found patterns: {:?}", threat_score, found_patterns))
        } else if threat_score >= 0.3 {
            (ThreatLevel::Low, format!("Low threat detected (score: {:.2}). Found patterns: {:?}", threat_score, found_patterns))
        } else {
            (ThreatLevel::Safe, format!("Content appears safe (score: {:.2})", threat_score))
        };
        
        // Apply confidence threshold
        let final_threat_level = if threat_score < self.confidence_threshold {
            ThreatLevel::Safe
        } else {
            threat_level
        };
        
        let final_explanation = if threat_score < self.confidence_threshold && threat_score > 0.0 {
            format!("{} (below confidence threshold {:.2}, treating as safe)", explanation, self.confidence_threshold)
        } else {
            explanation
        };
        
        ScanResult::with_confidence(final_threat_level, threat_score, final_explanation)
    }
}

#[async_trait]
impl ContentScanner for SimpleTestScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(self.analyze_content(&combined_content))
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        let combined_content = result
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );
        Ok(self.analyze_content(&contextual_content))
    }
}

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
                tracing::error!("Failed to create Python script for Deepset DeBERTa: {}", e);
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
            return Ok(ScanResult::new(
                ThreatLevel::Medium,
                format!("Deepset DeBERTa execution failed: {}", stderr),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
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
            format!(
                "{} (confidence {:.3} below threshold {:.3}, treating as safe)",
                explanation, confidence, self.confidence_threshold
            )
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult::with_confidence(threat_level, confidence, final_explanation))
    }
}

#[async_trait]
impl ContentScanner for DeepsetDebertaScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .filter_map(|c| c.as_text())
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
        let combined_content = result
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );
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
            return Ok(ScanResult::new(
                ThreatLevel::Medium,
                format!("ToxicBERT execution failed: {}", stderr),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
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
            format!(
                "{} (confidence {:.3} below threshold {:.3}, treating as safe)",
                explanation, confidence, self.confidence_threshold
            )
        } else {
            format!("{} (confidence: {:.3})", explanation, confidence)
        };

        Ok(ScanResult::with_confidence(threat_level, confidence, final_explanation))
    }
}

#[async_trait]
impl ContentScanner for ToxicBertScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .filter_map(|c| c.as_text())
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
        let combined_content = result
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );
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
            return Ok(ScanResult::new(
                ThreatLevel::Medium,
                "OpenAI API key not configured".to_string(),
            ));
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
        let results = analysis
            .get("results")
            .and_then(|r| r.as_array())
            .unwrap_or(&empty_vec);

        if results.is_empty() {
            return Ok(ScanResult::new(
                ThreatLevel::Medium,
                "No moderation results returned".to_string(),
            ));
        }

        let result = &results[0];
        let flagged = result
            .get("flagged")
            .and_then(|f| f.as_bool())
            .unwrap_or(false);

        if !flagged {
            return Ok(ScanResult::new(
                ThreatLevel::Safe,
                "Content passed OpenAI moderation".to_string(),
            ));
        }

        // Check category scores to determine threat level
        let empty_obj = serde_json::json!({});
        let categories = result.get("category_scores").unwrap_or(&empty_obj);
        let max_score = categories
            .as_object()
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
            format!(
                "Content flagged by OpenAI but score {:.3} below threshold {:.3}, treating as safe",
                max_score, self.confidence_threshold
            )
        } else {
            format!(
                "Content flagged by OpenAI moderation (max score: {:.3})",
                max_score
            )
        };

        Ok(ScanResult::with_confidence(threat_level, max_score, explanation))
    }
}

#[async_trait]
impl ContentScanner for OpenAiModerationScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        let combined_content = content
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        self.analyze_with_api(&combined_content).await
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        let combined_content = result
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );
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
                ScannerType::DeepsetDeberta => Box::new(DeepsetDebertaScanner::new(
                    member_config.confidence_threshold,
                )),
                ScannerType::RustDeepsetDeberta => {
                    #[cfg(feature = "security-onnx")]
                    {
                        Box::new(
                            crate::security::rust_scanners::OnnxDeepsetDebertaScanner::new(
                                member_config.confidence_threshold,
                            ),
                        )
                    }
                    #[cfg(not(feature = "security-onnx"))]
                    {
                        return Err(anyhow::anyhow!(
                            "ONNX scanner {:?} not available (security-onnx feature not enabled)",
                            member_config.scanner_type
                        ));
                    }
                }
                ScannerType::RustProtectAiDeberta => {
                    #[cfg(feature = "security-onnx")]
                    {
                        Box::new(
                            crate::security::rust_scanners::OnnxProtectAiDebertaScanner::new(
                                member_config.confidence_threshold,
                            ),
                        )
                    }
                    #[cfg(not(feature = "security-onnx"))]
                    {
                        return Err(anyhow::anyhow!(
                            "ONNX scanner {:?} not available (security-onnx feature not enabled)",
                            member_config.scanner_type
                        ));
                    }
                }
                // RustLlamaPromptGuard2 removed - no longer needed
                ScannerType::ProtectAiDeberta => {
                    // Use DeepsetDebertaScanner as fallback for ProtectAiDeberta
                    Box::new(DeepsetDebertaScanner::new(member_config.confidence_threshold))
                }
                // LlamaPromptGuard2 removed - no longer needed
                ScannerType::ToxicBert => {
                    Box::new(ToxicBertScanner::new(member_config.confidence_threshold))
                }
                ScannerType::OpenAiModeration => Box::new(OpenAiModerationScanner::new(
                    member_config.confidence_threshold,
                )),
                _ => {
                    return Err(anyhow::anyhow!(
                        "Scanner type {:?} not supported in ensemble",
                        member_config.scanner_type
                    ))
                }
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
        let scan_futures: Vec<_> = self
            .members
            .iter()
            .map(|(scanner, _)| scanner.scan_content(content))
            .collect();

        // Wait for all scans to complete
        let scan_results: Vec<Result<ScanResult>> = future::join_all(scan_futures).await;

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
                }
                Err(e) => {
                    let member_name = format!("{:?}", self.members[i].1.scanner_type);
                    explanations.push(format!("{}: Error - {}", member_name, e));
                }
            }
        }

        if successful_results.is_empty() {
            return Ok(ScanResult::new(
                ThreatLevel::Medium,
                "All ensemble members failed".to_string(),
            ));
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

        Ok(ScanResult::new(final_threat_level, combined_explanation))
    }

    fn any_detection_vote(
        &self,
        results: &[(ScanResult, &EnsembleMember)],
    ) -> (ThreatLevel, String) {
        let mut max_threat = ThreatLevel::Safe;
        let mut detections = 0;

        for (result, _) in results {
            if result.threat_level != ThreatLevel::Safe {
                detections += 1;
                if self.threat_level_priority(&result.threat_level)
                    > self.threat_level_priority(&max_threat)
                {
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
                if self.threat_level_priority(&result.threat_level)
                    > self.threat_level_priority(&max_threat)
                {
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
                if self.threat_level_priority(&result.threat_level)
                    > self.threat_level_priority(&max_threat)
                {
                    max_threat = result.threat_level.clone();
                }
            }
        }

        let threat_ratio = if total_weight > 0.0 {
            threat_weight / total_weight
        } else {
            0.0
        };

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

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        // For tool results, we analyze the content with some context
        let combined_content = result
            .iter()
            .filter_map(|c| c.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let contextual_content = format!(
            "Tool: {}\nArguments: {}\nResult: {}",
            tool_name,
            serde_json::to_string(arguments).unwrap_or_default(),
            combined_content
        );
        let content_with_context = vec![Content::text(contextual_content)];
        self.scan_with_ensemble(&content_with_context).await
    }
}

// Lazy Ensemble Scanner that defers model loading until first scan
pub struct LazyEnsembleScanner {
    ensemble_config: EnsembleConfig,
    scanner: tokio::sync::OnceCell<Arc<ParallelEnsembleScanner>>,
}

impl LazyEnsembleScanner {
    pub fn new(ensemble_config: EnsembleConfig) -> Self {
        Self {
            ensemble_config,
            scanner: tokio::sync::OnceCell::new(),
        }
    }

    async fn get_or_init_scanner(&self) -> Result<&Arc<ParallelEnsembleScanner>> {
        self.scanner.get_or_try_init(|| async {
            tracing::info!("🔒 Initialising Goose security models, this may take up to a minute...");
            match ParallelEnsembleScanner::new(self.ensemble_config.clone()) {
                Ok(scanner) => {
                    tracing::info!("✅ Ensemble scanner initialized successfully");
                    Ok(Arc::new(scanner))
                }
                Err(e) => {
                    tracing::error!("❌ Failed to initialize ensemble scanner: {}", e);
                    Err(e)
                }
            }
        }).await
    }
}

#[async_trait]
impl ContentScanner for LazyEnsembleScanner {
    async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
        match self.get_or_init_scanner().await {
            Ok(scanner) => scanner.scan_content(content).await,
            Err(e) => {
                // Don't treat as safe - return an error to indicate security isn't ready
                Err(anyhow::anyhow!("Security system not ready: {}", e))
            }
        }
    }

    async fn scan_tool_result(
        &self,
        tool_name: &str,
        arguments: &Value,
        result: &[Content],
    ) -> Result<ScanResult> {
        match self.get_or_init_scanner().await {
            Ok(scanner) => scanner.scan_tool_result(tool_name, arguments, result).await,
            Err(e) => {
                // Don't treat as safe - return an error to indicate security isn't ready
                Err(anyhow::anyhow!("Security system not ready: {}", e))
            }
        }
    }
}

// HybridTieredScanner implementation
