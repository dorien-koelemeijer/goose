use anyhow::Result;
use async_trait::async_trait;
use futures;
use rmcp::model::Content;

use crate::model_scanner::{extract_text_content, ModelScanner};
use crate::scanner::SecurityScanner;
use crate::types::{ContentType, ResponseMode, ScanResult, SecurityConfig, ThreatLevel};

/// Generic ensemble scanner that can combine any type of model scanners
pub struct EnsembleScanner {
    scanners: Vec<Box<dyn ModelScanner>>,
    response_mode: ResponseMode,
    name: String,
}

impl EnsembleScanner {
    pub fn new(scanners: Vec<Box<dyn ModelScanner>>, response_mode: ResponseMode) -> Self {
        let scanner_names: Vec<_> = scanners.iter().map(|s| s.name()).collect();
        let name = if scanner_names.len() == 1 {
            scanner_names[0].to_string()
        } else {
            format!("Ensemble-{}", scanner_names.join("-"))
        };

        Self {
            scanners,
            response_mode,
            name,
        }
    }

    pub fn from_config(config: &SecurityConfig) -> Result<Self> {
        tracing::info!(
            "🔨 EnsembleScanner::from_config called with {} models",
            config.models.len()
        );

        if config.models.is_empty() {
            return Err(anyhow::anyhow!(
                "No models configured for security scanning"
            ));
        }

        let mut scanners: Vec<Box<dyn ModelScanner>> = Vec::new();

        for (i, model_config) in config.models.iter().enumerate() {
            tracing::info!(
                "🔄 Processing model {}: {} (backend: {:?})",
                i + 1,
                model_config.model,
                model_config.backend
            );

            let scanner: Box<dyn ModelScanner> = match &model_config.backend {
                crate::types::ModelBackend::Onnx => {
                    #[cfg(feature = "onnx")]
                    {
                        Box::new(crate::onnx_model_scanner::OnnxModelScanner::new(
                            model_config.clone(),
                            config.mode.clone(),
                        )?)
                    }
                    #[cfg(not(feature = "onnx"))]
                    {
                        return Err(anyhow::anyhow!(
                            "ONNX backend requested but onnx feature not enabled"
                        ));
                    }
                }
                crate::types::ModelBackend::HuggingFaceApi => {
                    // TODO: Implement HuggingFace API scanner
                    return Err(anyhow::anyhow!(
                        "HuggingFace API backend not yet implemented"
                    ));
                }
                crate::types::ModelBackend::OpenAiModeration => {
                    // TODO: Implement OpenAI moderation scanner
                    return Err(anyhow::anyhow!(
                        "OpenAI moderation backend not yet implemented"
                    ));
                }
                crate::types::ModelBackend::Custom(backend_name) => {
                    return Err(anyhow::anyhow!(
                        "Custom backend '{}' not implemented",
                        backend_name
                    ));
                }
            };

            tracing::info!("✅ Successfully created scanner for {}", model_config.model);
            scanners.push(scanner);
        }

        tracing::info!(
            "🎯 Created EnsembleScanner with {} scanners",
            scanners.len()
        );

        Ok(Self::new(scanners, config.mode.clone()))
    }
}

#[async_trait]
impl SecurityScanner for EnsembleScanner {
    async fn scan_content(
        &self,
        content: &[Content],
        content_type: ContentType,
    ) -> Result<Option<ScanResult>> {
        if self.scanners.is_empty() {
            return Ok(Some(ScanResult::safe(
                "No-Models".to_string(),
                content_type,
            )));
        }

        // Extract text content
        let text_content = extract_text_content(content);

        if text_content.is_empty() {
            return Ok(Some(ScanResult::safe(
                "Empty-Content".to_string(),
                content_type,
            )));
        }

        // Log the content being scanned (for debugging false positives)
        tracing::debug!(
            content_type = ?content_type,
            content_length = text_content.len(),
            content_preview = if text_content.len() > 100 {
                format!("{}...", &text_content[..100])
            } else {
                text_content.clone()
            },
            "🔍 Scanning content"
        );

        // Filter scanners that should scan this content type
        let mut active_scanners = Vec::new();

        for scanner in &self.scanners {
            if scanner.should_scan_content_type(&content_type) {
                active_scanners.push(scanner.as_ref());
            }
        }

        if active_scanners.is_empty() {
            tracing::info!(
                content_type = ?content_type,
                total_models = self.scanners.len(),
                "⚪ No models configured to scan this content type"
            );
            return Ok(Some(ScanResult::safe(
                "No-Active-Models".to_string(),
                content_type,
            )));
        }

        tracing::info!(
            content_type = ?content_type,
            active_models = active_scanners.len(),
            total_models = self.scanners.len(),
            "🔍 Running security scan with {} active models",
            active_scanners.len()
        );

        // Run active scanners in parallel
        let scan_futures: Vec<_> = active_scanners
            .iter()
            .map(|scanner| scanner.scan_text(&text_content, content_type.clone()))
            .collect();

        let results: Vec<_> = futures::future::try_join_all(scan_futures).await?;

        // Perform weighted ensemble scoring with escalation logic
        let mut weighted_confidence = 0.0;
        let mut total_weight = 0.0;
        let mut explanations = Vec::new();
        let mut should_warn = false;
        let mut should_block = false;
        let mut max_individual_confidence: f32 = 0.0;
        let mut any_high_confidence_threat = false;

        for (i, result) in results.iter().enumerate() {
            let weight = active_scanners[i].weight();
            weighted_confidence += result.confidence * weight;
            total_weight += weight;

            // Track the highest individual confidence
            max_individual_confidence = max_individual_confidence.max(result.confidence);

            // Check for high-confidence individual threats (≥0.9) that should escalate
            if result.confidence >= 0.9 && result.threat_level != ThreatLevel::Safe {
                any_high_confidence_threat = true;
            }

            // Accumulate warnings and blocks (any model can trigger these)
            should_warn = should_warn || result.should_warn;
            should_block = should_block || result.should_block;

            explanations.push(format!(
                "{} (confidence: {:.3}, weight: {:.1})",
                result.explanation, result.confidence, weight
            ));
        }

        // Calculate final weighted confidence
        let final_confidence = if total_weight > 0.0 {
            weighted_confidence / total_weight
        } else {
            0.0
        };

        // Determine threat level with escalation logic
        let threat_level = if any_high_confidence_threat {
            // If any model has high confidence (≥0.9), escalate based on that
            if max_individual_confidence >= 0.95 {
                ThreatLevel::Critical
            } else if max_individual_confidence >= 0.9 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            }
        } else {
            // Otherwise use weighted confidence as before
            if final_confidence >= 0.9 {
                ThreatLevel::Critical
            } else if final_confidence >= 0.8 {
                ThreatLevel::High
            } else if final_confidence >= 0.6 {
                ThreatLevel::Medium
            } else if final_confidence >= 0.3 {
                ThreatLevel::Low
            } else {
                ThreatLevel::Safe
            }
        };

        // Override should_warn/should_block based on final threat level and mode
        let (final_should_warn, final_should_block) = match (&self.response_mode, &threat_level) {
            (ResponseMode::Warn, ThreatLevel::Safe) => (false, false),
            (ResponseMode::Warn, _) => (true, false), // Warn mode: warn but don't block
            (ResponseMode::Block, ThreatLevel::Safe) => (false, false),
            (ResponseMode::Block, ThreatLevel::Low) => (true, false),
            (ResponseMode::Block, _) => (true, true), // Block mode: warn and block for medium+
        };

        // Create ensemble explanation
        let explanation = if any_high_confidence_threat {
            format!(
                "Ensemble result from {} active models (ESCALATED due to high-confidence threat): {}",
                active_scanners.len(),
                explanations.join("; ")
            )
        } else {
            format!(
                "Ensemble result from {} active models: {}",
                active_scanners.len(),
                explanations.join("; ")
            )
        };

        // Create final result
        let mut final_result = if threat_level == ThreatLevel::Safe {
            ScanResult::safe(self.name.clone(), content_type)
        } else {
            ScanResult::threat(
                threat_level,
                final_confidence,
                explanation,
                self.name.clone(),
                content_type,
                final_should_warn,
                final_should_block,
            )
        };

        // Add ensemble details including the scanned content for debugging
        let ensemble_details = serde_json::json!({
            "ensemble_type": "weighted_average_with_escalation",
            "active_models": active_scanners.len(),
            "total_models": self.scanners.len(),
            "models": active_scanners.iter().map(|s| s.name()).collect::<Vec<_>>(),
            "weights": active_scanners.iter().map(|s| s.weight()).collect::<Vec<_>>(),
            "individual_results": results.iter().map(|r| {
                serde_json::json!({
                    "scanner": r.scanner_type,
                    "confidence": r.confidence,
                    "threat_level": format!("{:?}", r.threat_level),
                    "explanation": r.explanation
                })
            }).collect::<Vec<_>>(),
            "weighted_confidence": final_confidence,
            "max_individual_confidence": max_individual_confidence,
            "escalation_triggered": any_high_confidence_threat,
            "total_weight": total_weight,
            // Include the scanned content for debugging (truncated for logs)
            "scanned_content": if text_content.len() > 200 {
                format!("{}...", &text_content[..200])
            } else {
                text_content.clone()
            },
            "content_length": text_content.len()
        });

        final_result = final_result.with_details(ensemble_details);

        Ok(Some(final_result))
    }

    fn is_enabled(&self) -> bool {
        !self.scanners.is_empty() && self.scanners.iter().any(|s| s.is_enabled())
    }

    fn name(&self) -> &str {
        &self.name
    }
}
