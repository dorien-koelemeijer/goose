#[cfg(feature = "onnx")]
mod onnx_impl {
    use super::super::model_downloader::{get_global_downloader, ModelInfo};
    use super::super::scanner::SecurityScanner;
    use super::super::types::{
        ContentType, ModelArchitecture, ModelConfig, ResponseMode, ScanResult, SecurityConfig,
        ThreatLevel,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use futures;
    use ndarray::Array2;
    use ort::{
        session::{builder::GraphOptimizationLevel, Session, SessionOutputs},
        value::Value,
    };
    use rmcp::model::Content;
    use std::sync::Arc;
    use tokenizers::Tokenizer;

    /// Single ONNX model scanner
    pub struct OnnxScanner {
        model_info: ModelInfo,
        confidence_threshold: f32,
        response_mode: ResponseMode,
        name: String,
    }

    impl OnnxScanner {
        pub fn from_config(
            model_config: &ModelConfig,
            response_mode: ResponseMode,
        ) -> Result<Self> {
            tracing::info!("🔧 Creating OnnxScanner for model: {}", model_config.model);

            let architecture = model_config
                .architecture
                .clone()
                .unwrap_or_else(ModelArchitecture::default);

            tracing::debug!("📋 Using architecture: {:?}", architecture.model_type);

            let model_info =
                ModelInfo::from_hf_name_with_architecture(&model_config.model, Some(architecture))?;

            tracing::info!("📁 Model info created for: {}", model_info.hf_model_name);

            let name = format!("ONNX-{}", model_config.model.replace("/", "-"));

            let scanner = Self {
                model_info,
                confidence_threshold: model_config.threshold, // This will be overridden per content type
                response_mode,
                name: name.clone(),
            };

            tracing::info!("✅ OnnxScanner '{}' created successfully", name);
            Ok(scanner)
        }

        async fn load_model_cached(&self) -> Result<(Session, Arc<Tokenizer>)> {
            tracing::info!("🔄 Loading ONNX model: {}", self.model_info.hf_model_name);

            let downloader = get_global_downloader().await?;

            tracing::info!(
                "📥 Ensuring model is available: {}",
                self.model_info.hf_model_name
            );
            let (model_path, tokenizer_path) =
                downloader.ensure_model_available(&self.model_info).await?;

            tracing::info!("🧠 Creating ONNX session from: {:?}", model_path);
            // Create ONNX session with new API
            let session = Session::builder()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(1)?
                .commit_from_file(&model_path)?;

            tracing::info!("🔤 Loading tokenizer from: {:?}", tokenizer_path);
            // Load tokenizer
            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

            tracing::info!(
                "✅ Model and tokenizer loaded successfully for: {}",
                self.model_info.hf_model_name
            );
            Ok((session, Arc::new(tokenizer)))
        }

        async fn analyze_text_with_threshold(
            &self,
            text: &str,
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            let (mut session, tokenizer) = self.load_model_cached().await?;

            // Get architecture info - try to load from metadata first, fallback to model_info
            let downloader = get_global_downloader().await?;
            let architecture = downloader
                .load_model_metadata(&self.model_info)
                .await
                .unwrap_or_else(|_| self.model_info.architecture.clone());

            // Tokenize the input text with architecture-specific max length
            let max_length = architecture.max_sequence_length.unwrap_or(512);
            let encoding = tokenizer
                .encode(text, true)
                .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

            let input_ids = encoding.get_ids();
            let attention_mask = encoding.get_attention_mask();

            // Truncate to max length if needed
            let seq_len = input_ids.len().min(max_length);
            let input_ids = &input_ids[..seq_len];
            let attention_mask = &attention_mask[..seq_len];

            // Convert to ONNX tensors
            let input_ids_array = Array2::from_shape_vec(
                (1, input_ids.len()),
                input_ids.iter().map(|&x| x as i64).collect(),
            )?;

            let attention_mask_array = Array2::from_shape_vec(
                (1, attention_mask.len()),
                attention_mask.iter().map(|&x| x as i64).collect(),
            )?;

            // Create ONNX inputs based on architecture
            let mut inputs = Vec::new();
            for input_name in &architecture.input_names {
                match input_name.as_str() {
                    "input_ids" => inputs.push((
                        input_name.as_str(),
                        Value::from_array(input_ids_array.clone())?,
                    )),
                    "attention_mask" => inputs.push((
                        input_name.as_str(),
                        Value::from_array(attention_mask_array.clone())?,
                    )),
                    _ => {
                        tracing::warn!("Unknown input name: {}, skipping", input_name);
                    }
                }
            }

            // Run inference
            let outputs = session.run(inputs)?;

            // Process outputs based on architecture and task
            let result = self.process_model_outputs_with_threshold(
                &outputs,
                &architecture,
                content_type,
                threshold,
            )?;
            Ok(result)
        }

        async fn analyze_text(&self, text: &str, content_type: ContentType) -> Result<ScanResult> {
            self.analyze_text_with_threshold(text, content_type, self.confidence_threshold)
                .await
        }

        fn process_model_outputs_with_threshold(
            &self,
            outputs: &SessionOutputs,
            architecture: &ModelArchitecture,
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            use crate::types::{ModelTask, ModelType};

            // Find the main output tensor - just get the first one for simplicity
            let output_tensor = outputs
                .iter()
                .next()
                .map(|(_, v)| v)
                .ok_or_else(|| anyhow::anyhow!("No output tensor found"))?;

            let (_shape, output_slice) = output_tensor.try_extract_tensor::<f32>()?;

            match (&architecture.model_type, &architecture.task) {
                (ModelType::SequenceClassification, ModelTask::PromptInjectionDetection) => self
                    .process_prompt_injection_output_with_threshold(
                        output_slice,
                        content_type,
                        threshold,
                    ),
                (ModelType::SequenceClassification, ModelTask::ToxicityDetection) => self
                    .process_toxicity_output_with_threshold(output_slice, content_type, threshold),
                (ModelType::SequenceClassification, ModelTask::SentimentAnalysis) => self
                    .process_sentiment_output_with_threshold(output_slice, content_type, threshold),
                (ModelType::SequenceClassification, _) => {
                    // Generic binary classification
                    self.process_binary_classification_output_with_threshold(
                        output_slice,
                        content_type,
                        threshold,
                    )
                }
                _ => {
                    // Unsupported model type/task combination
                    tracing::warn!(
                        "Unsupported model type/task combination: {:?}/{:?}",
                        architecture.model_type,
                        architecture.task
                    );
                    Ok(ScanResult::safe(self.name.clone(), content_type))
                }
            }
        }

        fn process_prompt_injection_output_with_threshold(
            &self,
            logits: &[f32],
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            // Apply softmax to get probabilities
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For prompt injection: index 1 is typically the "injection" class
            let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result_with_threshold(
                injection_probability,
                content_type,
                "prompt injection",
                threshold,
            )
        }

        fn process_toxicity_output_with_threshold(
            &self,
            logits: &[f32],
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For toxicity: index 1 is typically the "toxic" class
            let toxic_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result_with_threshold(
                toxic_probability,
                content_type,
                "toxic content",
                threshold,
            )
        }

        fn process_sentiment_output_with_threshold(
            &self,
            logits: &[f32],
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For sentiment: treat negative sentiment as a threat
            let negative_probability = probabilities.get(0).copied().unwrap_or(0.0);

            self.create_scan_result_with_threshold(
                negative_probability,
                content_type,
                "negative sentiment",
                threshold,
            )
        }

        fn process_binary_classification_output_with_threshold(
            &self,
            logits: &[f32],
            content_type: ContentType,
            threshold: f32,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // Generic binary: index 1 is the "positive" class
            let positive_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result_with_threshold(
                positive_probability,
                content_type,
                "threat",
                threshold,
            )
        }

        fn create_scan_result_with_threshold(
            &self,
            confidence: f32,
            content_type: ContentType,
            threat_type: &str,
            threshold: f32,
        ) -> Result<ScanResult> {
            // Determine threat level based on confidence and threshold
            let threat_level = if confidence < threshold {
                ThreatLevel::Safe
            } else if confidence >= 0.9 {
                ThreatLevel::High
            } else if confidence >= (threshold + 0.1).min(0.85) {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };

            let explanation = if confidence < threshold {
                format!(
                    "{}: {} probability {:.3} below threshold {:.3}, treating as safe",
                    self.name, threat_type, confidence, threshold
                )
            } else {
                format!(
                    "{}: potential {} detected (confidence: {:.3})",
                    self.name, threat_type, confidence
                )
            };

            // Determine warning/blocking based on response mode and threat level
            let (should_warn, should_block) = match (&self.response_mode, &threat_level) {
                (ResponseMode::Warn, ThreatLevel::Safe) => (false, false),
                (ResponseMode::Warn, _) => (true, false), // Warn mode: warn but don't block
                (ResponseMode::Block, ThreatLevel::Safe) => (false, false),
                (ResponseMode::Block, ThreatLevel::Low) => (true, false),
                (ResponseMode::Block, _) => (true, true), // Block mode: warn and block for medium+
            };

            let details = serde_json::json!({
                "model": self.model_info.hf_model_name,
                "confidence": confidence,
                "threshold": threshold,
                "architecture": self.model_info.architecture
            });

            Ok(ScanResult::threat(
                threat_level,
                confidence,
                explanation,
                self.name.clone(),
                content_type,
                should_warn,
                should_block,
            )
            .with_details(details))
        }

        #[allow(dead_code)]
        fn process_prompt_injection_output(
            &self,
            logits: &[f32],
            content_type: ContentType,
        ) -> Result<ScanResult> {
            // Apply softmax to get probabilities
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For prompt injection: index 1 is typically the "injection" class
            let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result(injection_probability, content_type, "prompt injection")
        }

        #[allow(dead_code)]
        fn process_toxicity_output(
            &self,
            logits: &[f32],
            content_type: ContentType,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For toxicity: index 1 is typically the "toxic" class
            let toxic_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result(toxic_probability, content_type, "toxic content")
        }

        #[allow(dead_code)]
        fn process_sentiment_output(
            &self,
            logits: &[f32],
            content_type: ContentType,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // For sentiment: treat negative sentiment as a threat
            let negative_probability = probabilities.get(0).copied().unwrap_or(0.0);

            self.create_scan_result(negative_probability, content_type, "negative sentiment")
        }

        #[allow(dead_code)]
        fn process_binary_classification_output(
            &self,
            logits: &[f32],
            content_type: ContentType,
        ) -> Result<ScanResult> {
            let exp_sum: f32 = logits.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits.iter().map(|x| x.exp() / exp_sum).collect();

            // Generic binary: index 1 is the "positive" class
            let positive_probability = probabilities.get(1).copied().unwrap_or(0.0);

            self.create_scan_result(positive_probability, content_type, "threat")
        }

        #[allow(dead_code)]
        fn create_scan_result(
            &self,
            confidence: f32,
            content_type: ContentType,
            threat_type: &str,
        ) -> Result<ScanResult> {
            // Determine threat level based on confidence and threshold
            let threat_level = if confidence < self.confidence_threshold {
                ThreatLevel::Safe
            } else if confidence >= 0.9 {
                ThreatLevel::High
            } else if confidence >= (self.confidence_threshold + 0.1).min(0.85) {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };

            let explanation = if confidence < self.confidence_threshold {
                format!(
                    "{}: {} probability {:.3} below threshold {:.3}, treating as safe",
                    self.name, threat_type, confidence, self.confidence_threshold
                )
            } else {
                format!(
                    "{}: potential {} detected (confidence: {:.3})",
                    self.name, threat_type, confidence
                )
            };

            // Determine warning/blocking based on response mode and threat level
            let (should_warn, should_block) = match (&self.response_mode, &threat_level) {
                (ResponseMode::Warn, ThreatLevel::Safe) => (false, false),
                (ResponseMode::Warn, _) => (true, false), // Warn mode: warn but don't block
                (ResponseMode::Block, ThreatLevel::Safe) => (false, false),
                (ResponseMode::Block, ThreatLevel::Low) => (true, false),
                (ResponseMode::Block, _) => (true, true), // Block mode: warn and block for medium+
            };

            let details = serde_json::json!({
                "model": self.model_info.hf_model_name,
                "confidence": confidence,
                "threshold": self.confidence_threshold,
                "architecture": self.model_info.architecture
            });

            Ok(ScanResult::threat(
                threat_level,
                confidence,
                explanation,
                self.name.clone(),
                content_type,
                should_warn,
                should_block,
            )
            .with_details(details))
        }
    }

    #[async_trait]
    impl SecurityScanner for OnnxScanner {
        async fn scan_content(
            &self,
            content: &[Content],
            content_type: ContentType,
        ) -> Result<Option<ScanResult>> {
            // Extract text content
            let text_content = content
                .iter()
                .filter_map(|c| c.as_text())
                .map(|t| t.text.clone())
                .collect::<Vec<_>>()
                .join(" ");

            if text_content.is_empty() {
                return Ok(Some(ScanResult::safe(self.name.clone(), content_type)));
            }

            let result = self.analyze_text(&text_content, content_type).await?;
            Ok(Some(result))
        }

        fn is_enabled(&self) -> bool {
            true
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    /// Dual ONNX scanner that uses multiple models with weighted ensemble scoring
    pub struct DualOnnxScanner {
        scanners: Vec<OnnxScanner>,
        weights: Vec<f32>,
        model_configs: Vec<ModelConfig>, // Store original configs for content type filtering
        response_mode: ResponseMode,
        name: String,
    }

    impl DualOnnxScanner {
        pub fn from_config(config: &SecurityConfig) -> Result<Self> {
            tracing::info!(
                "🔨 DualOnnxScanner::from_config called with {} models",
                config.models.len()
            );

            if config.models.is_empty() {
                let error = anyhow::anyhow!("No models configured for security scanning");
                tracing::error!("❌ {}", error);
                return Err(error);
            }

            let mut scanners = Vec::new();
            let mut weights = Vec::new();
            let mut model_names = Vec::new();

            for (i, model_config) in config.models.iter().enumerate() {
                tracing::info!("🔄 Processing model {}: {}", i + 1, model_config.model);

                match OnnxScanner::from_config(model_config, config.mode.clone()) {
                    Ok(scanner) => {
                        tracing::info!(
                            "✅ Successfully created scanner for {}",
                            model_config.model
                        );
                        scanners.push(scanner);
                        weights.push(model_config.weight.unwrap_or(1.0));
                        model_names.push(model_config.model.replace("/", "-"));
                    }
                    Err(e) => {
                        tracing::error!(
                            "❌ Failed to create scanner for {}: {}",
                            model_config.model,
                            e
                        );
                        return Err(e);
                    }
                }
            }

            let name = if model_names.len() == 1 {
                format!("ONNX-{}", model_names[0])
            } else {
                format!("EnsembleONNX-{}", model_names.join("-"))
            };

            tracing::info!(
                "🎯 Created DualOnnxScanner '{}' with {} scanners",
                name,
                scanners.len()
            );

            Ok(Self {
                scanners,
                weights,
                model_configs: config.models.clone(), // Store original configs
                response_mode: config.mode.clone(),
                name,
            })
        }
    }

    #[async_trait]
    impl SecurityScanner for DualOnnxScanner {
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

            // Filter scanners that should scan this content type
            let mut active_scanners = Vec::new();
            let mut active_weights = Vec::new();

            for (i, (scanner, model_config)) in
                self.scanners.iter().zip(&self.model_configs).enumerate()
            {
                if model_config.should_scan_content_type(&content_type) {
                    active_scanners.push(scanner);
                    active_weights.push(self.weights.get(i).copied().unwrap_or(1.0));
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
                .map(|scanner| scanner.scan_content(content, content_type.clone()))
                .collect();

            let results: Vec<_> = futures::future::try_join_all(scan_futures).await?;

            // Extract actual results, defaulting to safe if None
            let scan_results: Vec<ScanResult> = results
                .into_iter()
                .enumerate()
                .map(|(i, result)| {
                    result.unwrap_or_else(|| {
                        ScanResult::safe(format!("Scanner-{}", i), content_type.clone())
                    })
                })
                .collect();

            // Perform weighted ensemble scoring with escalation logic
            let mut weighted_confidence = 0.0;
            let mut total_weight = 0.0;
            let mut explanations = Vec::new();
            let mut should_warn = false;
            let mut should_block = false;
            let mut max_individual_confidence: f32 = 0.0;
            let mut any_high_confidence_threat = false;

            for (i, result) in scan_results.iter().enumerate() {
                let weight = active_weights.get(i).copied().unwrap_or(1.0);
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
            let (final_should_warn, final_should_block) = match (&self.response_mode, &threat_level)
            {
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

            // Add ensemble details
            let ensemble_details = serde_json::json!({
                "ensemble_type": "weighted_average_with_escalation",
                "active_models": active_scanners.len(),
                "total_models": self.scanners.len(),
                "models": active_scanners.iter().map(|s| s.name()).collect::<Vec<_>>(),
                "weights": active_weights,
                "individual_results": scan_results.iter().map(|r| {
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
                "total_weight": total_weight
            });

            final_result = final_result.with_details(ensemble_details);

            Ok(Some(final_result))
        }

        fn is_enabled(&self) -> bool {
            !self.scanners.is_empty()
        }

        fn name(&self) -> &str {
            &self.name
        }
    }
}

#[cfg(feature = "onnx")]
pub use onnx_impl::{DualOnnxScanner, OnnxScanner};

// Stub implementations when ONNX feature is not enabled
#[cfg(not(feature = "onnx"))]
pub struct OnnxScanner;

#[cfg(not(feature = "onnx"))]
pub struct DualOnnxScanner;

#[cfg(not(feature = "onnx"))]
impl OnnxScanner {
    pub fn from_config(
        _: &crate::types::ModelConfig,
        _: crate::types::ResponseMode,
    ) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!(
            "ONNX scanner not available (onnx feature not enabled)"
        ))
    }
}

#[cfg(not(feature = "onnx"))]
impl DualOnnxScanner {
    pub fn from_config(_: &crate::types::SecurityConfig) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!(
            "ONNX scanner not available (onnx feature not enabled)"
        ))
    }
}

#[cfg(not(feature = "onnx"))]
#[async_trait::async_trait]
impl crate::scanner::SecurityScanner for OnnxScanner {
    async fn scan_content(
        &self,
        _: &[rmcp::model::Content],
        _: crate::types::ContentType,
    ) -> anyhow::Result<Option<crate::types::ScanResult>> {
        Err(anyhow::anyhow!(
            "ONNX scanner not available (onnx feature not enabled)"
        ))
    }
    fn is_enabled(&self) -> bool {
        false
    }
    fn name(&self) -> &str {
        "ONNX-Disabled"
    }
}

#[cfg(not(feature = "onnx"))]
#[async_trait::async_trait]
impl crate::scanner::SecurityScanner for DualOnnxScanner {
    async fn scan_content(
        &self,
        _: &[rmcp::model::Content],
        _: crate::types::ContentType,
    ) -> anyhow::Result<Option<crate::types::ScanResult>> {
        Err(anyhow::anyhow!(
            "ONNX scanner not available (onnx feature not enabled)"
        ))
    }
    fn is_enabled(&self) -> bool {
        false
    }
    fn name(&self) -> &str {
        "DualONNX-Disabled"
    }
}
