#[cfg(feature = "security-onnx")]
mod onnx_scanners {
    use super::super::content_scanner::{ContentScanner, ScanResult, ThreatLevel};
    use super::super::model_downloader::{get_global_downloader, ModelInfo};
    use anyhow::Result;
    use async_trait::async_trait;
    use mcp_core::Content;
    use ndarray::Array2;
    use ort::{Environment, Session, SessionBuilder};
    use serde_json::Value;
    use std::sync::Arc;
    use tokenizers::Tokenizer;
    use tokio::sync::OnceCell;

    pub struct OnnxDeepsetDebertaScanner {
        confidence_threshold: f32,
    }

    static MODEL_CACHE: OnceCell<(Arc<Session>, Arc<Tokenizer>)> = OnceCell::const_new();

    impl OnnxDeepsetDebertaScanner {
        pub fn new(confidence_threshold: f32) -> Self {
            Self {
                confidence_threshold,
            }
        }

        async fn load_model_cached() -> Result<(Arc<Session>, Arc<Tokenizer>)> {
            MODEL_CACHE
                .get_or_try_init(|| async {
                    tracing::info!("Loading ONNX DeBERTa model (with runtime download if needed)...");

                    // Get the global downloader
                    let downloader = get_global_downloader().await?;
                    
                    // Ensure the model is available (download if needed)
                    let model_info = ModelInfo::deepset_deberta();
                    let (model_path, tokenizer_path) = downloader.ensure_model_available(&model_info).await?;

                    tracing::info!("Loading ONNX model from: {:?}", model_path);

                    // Create ONNX environment
                    let environment = Arc::new(Environment::builder().build()?);

                    let session = SessionBuilder::new(&environment)?
                        .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
                        .with_intra_threads(1)?
                        .with_model_from_file(&model_path)?;

                    // Load tokenizer
                    let tokenizer = Tokenizer::from_file(tokenizer_path)
                        .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

                    tracing::info!("Successfully loaded ONNX DeBERTa model and tokenizer");

                    Ok((Arc::new(session), Arc::new(tokenizer)))
                })
                .await
                .cloned()
        }

        async fn analyze_text(&self, text: &str) -> Result<ScanResult> {
            // Load model and tokenizer (cached globally)
            let (session, tokenizer) = Self::load_model_cached().await?;

            // Use raw text without additional context to match training data
            // The models were trained on raw text, not text with meta-instructions
            let contextual_text = text.to_string();

            // Tokenize the input text
            let encoding = tokenizer
                .encode(contextual_text.as_str(), true)
                .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

            let input_ids = encoding.get_ids();
            let attention_mask = encoding.get_attention_mask();

            // Convert to ONNX tensors
            let input_ids_array = Array2::from_shape_vec(
                (1, input_ids.len()),
                input_ids.iter().map(|&x| x as i64).collect(),
            )?;

            let attention_mask_array = Array2::from_shape_vec(
                (1, attention_mask.len()),
                attention_mask.iter().map(|&x| x as i64).collect(),
            )?;

            // Create ONNX inputs - convert to CowArray format
            use ndarray::CowArray;
            let input_ids_cow = CowArray::from(input_ids_array.into_dyn());
            let attention_mask_cow = CowArray::from(attention_mask_array.into_dyn());

            let inputs = vec![
                ort::Value::from_array(session.allocator(), &input_ids_cow)?,
                ort::Value::from_array(session.allocator(), &attention_mask_cow)?,
            ];

            // Run inference
            let outputs = session.run(inputs)?;

            // Extract logits from output
            let logits = outputs[0].try_extract::<f32>()?.view().to_owned();

            // Apply softmax to get probabilities
            let logits_slice = logits.as_slice()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert logits to slice"))?;
            let exp_sum: f32 = logits_slice.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits_slice.iter().map(|x| x.exp() / exp_sum).collect();

            // For binary classification, index 1 is typically the "injection" class
            let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

            // Determine threat level based on confidence and threshold
            let threat_level = if injection_probability < self.confidence_threshold {
                ThreatLevel::Safe
            } else if injection_probability >= 0.9 {
                ThreatLevel::High
            } else if injection_probability >= (self.confidence_threshold + 0.1).min(0.85) {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };

            let explanation = if injection_probability < self.confidence_threshold {
                format!(
                    "ONNX DeBERTa: injection probability {:.3} below threshold {:.3}, treating as safe",
                    injection_probability, self.confidence_threshold
                )
            } else {
                format!(
                    "ONNX DeBERTa: potential prompt injection detected (confidence: {:.3})",
                    injection_probability
                )
            };

            Ok(ScanResult::with_confidence(
                threat_level,
                injection_probability,
                explanation,
            ))
        }

        /// Check if content is obviously safe and doesn't need detailed analysis
        fn is_obviously_safe_content(_text: &str) -> bool {
            // Let the ML models handle all content analysis
            // No pre-filtering to avoid potential security bypasses
            false
        }
    }

    #[async_trait]
    impl ContentScanner for OnnxDeepsetDebertaScanner {
        async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
            // Combine all content into a single string for analysis
            let combined_text = content
                .iter()
                .map(|c| match c {
                    Content::Text(text_content) => text_content.text.clone(),
                    Content::Image { .. } => "[Image content not supported]".to_string(),
                    Content::Resource(resource) => resource.get_text(),
                })
                .collect::<Vec<_>>()
                .join("\n");

            // Pre-filter obviously safe content to reduce false positives
            if Self::is_obviously_safe_content(&combined_text) {
                return Ok(ScanResult::new(
                    ThreatLevel::Safe,
                    "ONNX DeBERTa: Pre-filtering disabled, analyzing with ML model".to_string(),
                ));
            }

            self.analyze_text(&combined_text).await
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
                .map(|c| match c {
                    Content::Text(text_content) => text_content.text.clone(),
                    Content::Image { .. } => "[Image content not supported]".to_string(),
                    Content::Resource(resource) => resource.get_text(),
                })
                .collect::<Vec<_>>()
                .join("\n");

            // Add tool context to the analysis
            let contextual_content = format!(
                "Tool: {}\nArguments: {}\nResult: {}",
                tool_name,
                serde_json::to_string(arguments).unwrap_or_default(),
                combined_content
            );

            self.analyze_text(&contextual_content).await
        }

    }

    pub struct OnnxProtectAiDebertaScanner {
        confidence_threshold: f32,
    }

    static PROTECTAI_MODEL_CACHE: OnceCell<(Arc<Session>, Arc<Tokenizer>)> = OnceCell::const_new();

    impl OnnxProtectAiDebertaScanner {
        pub fn new(confidence_threshold: f32) -> Self {
            Self { confidence_threshold }
        }

        async fn load_model_cached() -> Result<(Arc<Session>, Arc<Tokenizer>)> {
            PROTECTAI_MODEL_CACHE
                .get_or_try_init(|| async {
                    tracing::info!("Loading ONNX ProtectAI DeBERTa model (with runtime download if needed)...");

                    // Get the global downloader
                    let downloader = get_global_downloader().await?;
                    
                    // Ensure the model is available (download if needed)
                    let model_info = ModelInfo::protectai_deberta();
                    let (model_path, tokenizer_path) = downloader.ensure_model_available(&model_info).await?;

                    tracing::info!("Loading ONNX ProtectAI model from: {:?}", model_path);

                    // Create ONNX environment
                    let environment = Arc::new(Environment::builder().build()?);

                    let session = SessionBuilder::new(&environment)?
                        .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
                        .with_intra_threads(1)?
                        .with_model_from_file(&model_path)?;

                    // Load tokenizer
                    let tokenizer = Tokenizer::from_file(tokenizer_path)
                        .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

                    tracing::info!("Successfully loaded ONNX ProtectAI DeBERTa model and tokenizer");

                    Ok((Arc::new(session), Arc::new(tokenizer)))
                })
                .await
                .cloned()
        }

        async fn analyze_text(&self, text: &str) -> Result<ScanResult> {
            // Load model and tokenizer (cached globally)
            let (session, tokenizer) = Self::load_model_cached().await?;

            // Use raw text without additional context to match training data
            // The models were trained on raw text, not text with meta-instructions
            let contextual_text = text.to_string();

            // Tokenize the input text
            let encoding = tokenizer
                .encode(contextual_text.as_str(), true)
                .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

            let input_ids = encoding.get_ids();
            let attention_mask = encoding.get_attention_mask();

            // Convert to ONNX tensors
            let input_ids_array = Array2::from_shape_vec(
                (1, input_ids.len()),
                input_ids.iter().map(|&x| x as i64).collect(),
            )?;

            let attention_mask_array = Array2::from_shape_vec(
                (1, attention_mask.len()),
                attention_mask.iter().map(|&x| x as i64).collect(),
            )?;

            // Create ONNX inputs - convert to CowArray format
            use ndarray::CowArray;
            let input_ids_cow = CowArray::from(input_ids_array.into_dyn());
            let attention_mask_cow = CowArray::from(attention_mask_array.into_dyn());

            let inputs = vec![
                ort::Value::from_array(session.allocator(), &input_ids_cow)?,
                ort::Value::from_array(session.allocator(), &attention_mask_cow)?,
            ];

            // Run inference
            let outputs = session.run(inputs)?;

            // Extract logits from output
            let logits = outputs[0].try_extract::<f32>()?.view().to_owned();

            // Apply softmax to get probabilities
            let logits_slice = logits.as_slice()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert logits to slice"))?;
            let exp_sum: f32 = logits_slice.iter().map(|x| x.exp()).sum();
            let probabilities: Vec<f32> = logits_slice.iter().map(|x| x.exp() / exp_sum).collect();

            // For binary classification, index 1 is typically the "injection" class
            let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

            // Determine threat level based on confidence and threshold
            let threat_level = if injection_probability < self.confidence_threshold {
                ThreatLevel::Safe
            } else if injection_probability >= 0.9 {
                ThreatLevel::High
            } else if injection_probability >= (self.confidence_threshold + 0.1).min(0.85) {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };

            let explanation = if injection_probability < self.confidence_threshold {
                format!(
                    "ONNX ProtectAI: injection probability {:.3} below threshold {:.3}, treating as safe",
                    injection_probability, self.confidence_threshold
                )
            } else {
                format!(
                    "ONNX ProtectAI: potential prompt injection detected (confidence: {:.3})",
                    injection_probability
                )
            };

            Ok(ScanResult::with_confidence(
                threat_level,
                injection_probability,
                explanation,
            ))
        }

        /// Check if content is obviously safe and doesn't need detailed analysis
        fn is_obviously_safe_content(_text: &str) -> bool {
            // Let the ML models handle all content analysis
            // No pre-filtering to avoid potential security bypasses
            false
        }
    }

    #[async_trait]
    impl ContentScanner for OnnxProtectAiDebertaScanner {
        async fn scan_content(&self, content: &[Content]) -> Result<ScanResult> {
            // Combine all content into a single string for analysis
            let combined_text = content
                .iter()
                .map(|c| match c {
                    Content::Text(text_content) => text_content.text.clone(),
                    Content::Image { .. } => "[Image content not supported]".to_string(),
                    Content::Resource(resource) => resource.get_text(),
                })
                .collect::<Vec<_>>()
                .join("\n");

            // Pre-filter obviously safe content to reduce false positives
            if Self::is_obviously_safe_content(&combined_text) {
                return Ok(ScanResult::new(
                    ThreatLevel::Safe,
                    "ONNX ProtectAI: Pre-filtering disabled, analyzing with ML model".to_string(),
                ));
            }

            self.analyze_text(&combined_text).await
        }

        async fn scan_tool_result(&self, tool_name: &str, arguments: &Value, result: &[Content]) -> Result<ScanResult> {
            // For tool results, we analyze the content with some context
            let combined_content = result
                .iter()
                .map(|c| match c {
                    Content::Text(text_content) => text_content.text.clone(),
                    Content::Image { .. } => "[Image content not supported]".to_string(),
                    Content::Resource(resource) => resource.get_text(),
                })
                .collect::<Vec<_>>()
                .join("\n");

            // Add tool context to the analysis
            let contextual_content = format!(
                "Tool: {}\nArguments: {}\nResult: {}",
                tool_name,
                serde_json::to_string(arguments).unwrap_or_default(),
                combined_content
            );

            self.analyze_text(&contextual_content).await
        }

    }
}

#[cfg(feature = "security-onnx")]
pub use onnx_scanners::{OnnxDeepsetDebertaScanner, OnnxProtectAiDebertaScanner};

// For when ONNX feature is not enabled, provide stub implementations
#[cfg(not(feature = "security-onnx"))]
pub struct OnnxDeepsetDebertaScanner {
    _confidence_threshold: f32,
}

#[cfg(not(feature = "security-onnx"))]
impl OnnxDeepsetDebertaScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            _confidence_threshold: confidence_threshold,
        }
    }
}

#[cfg(not(feature = "security-onnx"))]
#[async_trait::async_trait]
impl super::content_scanner::ContentScanner for OnnxDeepsetDebertaScanner {
    async fn scan_content(&self, _content: &[mcp_core::Content]) -> anyhow::Result<super::content_scanner::ScanResult> {
        Err(anyhow::anyhow!("ONNX scanner not available (security-onnx feature not enabled)"))
    }

    async fn scan_tool_result(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        _result: &[mcp_core::Content],
    ) -> anyhow::Result<super::content_scanner::ScanResult> {
        Err(anyhow::anyhow!("ONNX scanner not available (security-onnx feature not enabled)"))
    }
}

#[cfg(not(feature = "security-onnx"))]
pub struct OnnxProtectAiDebertaScanner {
    _confidence_threshold: f32,
}

#[cfg(not(feature = "security-onnx"))]
impl OnnxProtectAiDebertaScanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            _confidence_threshold: confidence_threshold,
        }
    }
}

#[cfg(not(feature = "security-onnx"))]
#[async_trait::async_trait]
impl super::content_scanner::ContentScanner for OnnxProtectAiDebertaScanner {
    async fn scan_content(&self, _content: &[mcp_core::Content]) -> anyhow::Result<super::content_scanner::ScanResult> {
        Err(anyhow::anyhow!("ONNX scanner not available (security-onnx feature not enabled)"))
    }

    async fn scan_tool_result(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        _result: &[mcp_core::Content],
    ) -> anyhow::Result<super::content_scanner::ScanResult> {
        Err(anyhow::anyhow!("ONNX scanner not available (security-onnx feature not enabled)"))
    }
}
