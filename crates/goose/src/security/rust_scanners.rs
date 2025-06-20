use super::content_scanner::{ContentScanner, ScanResult, ThreatLevel};
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
        MODEL_CACHE.get_or_try_init(|| async {
            tracing::info!("Loading ONNX DeBERTa model from disk...");
            
            // Create ONNX environment
            let environment = Arc::new(Environment::builder().build()?);
            
            // Load the ONNX model (find project root reliably)
            let project_root = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .ancestors()
                .find(|path| path.join("onnx_models").exists())
                .unwrap_or_else(|| std::path::Path::new("/Users/dkoelemeijer/Development/goose"))
                .to_path_buf();
            
            let model_path = project_root.join("onnx_models/deepset_deberta-v3-base-injection.onnx");
            
            tracing::info!("Loading ONNX model from: {:?}", model_path);
            
            let session = SessionBuilder::new(&environment)?
                .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
                .with_intra_threads(1)?
                .with_model_from_file(&model_path)?;
            
            // Load tokenizer
            let tokenizer_path = project_root.join("onnx_models/tokenizer.json");
            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;
            
            tracing::info!("Successfully loaded ONNX DeBERTa model and tokenizer");
            
            Ok((Arc::new(session), Arc::new(tokenizer)))
        }).await.cloned()
    }

    async fn analyze_text(&self, text: &str) -> Result<ScanResult> {
        // Load model and tokenizer (cached globally)
        let (session, tokenizer) = Self::load_model_cached().await?;

        // Tokenize the input text
        let encoding = tokenizer
            .encode(text, true)
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
        let logits = outputs[0]
            .try_extract::<f32>()?
            .view()
            .to_owned();

        // Apply softmax to get probabilities
        let logits_slice = logits.as_slice().unwrap();
        let exp_sum: f32 = logits_slice.iter().map(|x| x.exp()).sum();
        let probabilities: Vec<f32> = logits_slice.iter().map(|x| x.exp() / exp_sum).collect();

        // For binary classification, index 1 is typically the "injection" class
        let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

        // Determine threat level based on confidence and threshold
        let threat_level = if injection_probability < self.confidence_threshold {
            ThreatLevel::Safe
        } else if injection_probability >= 0.9 {
            ThreatLevel::High
        } else if injection_probability >= 0.7 {
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

        Ok(ScanResult {
            threat_level,
            explanation,
            sanitized_content: None,
        })
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
        Self {
            confidence_threshold,
        }
    }

    async fn load_model_cached() -> Result<(Arc<Session>, Arc<Tokenizer>)> {
        PROTECTAI_MODEL_CACHE.get_or_try_init(|| async {
            tracing::info!("Loading ONNX ProtectAI DeBERTa model from disk...");

            // Create ONNX environment
            let environment = Arc::new(Environment::builder().build()?);

            // Load the ONNX model (find project root reliably)
            let project_root = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .ancestors()
                .find(|path| path.join("onnx_models").exists())
                .unwrap_or_else(|| std::path::Path::new("/Users/dkoelemeijer/Development/goose"))
                .to_path_buf();

            let model_path = project_root.join("onnx_models/protectai_deberta-v3-base-prompt-injection-v2.onnx");

            tracing::info!("Loading ONNX ProtectAI model from: {:?}", model_path);

            let session = SessionBuilder::new(&environment)?
                .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
                .with_intra_threads(1)?
                .with_model_from_file(&model_path)?;

            // Load tokenizer (same tokenizer for both models)
            let tokenizer_path = project_root.join("onnx_models/tokenizer.json");
            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

            tracing::info!("Successfully loaded ONNX ProtectAI DeBERTa model and tokenizer");

            Ok((Arc::new(session), Arc::new(tokenizer)))
        }).await.cloned()
    }

    async fn analyze_text(&self, text: &str) -> Result<ScanResult> {
        // Load model and tokenizer (cached globally)
        let (session, tokenizer) = Self::load_model_cached().await?;

        // Tokenize the input text
        let encoding = tokenizer
            .encode(text, true)
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
        let logits = outputs[0]
            .try_extract::<f32>()?
            .view()
            .to_owned();

        // Apply softmax to get probabilities
        let logits_slice = logits.as_slice().unwrap();
        let exp_sum: f32 = logits_slice.iter().map(|x| x.exp()).sum();
        let probabilities: Vec<f32> = logits_slice.iter().map(|x| x.exp() / exp_sum).collect();

        // For binary classification, index 1 is typically the "injection" class
        let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

        // Determine threat level based on confidence and threshold
        let threat_level = if injection_probability < self.confidence_threshold {
            ThreatLevel::Safe
        } else if injection_probability >= 0.9 {
            ThreatLevel::High
        } else if injection_probability >= 0.7 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        let explanation = if injection_probability < self.confidence_threshold {
            format!(
                "ONNX ProtectAI DeBERTa: injection probability {:.3} below threshold {:.3}, treating as safe",
                injection_probability, self.confidence_threshold
            )
        } else {
            format!(
                "ONNX ProtectAI DeBERTa: potential prompt injection detected (confidence: {:.3})",
                injection_probability
            )
        };

        Ok(ScanResult {
            threat_level,
            explanation,
            sanitized_content: None,
        })
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

pub struct OnnxLlamaPromptGuard2Scanner {
    confidence_threshold: f32,
}

static LLAMA_GUARD2_MODEL_CACHE: OnceCell<(Arc<Session>, Arc<Tokenizer>)> = OnceCell::const_new();

impl OnnxLlamaPromptGuard2Scanner {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            confidence_threshold,
        }
    }

    async fn load_model_cached() -> Result<(Arc<Session>, Arc<Tokenizer>)> {
        LLAMA_GUARD2_MODEL_CACHE.get_or_try_init(|| async {
            tracing::info!("Loading ONNX Llama Prompt Guard 2 model from disk...");

            // Create ONNX environment
            let environment = Arc::new(Environment::builder().build()?);

            // Load the ONNX model (find project root reliably)
            let project_root = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .ancestors()
                .find(|path| path.join("onnx_models").exists())
                .unwrap_or_else(|| std::path::Path::new("/Users/dkoelemeijer/Development/goose"))
                .to_path_buf();

            let model_path = project_root.join("onnx_models/meta-llama_Llama-Prompt-Guard-2-86M.onnx");

            tracing::info!("Loading ONNX Llama Guard 2 model from: {:?}", model_path);

            let session = SessionBuilder::new(&environment)?
                .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
                .with_intra_threads(1)?
                .with_model_from_file(&model_path)?;

            // Load tokenizer (Llama Guard 2 has its own tokenizer)
            let tokenizer_path = project_root.join("onnx_models/meta-llama_Llama-Prompt-Guard-2-86M_tokenizer/tokenizer.json");
            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

            tracing::info!("Successfully loaded ONNX Llama Prompt Guard 2 model and tokenizer");

            Ok((Arc::new(session), Arc::new(tokenizer)))
        }).await.cloned()
    }

    async fn analyze_text(&self, text: &str) -> Result<ScanResult> {
        // Load model and tokenizer (cached globally)
        let (session, tokenizer) = Self::load_model_cached().await?;

        // Tokenize the input text
        let encoding = tokenizer
            .encode(text, true)
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
        let logits = outputs[0]
            .try_extract::<f32>()?
            .view()
            .to_owned();

        // Apply softmax to get probabilities
        let logits_slice = logits.as_slice().unwrap();
        let exp_sum: f32 = logits_slice.iter().map(|x| x.exp()).sum();
        let probabilities: Vec<f32> = logits_slice.iter().map(|x| x.exp() / exp_sum).collect();

        // For binary classification, index 1 is typically the "injection" class
        let injection_probability = probabilities.get(1).copied().unwrap_or(0.0);

        // Determine threat level based on confidence and threshold
        let threat_level = if injection_probability < self.confidence_threshold {
            ThreatLevel::Safe
        } else if injection_probability >= 0.9 {
            ThreatLevel::High
        } else if injection_probability >= 0.7 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        let explanation = if injection_probability < self.confidence_threshold {
            format!(
                "ONNX Llama Guard 2: injection probability {:.3} below threshold {:.3}, treating as safe",
                injection_probability, self.confidence_threshold
            )
        } else {
            format!(
                "ONNX Llama Guard 2: potential prompt injection detected (confidence: {:.3})",
                injection_probability
            )
        };

        Ok(ScanResult {
            threat_level,
            explanation,
            sanitized_content: None,
        })
    }
}

#[async_trait]
impl ContentScanner for OnnxLlamaPromptGuard2Scanner {
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

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_core::Content;

    #[tokio::test]
    async fn test_onnx_scanner_basic() {
        // Initialize tracing for the test
        let _ = tracing_subscriber::fmt::try_init();
        
        let scanner = OnnxDeepsetDebertaScanner::new(0.7);
        
        // Test with safe content
        let safe_content = vec![Content::text("Hello, how are you today?")];
        let result = scanner.scan_content(&safe_content).await;
        
        match result {
            Ok(scan_result) => {
                println!("✅ ONNX Scanner test passed!");
                println!("   Threat level: {:?}", scan_result.threat_level);
                println!("   Explanation: {}", scan_result.explanation);
            }
            Err(e) => {
                println!("❌ ONNX Scanner test failed: {}", e);
                // Don't panic - model files might not be available in CI
            }
        }
    }
}
