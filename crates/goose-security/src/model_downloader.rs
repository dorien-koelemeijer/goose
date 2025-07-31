#[cfg(feature = "onnx")]
use anyhow::{anyhow, Result};
#[cfg(feature = "onnx")]
use std::path::PathBuf;
#[cfg(feature = "onnx")]
use std::process::Command;
#[cfg(feature = "onnx")]
use tokio::fs;
#[cfg(feature = "onnx")]
use tokio::sync::OnceCell;

#[cfg(feature = "onnx")]
pub struct ModelDownloader {
    cache_dir: PathBuf,
}

#[cfg(feature = "onnx")]
impl ModelDownloader {
    pub fn new() -> Result<Self> {
        // Use platform-appropriate cache directory
        let cache_dir = if let Some(cache_dir) = dirs::cache_dir() {
            cache_dir.join("goose").join("security_models")
        } else {
            // Fallback to home directory
            dirs::home_dir()
                .ok_or_else(|| anyhow!("Could not determine home directory"))?
                .join(".cache")
                .join("goose")
                .join("security_models")
        };

        Ok(Self { cache_dir })
    }

    pub async fn ensure_model_available(&self, model_info: &ModelInfo) -> Result<(PathBuf, PathBuf)> {
        let model_path = self.cache_dir.join(&model_info.onnx_filename);
        let tokenizer_path = self.cache_dir.join(&model_info.tokenizer_filename);
        let metadata_path = self.cache_dir.join(format!("{}_metadata.json", 
            model_info.hf_model_name.replace("/", "_")));

        // Check if conversion is needed
        let needs_conversion = self.check_conversion_needed(&model_path, &tokenizer_path, &metadata_path, model_info).await?;

        if !needs_conversion {
            tracing::info!(
                model = %model_info.hf_model_name,
                path = ?model_path,
                "Using cached ONNX model"
            );
            return Ok((model_path, tokenizer_path));
        }

        tracing::info!(
            model = %model_info.hf_model_name,
            "🔒 Setting up security model, this may take a moment..."
        );

        // Create cache directory if it doesn't exist
        fs::create_dir_all(&self.cache_dir).await?;

        // Download and convert the model
        self.download_and_convert_model(model_info).await?;

        // Verify the files were created and are valid
        self.verify_converted_model(&model_path, &tokenizer_path, &metadata_path).await?;

        tracing::info!(
            model = %model_info.hf_model_name,
            "✅ Security model ready"
        );

        Ok((model_path, tokenizer_path))
    }

    async fn check_conversion_needed(
        &self,
        model_path: &PathBuf,
        tokenizer_path: &PathBuf,
        metadata_path: &PathBuf,
        model_info: &ModelInfo
    ) -> Result<bool> {
        // 1. Check if required files exist
        if !model_path.exists() || !tokenizer_path.exists() {
            tracing::info!("Model files missing, conversion needed");
            return Ok(true);
        }

        // 2. Check if files are not empty/corrupted
        if let Ok(metadata) = fs::metadata(model_path).await {
            if metadata.len() == 0 {
                tracing::info!("Model file is empty, conversion needed");
                return Ok(true);
            }
        }

        if let Ok(metadata) = fs::metadata(tokenizer_path).await {
            if metadata.len() == 0 {
                tracing::info!("Tokenizer file is empty, conversion needed");
                return Ok(true);
            }
        }

        // 3. Check if metadata exists and is valid
        if !metadata_path.exists() {
            tracing::info!("Metadata file missing, conversion needed");
            return Ok(true);
        }

        // 4. Validate metadata matches expected architecture
        match self.validate_cached_metadata(metadata_path, model_info).await {
            Ok(false) => {
                tracing::info!("Cached metadata doesn't match expected architecture, conversion needed");
                return Ok(true);
            }
            Err(e) => {
                tracing::warn!("Failed to validate metadata: {}, assuming conversion needed", e);
                return Ok(true);
            }
            Ok(true) => {} // Metadata is valid, continue checks
        }

        // 5. Check for model updates (optional - could be expensive)
        if let Ok(needs_update) = self.check_for_model_updates(model_info).await {
            if needs_update {
                tracing::info!("Model has been updated on HuggingFace, conversion needed");
                return Ok(true);
            }
        }

        // 6. Verify ONNX model can be loaded (quick sanity check)
        if let Err(e) = self.quick_onnx_validation(model_path).await {
            tracing::warn!("ONNX model failed validation: {}, conversion needed", e);
            return Ok(true);
        }

        // All checks passed - no conversion needed
        Ok(false)
    }

    async fn validate_cached_metadata(
        &self,
        metadata_path: &PathBuf,
        expected_model_info: &ModelInfo
    ) -> Result<bool> {
        let metadata_content = fs::read_to_string(metadata_path).await?;
        let cached_metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;

        // Check if the cached architecture matches what we expect
        let expected_arch = &expected_model_info.architecture;
        
        // Compare key architecture fields
        let cached_model_type = cached_metadata.get("model_type").and_then(|v| v.as_str());
        let expected_model_type = match expected_arch.model_type {
            crate::types::ModelType::SequenceClassification => "SequenceClassification",
            crate::types::ModelType::TokenClassification => "TokenClassification",
            crate::types::ModelType::TextGeneration => "TextGeneration",
            crate::types::ModelType::Custom(ref s) => s,
        };

        if cached_model_type != Some(expected_model_type) {
            return Ok(false);
        }

        let cached_task = cached_metadata.get("task").and_then(|v| v.as_str());
        let expected_task = match expected_arch.task {
            crate::types::ModelTask::PromptInjectionDetection => "PromptInjectionDetection",
            crate::types::ModelTask::ToxicityDetection => "ToxicityDetection",
            crate::types::ModelTask::SentimentAnalysis => "SentimentAnalysis",
            crate::types::ModelTask::Custom(ref s) => s,
        };

        if cached_task != Some(expected_task) {
            return Ok(false);
        }

        // Could add more detailed checks here (input/output names, etc.)
        Ok(true)
    }

    async fn check_for_model_updates(&self, _model_info: &ModelInfo) -> Result<bool> {
        // This is optional and could be expensive, so we might want to:
        // 1. Only check periodically (e.g., once per day)
        // 2. Make it configurable
        // 3. Use ETag/Last-Modified headers if available
        
        // For now, we'll skip this check to avoid network overhead
        // In the future, could implement:
        // - Check HuggingFace API for model last_modified date
        // - Compare with cached conversion timestamp
        // - Use git commit hash if available
        
        Ok(false) // Assume no updates for now
    }

    async fn quick_onnx_validation(&self, model_path: &PathBuf) -> Result<()> {
        // Quick check to see if ONNX file can be opened
        // This doesn't do full validation but catches obviously corrupted files
        
        use ort::session::Session;
        
        match Session::builder() {
            Ok(builder) => {
                match builder.commit_from_file(model_path) {
                    Ok(_session) => Ok(()), // Model loads successfully
                    Err(e) => Err(anyhow!("ONNX model failed to load: {}", e)),
                }
            }
            Err(e) => Err(anyhow!("Failed to create ONNX session builder: {}", e)),
        }
    }

    async fn verify_converted_model(
        &self,
        model_path: &PathBuf,
        tokenizer_path: &PathBuf,
        metadata_path: &PathBuf
    ) -> Result<()> {
        // Verify all files were created
        if !model_path.exists() {
            return Err(anyhow!("Model file was not created: {:?}", model_path));
        }
        if !tokenizer_path.exists() {
            return Err(anyhow!("Tokenizer file was not created: {:?}", tokenizer_path));
        }
        if !metadata_path.exists() {
            return Err(anyhow!("Metadata file was not created: {:?}", metadata_path));
        }

        // Verify files are not empty
        let model_size = fs::metadata(model_path).await?.len();
        if model_size == 0 {
            return Err(anyhow!("Model file is empty"));
        }

        let tokenizer_size = fs::metadata(tokenizer_path).await?.len();
        if tokenizer_size == 0 {
            return Err(anyhow!("Tokenizer file is empty"));
        }

        // Verify ONNX model can be loaded
        self.quick_onnx_validation(model_path).await?;

        // Verify metadata is valid JSON
        let metadata_content = fs::read_to_string(metadata_path).await?;
        serde_json::from_str::<serde_json::Value>(&metadata_content)
            .map_err(|e| anyhow!("Invalid metadata JSON: {}", e))?;

        tracing::debug!(
            "Verified converted model - ONNX: {:.1}KB, Tokenizer: {:.1}KB",
            model_size as f64 / 1024.0,
            tokenizer_size as f64 / 1024.0
        );

        Ok(())
    }

    pub async fn force_reconversion(&self, model_info: &ModelInfo) -> Result<(PathBuf, PathBuf)> {
        tracing::info!(
            model = %model_info.hf_model_name,
            "🔄 Forcing model reconversion..."
        );

        let model_path = self.cache_dir.join(&model_info.onnx_filename);
        let tokenizer_path = self.cache_dir.join(&model_info.tokenizer_filename);
        let metadata_path = self.cache_dir.join(format!("{}_metadata.json", 
            model_info.hf_model_name.replace("/", "_")));

        // Remove existing files
        if model_path.exists() {
            fs::remove_file(&model_path).await?;
        }
        if tokenizer_path.exists() {
            fs::remove_file(&tokenizer_path).await?;
        }
        if metadata_path.exists() {
            fs::remove_file(&metadata_path).await?;
        }

        // Force conversion
        self.ensure_model_available(model_info).await
    }

    pub async fn clear_model_cache(&self, model_name: &str) -> Result<()> {
        let safe_name = model_name.replace("/", "_");
        let model_path = self.cache_dir.join(format!("{}.onnx", safe_name));
        let tokenizer_path = self.cache_dir.join(format!("{}_tokenizer.json", safe_name));
        let metadata_path = self.cache_dir.join(format!("{}_metadata.json", safe_name));

        let mut removed_files = 0;
        
        if model_path.exists() {
            fs::remove_file(&model_path).await?;
            removed_files += 1;
        }
        if tokenizer_path.exists() {
            fs::remove_file(&tokenizer_path).await?;
            removed_files += 1;
        }
        if metadata_path.exists() {
            fs::remove_file(&metadata_path).await?;
            removed_files += 1;
        }

        if removed_files > 0 {
            tracing::info!("Cleared cache for model '{}' ({} files removed)", model_name, removed_files);
        } else {
            tracing::info!("No cached files found for model '{}'", model_name);
        }

        Ok(())
    }

    pub async fn load_model_metadata(&self, model_info: &ModelInfo) -> Result<crate::types::ModelArchitecture> {
        let metadata_path = self.cache_dir.join(format!("{}_metadata.json", 
            model_info.hf_model_name.replace("/", "_")));

        if metadata_path.exists() {
            let metadata_content = fs::read_to_string(&metadata_path).await?;
            let metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;
            
            // Convert JSON metadata to ModelArchitecture
            let model_type = match metadata.get("model_type").and_then(|v| v.as_str()) {
                Some("SequenceClassification") => crate::types::ModelType::SequenceClassification,
                Some("TokenClassification") => crate::types::ModelType::TokenClassification,
                Some("TextGeneration") => crate::types::ModelType::TextGeneration,
                Some(other) => crate::types::ModelType::Custom(other.to_string()),
                None => crate::types::ModelType::SequenceClassification,
            };

            let task = match metadata.get("task").and_then(|v| v.as_str()) {
                Some("PromptInjectionDetection") => crate::types::ModelTask::PromptInjectionDetection,
                Some("ToxicityDetection") => crate::types::ModelTask::ToxicityDetection,
                Some("SentimentAnalysis") => crate::types::ModelTask::SentimentAnalysis,
                Some(other) => crate::types::ModelTask::Custom(other.to_string()),
                None => crate::types::ModelTask::PromptInjectionDetection,
            };

            let input_names = metadata.get("input_names")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_else(|| vec!["input_ids".to_string(), "attention_mask".to_string()]);

            let output_names = metadata.get("output_names")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_else(|| vec!["logits".to_string()]);

            let max_sequence_length = metadata.get("max_sequence_length")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);

            let num_labels = metadata.get("num_labels")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);

            let label_mapping = metadata.get("label_mapping")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_u64().map(|num| (k.clone(), num as usize)))
                        .collect()
                });

            Ok(crate::types::ModelArchitecture {
                model_type,
                task,
                input_names,
                output_names,
                max_sequence_length,
                num_labels,
                label_mapping,
            })
        } else {
            // Fallback to the architecture from ModelInfo
            Ok(model_info.architecture.clone())
        }
    }

    async fn download_and_convert_model(&self, model_info: &ModelInfo) -> Result<()> {
        // Set up Python virtual environment with required dependencies
        let venv_dir = self.cache_dir.join("python_venv");
        self.ensure_python_venv(&venv_dir).await?;
        
        let python_script = self.create_conversion_script(model_info).await?;
        
        tracing::info!("Converting model to ONNX format...");
        
        // Use the virtual environment's Python
        let python_exe = if cfg!(windows) {
            venv_dir.join("Scripts").join("python.exe")
        } else {
            venv_dir.join("bin").join("python")
        };
        
        let output = Command::new(&python_exe)
            .arg(&python_script)
            .env("CACHE_DIR", &self.cache_dir)
            .env("MODEL_NAME", &model_info.hf_model_name)
            .output()
            .map_err(|e| anyhow!("Failed to execute Python conversion script: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "Model conversion failed:\nStdout: {}\nStderr: {}",
                stdout,
                stderr
            ));
        }

        // Clean up the temporary script
        let _ = fs::remove_file(&python_script).await;

        Ok(())
    }

    async fn ensure_python_venv(&self, venv_dir: &std::path::Path) -> Result<()> {
        let python_exe = if cfg!(windows) {
            venv_dir.join("Scripts").join("python.exe")
        } else {
            venv_dir.join("bin").join("python")
        };

        if python_exe.exists() {
            // Check if required packages are installed
            let output = Command::new(&python_exe)
                .args(&["-c", "import torch, transformers, onnx, tokenizers; print('OK')"])
                .output();
            
            if let Ok(output) = output {
                if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "OK" {
                    return Ok(());
                }
            }
        }

        tracing::info!("Setting up Python environment for model conversion...");

        // Create virtual environment
        fs::create_dir_all(venv_dir).await?;
        
        let output = Command::new("python3")
            .args(&["-m", "venv", venv_dir.to_str()
                .ok_or_else(|| anyhow!("Invalid venv directory path"))?])
            .output()
            .map_err(|e| anyhow!("Failed to create Python virtual environment: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to create virtual environment: {}", stderr));
        }

        // Install required packages
        let pip_exe = if cfg!(windows) {
            venv_dir.join("Scripts").join("pip.exe")
        } else {
            venv_dir.join("bin").join("pip")
        };

        let packages = ["torch", "transformers", "onnx", "tokenizers"];

        for package in &packages {
            let output = Command::new(&pip_exe)
                .args(&["install", package])
                .output()
                .map_err(|e| anyhow!("Failed to install {}: {}", package, e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("Failed to install {}: {}", package, stderr));
            }
        }

        Ok(())
    }

    async fn create_conversion_script(&self, model_info: &ModelInfo) -> Result<PathBuf> {
        let script_content = format!(
            r#"#!/usr/bin/env python3
import os
import sys
import json
import torch
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification, 
    AutoModelForTokenClassification, AutoConfig, AutoModel
)
from pathlib import Path

def detect_model_type(config):
    """Detect the model type from the config"""
    if hasattr(config, 'problem_type'):
        if config.problem_type == 'single_label_classification':
            return 'sequence_classification'
        elif config.problem_type == 'multi_label_classification':
            return 'sequence_classification'
    
    if hasattr(config, 'num_labels') and config.num_labels > 0:
        return 'sequence_classification'
    
    # Check architecture-specific attributes
    if hasattr(config, 'model_type'):
        if config.model_type in ['bert', 'roberta', 'deberta', 'distilbert']:
            # These are typically used for classification
            return 'sequence_classification'
        elif config.model_type in ['gpt2', 'gpt-neo', 'llama']:
            return 'text_generation'
    
    # Default fallback
    return 'sequence_classification'

def load_model_by_type(model_name: str, model_type: str, auth_kwargs: dict):
    """Load model based on detected type"""
    try:
        if model_type == 'sequence_classification':
            return AutoModelForSequenceClassification.from_pretrained(model_name, **auth_kwargs)
        elif model_type == 'token_classification':
            return AutoModelForTokenClassification.from_pretrained(model_name, **auth_kwargs)
        elif model_type == 'text_generation':
            return AutoModel.from_pretrained(model_name, **auth_kwargs)
        else:
            # Fallback to AutoModel
            return AutoModel.from_pretrained(model_name, **auth_kwargs)
    except Exception as e:
        print(f"Failed to load as {{model_type}}, trying AutoModel: {{e}}")
        return AutoModel.from_pretrained(model_name, **auth_kwargs)

def get_model_inputs_outputs(model, tokenizer, model_type: str, config):
    """Determine input/output structure based on model type and config"""
    
    # Standard inputs for most transformer models
    input_names = ['input_ids', 'attention_mask']
    
    # Determine outputs based on model type
    if model_type == 'sequence_classification':
        output_names = ['logits']
        num_labels = getattr(config, 'num_labels', 2)
    elif model_type == 'token_classification':
        output_names = ['logits']
        num_labels = getattr(config, 'num_labels', 2)
    elif model_type == 'text_generation':
        output_names = ['last_hidden_state']
        num_labels = None
    else:
        # Try to infer from model outputs
        dummy_text = "This is a test input for model inspection"
        inputs = tokenizer(dummy_text, return_tensors="pt", padding=True, truncation=True, max_length=128)
        
        with torch.no_grad():
            outputs = model(**inputs)
            
        if hasattr(outputs, 'logits'):
            output_names = ['logits']
            num_labels = outputs.logits.shape[-1] if outputs.logits.dim() > 1 else None
        elif hasattr(outputs, 'last_hidden_state'):
            output_names = ['last_hidden_state']
            num_labels = None
        else:
            # Fallback
            output_names = ['output']
            num_labels = None
    
    return input_names, output_names, num_labels

def create_model_metadata(model_name: str, model_type: str, input_names: list, 
                         output_names: list, num_labels: int, config) -> dict:
    """Create metadata about the model architecture"""
    
    # Detect task based on model name and config
    lower_name = model_name.lower()
    if 'prompt-injection' in lower_name or 'injection' in lower_name:
        task = 'PromptInjectionDetection'
        label_mapping = {{"safe": 0, "injection": 1}}
    elif 'toxic' in lower_name or 'hate' in lower_name:
        task = 'ToxicityDetection'
        label_mapping = {{"non_toxic": 0, "toxic": 1}}
    elif 'sentiment' in lower_name:
        task = 'SentimentAnalysis'
        label_mapping = {{"negative": 0, "neutral": 1, "positive": 2}}
    else:
        task = 'Custom'
        label_mapping = None
    
    # Map model types
    type_mapping = {{
        'sequence_classification': 'SequenceClassification',
        'token_classification': 'TokenClassification', 
        'text_generation': 'TextGeneration'
    }}
    
    return {{
        "model_type": type_mapping.get(model_type, "Custom"),
        "task": task,
        "input_names": input_names,
        "output_names": output_names,
        "max_sequence_length": getattr(config, 'max_position_embeddings', 512),
        "num_labels": num_labels,
        "label_mapping": label_mapping
    }}

def convert_model_to_onnx(model_name: str, output_dir: str):
    print(f"Converting {{model_name}} to ONNX...")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    try:
        hf_token = os.getenv('HUGGINGFACE_TOKEN') or os.getenv('HF_TOKEN')
        auth_kwargs = {{}}
        if hf_token:
            auth_kwargs['token'] = hf_token

        # Load config first to detect model type
        config = AutoConfig.from_pretrained(model_name, **auth_kwargs)
        model_type = detect_model_type(config)
        
        print(f"Detected model type: {{model_type}}")
        
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained(model_name, **auth_kwargs)
        model = load_model_by_type(model_name, model_type, auth_kwargs)
        model.eval()

        # Determine input/output structure
        input_names, output_names, num_labels = get_model_inputs_outputs(model, tokenizer, model_type, config)
        
        print(f"Input names: {{input_names}}")
        print(f"Output names: {{output_names}}")
        print(f"Number of labels: {{num_labels}}")

        # Create dummy inputs for ONNX export
        dummy_text = "This is a test input for ONNX conversion"
        max_length = min(getattr(config, 'max_position_embeddings', 512), 512)
        inputs = tokenizer(dummy_text, return_tensors="pt", padding=True, truncation=True, max_length=max_length)

        # Prepare model inputs for export
        model_inputs = tuple(inputs[name] for name in input_names if name in inputs)
        
        # Create dynamic axes
        dynamic_axes = {{}}
        for name in input_names:
            if name in inputs:
                dynamic_axes[name] = {{0: 'batch_size', 1: 'sequence'}}
        for name in output_names:
            dynamic_axes[name] = {{0: 'batch_size'}}

        # Export to ONNX
        model_filename = model_name.replace("/", "_") + ".onnx"
        model_path = os.path.join(output_dir, model_filename)

        torch.onnx.export(
            model,
            model_inputs,
            model_path,
            export_params=True,
            opset_version=14,
            do_constant_folding=True,
            input_names=input_names,
            output_names=output_names,
            dynamic_axes=dynamic_axes
        )

        # Save tokenizer
        tokenizer_filename = model_name.replace("/", "_") + "_tokenizer.json"
        tokenizer_path = os.path.join(output_dir, tokenizer_filename)
        
        temp_dir = os.path.join(output_dir, "temp_tokenizer")
        tokenizer.save_pretrained(temp_dir, legacy_format=False)
        
        import shutil
        temp_tokenizer_json = os.path.join(temp_dir, "tokenizer.json")
        if os.path.exists(temp_tokenizer_json):
            shutil.copy2(temp_tokenizer_json, tokenizer_path)
            shutil.rmtree(temp_dir)

        # Save model metadata
        metadata = create_model_metadata(model_name, model_type, input_names, output_names, num_labels, config)
        metadata_filename = model_name.replace("/", "_") + "_metadata.json"
        metadata_path = os.path.join(output_dir, metadata_filename)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"✅ Successfully converted {{model_name}}")
        print(f"   Model: {{model_path}}")
        print(f"   Tokenizer: {{tokenizer_path}}")
        print(f"   Metadata: {{metadata_path}}")
        return True

    except Exception as e:
        print(f"❌ Failed to convert {{model_name}}: {{e}}")
        import traceback
        traceback.print_exc()
        return False

def main():
    model_name = os.getenv('MODEL_NAME')
    cache_dir = os.getenv('CACHE_DIR')
    
    if not model_name or not cache_dir:
        print("Error: MODEL_NAME and CACHE_DIR environment variables must be set")
        sys.exit(1)
    
    success = convert_model_to_onnx(model_name, cache_dir)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
"#
        );

        let script_path = self.cache_dir.join(format!("convert_model_{}.py", 
            model_info.hf_model_name.replace("/", "_").replace("-", "_")));
        fs::write(&script_path, script_content).await?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).await?;
        }

        Ok(script_path)
    }
}

#[cfg(feature = "onnx")]
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub hf_model_name: String,
    pub onnx_filename: String,
    pub tokenizer_filename: String,
    pub architecture: crate::types::ModelArchitecture,
}

#[cfg(feature = "onnx")]
impl ModelInfo {
    pub fn from_hf_name(hf_model_name: &str) -> Result<Self> {
        Self::from_hf_name_with_architecture(hf_model_name, None)
    }

    pub fn from_hf_name_with_architecture(
        hf_model_name: &str, 
        architecture: Option<crate::types::ModelArchitecture>
    ) -> Result<Self> {
        if hf_model_name.is_empty() {
            return Err(anyhow!("Model name cannot be empty"));
        }
        
        let safe_name = hf_model_name.replace("/", "_");
        let architecture = architecture.unwrap_or_else(|| {
            Self::detect_architecture_from_name(hf_model_name)
        });

        Ok(Self {
            hf_model_name: hf_model_name.to_string(),
            onnx_filename: format!("{}.onnx", safe_name),
            tokenizer_filename: format!("{}_tokenizer.json", safe_name),
            architecture,
        })
    }

    fn detect_architecture_from_name(model_name: &str) -> crate::types::ModelArchitecture {
        use crate::types::{ModelArchitecture, ModelType, ModelTask};
        
        // Try to infer architecture from model name patterns
        let lower_name = model_name.to_lowercase();
        
        if lower_name.contains("prompt-injection") || lower_name.contains("injection") {
            ModelArchitecture {
                model_type: ModelType::SequenceClassification,
                task: ModelTask::PromptInjectionDetection,
                input_names: vec!["input_ids".to_string(), "attention_mask".to_string()],
                output_names: vec!["logits".to_string()],
                max_sequence_length: Some(512),
                num_labels: Some(2),
                label_mapping: Some([
                    ("safe".to_string(), 0),
                    ("injection".to_string(), 1),
                ].into_iter().collect()),
            }
        } else if lower_name.contains("toxic") || lower_name.contains("hate") {
            ModelArchitecture {
                model_type: ModelType::SequenceClassification,
                task: ModelTask::ToxicityDetection,
                input_names: vec!["input_ids".to_string(), "attention_mask".to_string()],
                output_names: vec!["logits".to_string()],
                max_sequence_length: Some(512),
                num_labels: Some(2),
                label_mapping: Some([
                    ("non_toxic".to_string(), 0),
                    ("toxic".to_string(), 1),
                ].into_iter().collect()),
            }
        } else if lower_name.contains("sentiment") {
            ModelArchitecture {
                model_type: ModelType::SequenceClassification,
                task: ModelTask::SentimentAnalysis,
                input_names: vec!["input_ids".to_string(), "attention_mask".to_string()],
                output_names: vec!["logits".to_string()],
                max_sequence_length: Some(512),
                num_labels: Some(3),
                label_mapping: Some([
                    ("negative".to_string(), 0),
                    ("neutral".to_string(), 1),
                    ("positive".to_string(), 2),
                ].into_iter().collect()),
            }
        } else {
            // Default to sequence classification for unknown models
            ModelArchitecture::default()
        }
    }
}

// Global downloader instance
#[cfg(feature = "onnx")]
static GLOBAL_DOWNLOADER: OnceCell<ModelDownloader> = OnceCell::const_new();

#[cfg(feature = "onnx")]
pub async fn get_global_downloader() -> Result<&'static ModelDownloader> {
    GLOBAL_DOWNLOADER
        .get_or_try_init(|| async { ModelDownloader::new() })
        .await
}

// Stub implementations when ONNX feature is not enabled
#[cfg(not(feature = "onnx"))]
pub struct ModelDownloader;

#[cfg(not(feature = "onnx"))]
pub struct ModelInfo;

#[cfg(not(feature = "onnx"))]
impl ModelDownloader {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }
}

#[cfg(not(feature = "onnx"))]
impl ModelInfo {
    pub fn from_hf_name(_: &str) -> anyhow::Result<Self> { 
        Err(anyhow::anyhow!("ONNX models not available (onnx feature not enabled)"))
    }
}