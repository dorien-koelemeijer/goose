#[cfg(feature = "security-onnx")]
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use tokio::sync::OnceCell;

#[cfg(feature = "security-onnx")]
pub struct ModelDownloader {
    cache_dir: PathBuf,
}

#[cfg(feature = "security-onnx")]
impl ModelDownloader {
    pub fn new() -> Result<Self> {
        // Use platform-appropriate cache directory
        let cache_dir = if let Some(cache_dir) = dirs::cache_dir() {
            cache_dir.join("goose").join("onnx_models")
        } else {
            // Fallback to home directory
            dirs::home_dir()
                .ok_or_else(|| anyhow!("Could not determine home directory"))?
                .join(".cache")
                .join("goose")
                .join("onnx_models")
        };

        Ok(Self { cache_dir })
    }

    pub async fn ensure_model_available(&self, model_info: &ModelInfo) -> Result<(PathBuf, PathBuf)> {
        let model_path = self.cache_dir.join(&model_info.onnx_filename);
        let tokenizer_path = self.cache_dir.join(&model_info.tokenizer_filename);

        // Check if both model and tokenizer exist
        if model_path.exists() && tokenizer_path.exists() {
            tracing::info!(
                model = %model_info.hf_model_name,
                path = ?model_path,
                "Using cached ONNX model"
            );
            return Ok((model_path, tokenizer_path));
        }

        tracing::info!(
            model = %model_info.hf_model_name,
            "Model not cached, downloading and converting..."
        );

        // Create cache directory if it doesn't exist
        fs::create_dir_all(&self.cache_dir).await?;

        // Download and convert the model
        self.download_and_convert_model(model_info).await?;

        // Verify the files were created
        if !model_path.exists() || !tokenizer_path.exists() {
            return Err(anyhow!(
                "Model conversion completed but files not found at expected paths"
            ));
        }

        tracing::info!(
            model = %model_info.hf_model_name,
            model_path = ?model_path,
            tokenizer_path = ?tokenizer_path,
            "Successfully downloaded and converted model"
        );

        Ok((model_path, tokenizer_path))
    }

    async fn download_and_convert_model(&self, model_info: &ModelInfo) -> Result<()> {
        // Set up Python virtual environment with required dependencies
        let venv_dir = self.cache_dir.join("python_venv");
        self.ensure_python_venv(&venv_dir).await?;
        
        let python_script = self.create_conversion_script(model_info).await?;
        
        tracing::info!("Running model conversion script in virtual environment...");
        
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
        // Check if virtual environment already exists and has required packages
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
                    tracing::info!("Python virtual environment already set up with required packages");
                    return Ok(());
                }
            }
        }

        tracing::info!("Setting up Python virtual environment...");

        // Create virtual environment
        fs::create_dir_all(venv_dir).await?;
        
        let output = Command::new("python3")
            .args(&["-m", "venv", venv_dir.to_str().unwrap()])
            .output()
            .map_err(|e| anyhow!("Failed to create Python virtual environment: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to create virtual environment: {}", stderr));
        }

        tracing::info!("Installing required Python packages...");

        // Install required packages
        let pip_exe = if cfg!(windows) {
            venv_dir.join("Scripts").join("pip.exe")
        } else {
            venv_dir.join("bin").join("pip")
        };

        let packages = [
            "torch",
            "transformers", 
            "onnx",
            "tokenizers",
        ];

        for package in &packages {
            tracing::info!("Installing {}...", package);
            let output = Command::new(&pip_exe)
                .args(&["install", package])
                .output()
                .map_err(|e| anyhow!("Failed to install {}: {}", package, e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("Failed to install {}: {}", package, stderr));
            }
        }

        tracing::info!("Python virtual environment setup complete");
        Ok(())
    }

    async fn create_conversion_script(&self, _model_info: &ModelInfo) -> Result<PathBuf> {
        let script_content = format!(
            r#"#!/usr/bin/env python3
"""
Runtime model conversion script for Goose security models
"""

import os
import sys
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path

def convert_model_to_onnx(model_name: str, output_dir: str):
    """Convert a Hugging Face model to ONNX format"""
    print(f"Converting {{model_name}} to ONNX...")

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    try:
        # Handle authentication for gated models
        hf_token = os.getenv('HUGGINGFACE_TOKEN') or os.getenv('HF_TOKEN')
        auth_kwargs = {{}}
        if hf_token:
            auth_kwargs['token'] = hf_token
            print(f"   Using HF token for authentication")

        # Load model and tokenizer
        print(f"   Loading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(model_name, **auth_kwargs)

        print(f"   Loading model...")
        model = AutoModelForSequenceClassification.from_pretrained(model_name, **auth_kwargs)
        model.eval()

        # Create dummy input
        dummy_text = "This is a test input for ONNX conversion"
        inputs = tokenizer(dummy_text, return_tensors="pt", padding=True, truncation=True, max_length=512)

        # Export to ONNX
        model_filename = model_name.replace("/", "_") + ".onnx"
        model_path = os.path.join(output_dir, model_filename)

        print(f"   Exporting to ONNX...")
        torch.onnx.export(
            model,
            (inputs['input_ids'], inputs['attention_mask']),
            model_path,
            export_params=True,
            opset_version=14,
            do_constant_folding=True,
            input_names=['input_ids', 'attention_mask'],
            output_names=['logits'],
            dynamic_axes={{
                'input_ids': {{0: 'batch_size', 1: 'sequence'}},
                'attention_mask': {{0: 'batch_size', 1: 'sequence'}},
                'logits': {{0: 'batch_size'}}
            }}
        )

        # Save tokenizer
        tokenizer_filename = "tokenizer.json"
        tokenizer_path = os.path.join(output_dir, tokenizer_filename)
        tokenizer.save_pretrained(output_dir, legacy_format=False)

        print(f"✅ Successfully converted {{model_name}}")
        print(f"   Model: {{model_path}}")
        print(f"   Tokenizer: {{tokenizer_path}}")
        return True

    except Exception as e:
        print(f"❌ Failed to convert {{model_name}}: {{e}}")
        if "gated repo" in str(e).lower() or "access" in str(e).lower():
            print(f"   This might be a gated model. Make sure you:")
            print(f"   1. Have access to {{model_name}} on Hugging Face")
            print(f"   2. Set your HF token: export HUGGINGFACE_TOKEN='your_token'")
            print(f"   3. Get a token from: https://huggingface.co/settings/tokens")
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

        let script_path = self.cache_dir.join("convert_model.py");
        fs::write(&script_path, script_content).await?;
        
        // Make the script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).await?;
        }

        Ok(script_path)
    }

    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(feature = "security-onnx")]
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub hf_model_name: String,
    pub onnx_filename: String,
    pub tokenizer_filename: String,
}

#[cfg(feature = "security-onnx")]
impl ModelInfo {
    pub fn deepset_deberta() -> Self {
        Self {
            hf_model_name: "deepset/deberta-v3-base-injection".to_string(),
            onnx_filename: "deepset_deberta-v3-base-injection.onnx".to_string(),
            tokenizer_filename: "tokenizer.json".to_string(),
        }
    }

    pub fn protectai_deberta() -> Self {
        Self {
            hf_model_name: "protectai/deberta-v3-base-prompt-injection-v2".to_string(),
            onnx_filename: "protectai_deberta-v3-base-prompt-injection-v2.onnx".to_string(),
            tokenizer_filename: "tokenizer.json".to_string(),
        }
    }
}

// Global downloader instance
#[cfg(feature = "security-onnx")]
static GLOBAL_DOWNLOADER: OnceCell<ModelDownloader> = OnceCell::const_new();

#[cfg(feature = "security-onnx")]
pub async fn get_global_downloader() -> Result<&'static ModelDownloader> {
    GLOBAL_DOWNLOADER
        .get_or_try_init(|| async { ModelDownloader::new() })
        .await
}

// Stub implementations when ONNX feature is not enabled
#[cfg(not(feature = "security-onnx"))]
pub struct ModelDownloader;

#[cfg(not(feature = "security-onnx"))]
pub struct ModelInfo;

#[cfg(not(feature = "security-onnx"))]
impl ModelDownloader {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}