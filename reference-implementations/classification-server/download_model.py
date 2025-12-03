#!/usr/bin/env python3
"""
Smart model downloader for text classification models.

This script intelligently downloads models from HuggingFace:
1. Checks if pre-converted ONNX models exist in the repo
2. If yes: downloads ONNX files directly (faster, no conversion needed)
3. If no: downloads PyTorch model and converts to ONNX

Usage:
    python download_model.py --model ProtectAI/deberta-v3-base-prompt-injection-v2
    python download_model.py --model deepset/deberta-v3-base-injection --output-dir ./models
"""

import argparse
import os
import sys
from pathlib import Path

# Disable tokenizers parallelism to avoid fork warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"

try:
    from huggingface_hub import HfApi, hf_hub_download, snapshot_download
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    import onnx
    import numpy as np
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("\nPlease install required packages:")
    print("  pip install transformers torch onnx onnxruntime huggingface_hub numpy")
    sys.exit(1)


def sanitize_model_name(model_name: str) -> str:
    """Convert model name to safe directory name."""
    return model_name.replace("/", "_").replace("-", "-")


def check_for_onnx_in_repo(model_name: str) -> bool:
    """Check if the HuggingFace repo contains pre-converted ONNX files."""
    try:
        api = HfApi()
        files = api.list_repo_files(repo_id=model_name, repo_type="model")
        
        # Check for ONNX files in common locations
        onnx_patterns = [
            "model.onnx",
            "onnx/model.onnx",
            "onnx/model_quantized.onnx",
        ]
        
        for pattern in onnx_patterns:
            if pattern in files:
                print(f"✓ Found pre-converted ONNX model: {pattern}")
                return True
        
        # Check if there's an onnx/ directory with any .onnx files
        onnx_files = [f for f in files if f.endswith('.onnx')]
        if onnx_files:
            print(f"✓ Found ONNX files: {', '.join(onnx_files)}")
            return True
            
        return False
    except Exception as e:
        print(f"Warning: Could not check repo for ONNX files: {e}")
        return False


def download_onnx_model(model_name: str, output_dir: Path) -> Path:
    """Download pre-converted ONNX model from HuggingFace."""
    print(f"\n📥 Downloading pre-converted ONNX model from {model_name}...")
    
    model_dir = output_dir / sanitize_model_name(model_name)
    model_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Download the entire repo (or specific files if we know the structure)
        # This will get tokenizer files + ONNX model
        snapshot_download(
            repo_id=model_name,
            local_dir=model_dir,
            allow_patterns=["*.onnx", "*.json", "*.txt", "tokenizer*", "config.json", "special_tokens_map.json", "vocab.txt"],
            ignore_patterns=["*.bin", "*.safetensors", "pytorch_model.bin"],
        )
        
        # Find the ONNX file
        onnx_files = list(model_dir.rglob("*.onnx"))
        if not onnx_files:
            raise FileNotFoundError("No ONNX files found after download")
        
        # If ONNX file is in a subdirectory (e.g., onnx/model.onnx), move it to root
        onnx_file = onnx_files[0]
        if onnx_file.parent != model_dir:
            target_path = model_dir / "model.onnx"
            print(f"Moving {onnx_file} to {target_path}")
            onnx_file.rename(target_path)
            onnx_file = target_path
        
        print(f"✓ Downloaded ONNX model to: {model_dir}")
        print(f"  ONNX file: {onnx_file.name}")
        
        return model_dir
        
    except Exception as e:
        print(f"✗ Failed to download ONNX model: {e}")
        raise


def convert_pytorch_to_onnx(model_name: str, output_dir: Path) -> Path:
    """Download PyTorch model and convert to ONNX."""
    print(f"\n🔄 No pre-converted ONNX found. Converting PyTorch model to ONNX...")
    
    model_dir = output_dir / sanitize_model_name(model_name)
    model_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📥 Downloading model and tokenizer from {model_name}...")
    
    try:
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        model.eval()
        
        # Save tokenizer
        tokenizer.save_pretrained(model_dir)
        print(f"✓ Saved tokenizer to {model_dir}")
        
        # Create dummy input for ONNX export
        dummy_text = "This is a sample text for model export."
        inputs = tokenizer(
            dummy_text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        )
        
        # Export to ONNX
        onnx_path = model_dir / "model.onnx"
        print(f"🔄 Converting to ONNX format...")
        
        # Use legacy exporter to avoid decomposition hang
        with torch.no_grad():
            torch.onnx.export(
                model,
                (inputs["input_ids"], inputs["attention_mask"]),
                onnx_path,
                input_names=["input_ids", "attention_mask"],
                output_names=["logits"],
                dynamic_axes={
                    "input_ids": {0: "batch_size", 1: "sequence_length"},
                    "attention_mask": {0: "batch_size", 1: "sequence_length"},
                    "logits": {0: "batch_size"}
                },
                opset_version=14,
                do_constant_folding=True,
                export_params=True,
                # Use legacy exporter (dynamo=False) to avoid hang
                dynamo=False,
            )
        
        # Verify the ONNX model
        print(f"✓ Verifying ONNX model...")
        onnx_model = onnx.load(onnx_path)
        onnx.checker.check_model(onnx_model)
        
        print(f"✓ Successfully converted model to ONNX")
        print(f"  Output directory: {model_dir}")
        print(f"  ONNX model: {onnx_path}")
        
        # Test the ONNX model
        print(f"🧪 Testing ONNX model...")
        import onnxruntime as ort
        
        session = ort.InferenceSession(str(onnx_path))
        onnx_inputs = {
            "input_ids": inputs["input_ids"].numpy(),
            "attention_mask": inputs["attention_mask"].numpy()
        }
        outputs = session.run(None, onnx_inputs)
        print(f"✓ ONNX model test successful (output shape: {outputs[0].shape})")
        
        return model_dir
        
    except Exception as e:
        print(f"✗ Failed to convert model: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Smart model downloader - downloads ONNX if available, otherwise converts from PyTorch"
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="HuggingFace model name (e.g., ProtectAI/deberta-v3-base-prompt-injection-v2)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./models",
        help="Output directory for downloaded/converted models (default: ./models)"
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"🔍 Checking model: {args.model}")
    
    # Check if ONNX model exists in repo
    has_onnx = check_for_onnx_in_repo(args.model)
    
    try:
        if has_onnx:
            model_dir = download_onnx_model(args.model, output_dir)
        else:
            print(f"ℹ️  No pre-converted ONNX found, will convert from PyTorch")
            model_dir = convert_pytorch_to_onnx(args.model, output_dir)
        
        print(f"\n✅ Model ready!")
        print(f"\nTo run the classification server:")
        print(f"  python classify_server.py --model-path {model_dir}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
