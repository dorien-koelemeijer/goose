#!/usr/bin/env python3
"""
Convert prompt injection detection models to ONNX format for fast Rust inference
"""

import os
import sys
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path

def convert_model_to_onnx(model_name: str, output_dir: str = "onnx_models"):
    """Convert a Hugging Face model to ONNX format"""
    print(f"Converting {model_name} to ONNX...")

    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)

    try:
        # Handle authentication for gated models
        hf_token = os.getenv('HUGGINGFACE_TOKEN') or os.getenv('HF_TOKEN')
        auth_kwargs = {}
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
            opset_version=14,  # Use newer opset version
            do_constant_folding=True,
            input_names=['input_ids', 'attention_mask'],
            output_names=['logits'],
            dynamic_axes={
                'input_ids': {0: 'batch_size', 1: 'sequence'},
                'attention_mask': {0: 'batch_size', 1: 'sequence'},
                'logits': {0: 'batch_size'}
            }
        )

        # Save tokenizer (create unique directory for each model's tokenizer)
        tokenizer_filename = model_name.replace("/", "_") + "_tokenizer"
        tokenizer_dir = os.path.join(output_dir, tokenizer_filename)
        tokenizer.save_pretrained(tokenizer_dir, legacy_format=False)

        print(f"✅ Successfully converted {model_name}")
        print(f"   Model: {model_path}")
        print(f"   Tokenizer: {tokenizer_dir}")
        return True

    except Exception as e:
        print(f"❌ Failed to convert {model_name}: {e}")
        if "gated repo" in str(e).lower() or "access" in str(e).lower():
            print(f"   This might be a gated model. Make sure you:")
            print(f"   1. Have access to {model_name} on Hugging Face")
            print(f"   2. Set your HF token: export HUGGINGFACE_TOKEN='your_token'")
            print(f"   3. Get a token from: https://huggingface.co/settings/tokens")
        return False

def main():
    models_to_convert = [
        "deepset/deberta-v3-base-injection",
        "protectai/deberta-v3-base-prompt-injection-v2"
        # Add more models as needed
    ]

    print("🚀 Starting ONNX model conversion...")

    # Check for Hugging Face token
    hf_token = os.getenv('HUGGINGFACE_TOKEN') or os.getenv('HF_TOKEN')
    if not hf_token:
        print("⚠️  No Hugging Face token found in environment variables")
        print("   For gated models like Llama Guard 2, you need to set:")
        print("   export HUGGINGFACE_TOKEN='your_token_here'")
        print("   or")
        print("   export HF_TOKEN='your_token_here'")
        print("   You can get a token from: https://huggingface.co/settings/tokens")
        print("   Continuing anyway - public models will still work...")
        print()
    else:
        print(f"✅ Found Hugging Face token: {hf_token[:8]}...")
        print()

    successful = 0
    for model_name in models_to_convert:
        if convert_model_to_onnx(model_name):
            successful += 1

    print(f"\n✨ Conversion complete: {successful}/{len(models_to_convert)} models converted successfully")

if __name__ == "__main__":
    main()