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
        # Load model and tokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        model.eval()
        
        # Create dummy input
        dummy_text = "This is a test input for ONNX conversion"
        inputs = tokenizer(dummy_text, return_tensors="pt", padding=True, truncation=True, max_length=512)
        
        # Export to ONNX
        model_filename = model_name.replace("/", "_") + ".onnx"
        model_path = os.path.join(output_dir, model_filename)
        
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
        
        # Save tokenizer
        tokenizer_path = os.path.join(output_dir, model_name.replace("/", "_") + "_tokenizer.json")
        tokenizer.save_pretrained(output_dir, legacy_format=False)
        
        print(f"✅ Successfully converted {model_name}")
        print(f"   Model: {model_path}")
        print(f"   Tokenizer: {tokenizer_path}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to convert {model_name}: {e}")
        return False

def main():
    models_to_convert = [
        "deepset/deberta-v3-base-injection",
        "protectai/deberta-v3-base-prompt-injection-v2",
        # Add more models as needed
    ]
    
    print("🚀 Starting ONNX model conversion...")
    
    successful = 0
    for model_name in models_to_convert:
        if convert_model_to_onnx(model_name):
            successful += 1
    
    print(f"\n✨ Conversion complete: {successful}/{len(models_to_convert)} models converted successfully")

if __name__ == "__main__":
    main()
