#!/usr/bin/env python3
"""
Convert a HuggingFace text classification model to ONNX format.

This script converts PyTorch-based BERT models from HuggingFace to ONNX format
for faster inference (~2-5x speedup on CPU).

Usage:
    python convert_to_onnx.py --model ProtectAI/deberta-v3-base-prompt-injection-v2
    python convert_to_onnx.py --model your-custom-model --output-dir ./my-models
"""
import argparse
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch


def convert_to_onnx(model_name: str, output_dir: str = "models"):
    """
    Convert a HuggingFace text classification model to ONNX format.
    
    Args:
        model_name: HuggingFace model identifier (e.g., "ProtectAI/deberta-v3-base-prompt-injection-v2")
        output_dir: Directory to save the converted model
    """
    print(f"📦 Loading model: {model_name}")
    print(f"   (This may take a minute on first run - model will be cached)")
    
    # Load model and tokenizer from HuggingFace
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    
    # Set model to evaluation mode
    model.eval()
    
    # Create output directory
    output_path = Path(output_dir) / model_name.replace("/", "_")
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create dummy input for tracing
    dummy_text = "This is a test input for model conversion"
    dummy_input = tokenizer(dummy_text, return_tensors="pt")
    
    print(f"🔄 Converting to ONNX format...")
    print(f"   Input names: input_ids, attention_mask")
    print(f"   Output names: logits")
    
    # Export to ONNX
    torch.onnx.export(
        model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        output_path / "model.onnx",
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=14,
        do_constant_folding=True,
    )
    
    # Save tokenizer
    print(f"💾 Saving tokenizer...")
    tokenizer.save_pretrained(output_path)
    
    # Get model info
    onnx_path = output_path / "model.onnx"
    onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
    
    print(f"\n✅ Model converted successfully!")
    print(f"   Location: {output_path}")
    print(f"   Files:")
    print(f"     - model.onnx ({onnx_size_mb:.1f} MB)")
    print(f"     - tokenizer files")
    print(f"\n🚀 Next steps:")
    print(f"   1. Run: python classify_server.py --model-path {output_path}")
    print(f"   2. Test: curl -X POST http://localhost:8000/classify \\")
    print(f"            -H 'Content-Type: application/json' \\")
    print(f"            -d '{{\"inputs\": \"test text\"}}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert HuggingFace text classification model to ONNX format"
    )
    parser.add_argument(
        "--model",
        default="ProtectAI/deberta-v3-base-prompt-injection-v2",
        help="HuggingFace model identifier (default: ProtectAI/deberta-v3-base-prompt-injection-v2)",
    )
    parser.add_argument(
        "--output-dir",
        default="models",
        help="Output directory for converted model (default: models)",
    )
    args = parser.parse_args()
    
    try:
        convert_to_onnx(args.model, args.output_dir)
    except Exception as e:
        print(f"\n❌ Error during conversion: {e}")
        print(f"\nTroubleshooting:")
        print(f"  - Make sure the model exists on HuggingFace: https://huggingface.co/{args.model}")
        print(f"  - Check that you have installed: pip install transformers torch onnx")
        exit(1)
