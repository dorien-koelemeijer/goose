#!/usr/bin/env python3
"""
Convert the local bashcat model to ONNX format.
"""
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

model_path = Path("../../bashcat_distilbert2")

print(f"📦 Loading bashcat model from: {model_path}")

# Load model and tokenizer from local directory
tokenizer = AutoTokenizer.from_pretrained(str(model_path))
model = AutoModelForSequenceClassification.from_pretrained(str(model_path))

# Set model to evaluation mode
model.eval()

print(f"🔄 Converting to ONNX format...")

# Create dummy input for tracing
dummy_text = "ls -la"
dummy_input = tokenizer(dummy_text, return_tensors="pt")

# Export to ONNX
onnx_path = model_path / "model.onnx"
torch.onnx.export(
    model,
    (dummy_input["input_ids"], dummy_input["attention_mask"]),
    str(onnx_path),
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

onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)

print(f"\n✅ Conversion complete!")
print(f"   ONNX model: {onnx_path} ({onnx_size_mb:.1f} MB)")
print(f"\n🚀 Now you can run:")
print(f"   cd reference-implementations/classification-server")
print(f"   python classify_server.py --model-path ../../bashcat_distilbert2 --port 8001")
