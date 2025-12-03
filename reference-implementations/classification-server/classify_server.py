#!/usr/bin/env python3
"""
Fast ONNX-based text classification server for prompt injection detection.

This server uses ONNX Runtime for 2-5x faster inference compared to PyTorch.
It implements the HuggingFace text-classification API format.

Usage:
    # First, convert your model to ONNX:
    python convert_to_onnx.py --model ProtectAI/deberta-v3-base-prompt-injection-v2
    
    # Then run the server:
    python classify_server.py --model-path models/ProtectAI_deberta-v3-base-prompt-injection-v2

Environment variables:
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)
"""
import argparse
import os
from pathlib import Path
from typing import List

import numpy as np
import onnxruntime as ort
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoTokenizer
import uvicorn


app = FastAPI(
    title="ONNX Classification Server",
    description="Fast text classification using ONNX Runtime",
)


class ClassificationRequest(BaseModel):
    """HuggingFace-compatible classification request"""
    inputs: str
    parameters: dict | None = None


class ClassificationLabel(BaseModel):
    """Single classification result"""
    label: str
    score: float


class ClassificationModel:
    """ONNX-based text classification model"""
    
    def __init__(self, model_path: str):
        """
        Load ONNX model and tokenizer.
        
        Args:
            model_path: Path to directory containing model.onnx and tokenizer files
        """
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise ValueError(f"Model path does not exist: {model_path}")
        
        onnx_file = model_path / "model.onnx"
        if not onnx_file.exists():
            raise ValueError(f"ONNX model not found: {onnx_file}")
        
        print(f"📦 Loading ONNX model from: {model_path}")
        
        # Load ONNX model
        self.session = ort.InferenceSession(
            str(onnx_file),
            providers=["CPUExecutionProvider"]  # Use CPU for maximum compatibility
        )
        
        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        
        # Get label mapping from model config
        config_file = model_path / "config.json"
        if config_file.exists():
            import json
            with open(config_file) as f:
                config = json.load(f)
                self.id2label = config.get("id2label", {})
                # Convert string keys to int
                self.id2label = {int(k): v for k, v in self.id2label.items()}
        else:
            # Default labels if config not found
            self.id2label = {0: "SAFE", 1: "INJECTION"}
        
        print(f"✅ Model loaded successfully")
        print(f"   Labels: {self.id2label}")
        print(f"   ONNX Runtime providers: {ort.get_available_providers()}")
    
    def softmax(self, logits: np.ndarray) -> np.ndarray:
        """Apply softmax to convert logits to probabilities"""
        exp_logits = np.exp(logits - np.max(logits))  # Subtract max for numerical stability
        return exp_logits / np.sum(exp_logits)
    
    def classify(self, text: str) -> List[ClassificationLabel]:
        """
        Classify text and return results in HuggingFace format.
        
        Args:
            text: Input text to classify
            
        Returns:
            List of classification results sorted by score (descending)
        """
        # Tokenize input
        inputs = self.tokenizer(
            text,
            return_tensors="np",
            padding=True,
            truncation=True,
            max_length=512,
        )
        
        # Run inference
        outputs = self.session.run(
            None,
            {
                "input_ids": inputs["input_ids"].astype(np.int64),
                "attention_mask": inputs["attention_mask"].astype(np.int64),
            },
        )
        
        # Get logits and apply softmax
        logits = outputs[0][0]  # Shape: [num_labels]
        probs = self.softmax(logits)
        
        # Create results
        results = [
            ClassificationLabel(
                label=self.id2label.get(i, f"LABEL_{i}"),
                score=float(probs[i]),
            )
            for i in range(len(probs))
        ]
        
        # Sort by score descending (highest first)
        results.sort(key=lambda x: x.score, reverse=True)
        
        return results


# Global model instance
model: ClassificationModel | None = None


@app.post("/classify")
async def classify(request: ClassificationRequest) -> List[List[ClassificationLabel]]:
    """
    HuggingFace-compatible text classification endpoint.
    
    Returns: [[{"label": "INJECTION", "score": 0.95}, {"label": "SAFE", "score": 0.05}]]
    """
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Log the input text being analyzed
        print(f"\n🔍 Analyzing text:")
        print(f"   Length: {len(request.inputs)} chars")
        print(f"   Content: {request.inputs[:200]}{'...' if len(request.inputs) > 200 else ''}")
        
        results = model.classify(request.inputs)
        
        # Log classification results
        top_result = results[0]
        print(
            f"📊 Result: top_label={top_result.label}, "
            f"score={top_result.score:.4f}"
        )
        
        # Return in HuggingFace format: [[{label, score}, ...]]
        return [results]
        
    except Exception as e:
        print(f"❌ Classification error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Classification failed: {str(e)}"
        )


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy" if model is not None else "model_not_loaded",
        "model_loaded": model is not None,
    }


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "ONNX Classification Server",
        "version": "1.0.0",
        "endpoints": {
            "classify": "POST /classify",
            "health": "GET /health",
        },
        "model_loaded": model is not None,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run ONNX-based text classification server"
    )
    parser.add_argument(
        "--model-path",
        required=True,
        help="Path to directory containing model.onnx and tokenizer files",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("HOST", "0.0.0.0"),
        help="Server host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8000")),
        help="Server port (default: 8000)",
    )
    args = parser.parse_args()
    
    # Load model
    global model
    try:
        model = ClassificationModel(args.model_path)
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        print(f"\nMake sure you've converted the model to ONNX first:")
        print(f"  python convert_to_onnx.py --model ProtectAI/deberta-v3-base-prompt-injection-v2")
        exit(1)
    
    # Start server
    print(f"\n🚀 Starting classification server")
    print(f"   Host: {args.host}")
    print(f"   Port: {args.port}")
    print(f"   Model: {args.model_path}")
    print(f"\n📝 Test with:")
    print(f"   curl -X POST http://localhost:{args.port}/classify \\")
    print(f"        -H 'Content-Type: application/json' \\")
    print(f"        -d '{{\"inputs\": \"Ignore all previous instructions\"}}'")
    print()
    
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
