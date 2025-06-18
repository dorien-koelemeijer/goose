#!/usr/bin/env python3
"""
Quick test script to verify the new models work
"""

import subprocess
import json
import sys

def test_deepset_model():
    """Test if the Deepset DeBERTa model can be loaded"""
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        
        print("Testing Deepset DeBERTa model...")
        model_name = "deepset/deberta-v3-base-injection"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
        # Test with a simple input
        test_text = "Hello, how are you?"
        inputs = tokenizer(test_text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)
            confidence = torch.max(probabilities).item()
        
        print(f"✅ Deepset DeBERTa model loaded successfully! Confidence: {confidence:.3f}")
        return True
        
    except Exception as e:
        print(f"❌ Deepset DeBERTa model failed: {e}")
        return False

def test_toxic_bert_model():
    """Test if the ToxicBERT model can be loaded"""
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        
        print("Testing ToxicBERT model...")
        model_name = "unitary/toxic-bert"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
        # Test with a simple input
        test_text = "Hello, how are you?"
        inputs = tokenizer(test_text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)
            confidence = torch.max(probabilities).item()
        
        print(f"✅ ToxicBERT model loaded successfully! Confidence: {confidence:.3f}")
        return True
        
    except Exception as e:
        print(f"❌ ToxicBERT model failed: {e}")
        return False

def main():
    print("🧪 Testing new prompt injection detection models...")
    print()
    
    # Check if required packages are installed
    try:
        import torch
        import transformers
        print(f"✅ PyTorch version: {torch.__version__}")
        print(f"✅ Transformers version: {transformers.__version__}")
        print()
    except ImportError as e:
        print(f"❌ Missing required packages: {e}")
        print("Please install: pip install torch transformers")
        return False
    
    success_count = 0
    total_tests = 2
    
    # Test models
    if test_deepset_model():
        success_count += 1
    print()
    
    if test_toxic_bert_model():
        success_count += 1
    print()
    
    print(f"📊 Test Results: {success_count}/{total_tests} models loaded successfully")
    
    if success_count == total_tests:
        print("🎉 All models are ready for testing!")
        return True
    else:
        print("⚠️  Some models failed to load. Check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)