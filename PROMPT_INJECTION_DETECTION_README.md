# Prompt Injection Detection System

This system implements multi-model prompt injection detection for Goose, with comprehensive benchmarking to evaluate model effectiveness.

## 🎯 Overview

The system tests **3 different models** across **9 configurations** to find the best approach for detecting prompt injection attacks:

1. **Mistral Nemo** (via Ollama) - General purpose LLM with custom security prompting
2. **ProtectAI DeBERTa** (via Python) - Specialized prompt injection detection model (`protectai/deberta-v3-base-prompt-injection-v2`)
3. **Llama Prompt Guard 2** (via Python) - Meta's latest security-focused model (`meta-llama/Llama-Prompt-Guard-2-86M`)

**Note**: The `LlamaPromptGuard` scanner type actually uses ProtectAI's DeBERTa model, not a Llama model. The naming is historical.

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python dependencies for specialized models
pip install torch transformers

# For Mistral Nemo: Install and start Ollama
# Download from: https://ollama.ai/
ollama pull mistral-nemo
ollama serve  # Start the server
```

### Run the Benchmark

```bash
# Run comprehensive evaluation of all models
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

**Important Note**: The `prompt-injection-benchmark-config.json` file specifies `"provider": "ollama"` and `"name": "mistral-nemo"`, but this is just used by the benchmark framework for organizing output directories. The actual evaluation tests **all 3 models** (Mistral Nemo, ProtectAI DeBERTa, and Llama Prompt Guard 2) regardless of what's in the config file.

## 📊 What Gets Tested

The benchmark evaluates each model on:
- **Real prompt injection attacks** from HuggingFace datasets
- **Accuracy, Precision, Recall, F1 scores**
- **Scan speed** (specialized models vs LLM)
- **Different action policies**: Block, Sanitize, Warn, LogOnly
- **Various threat thresholds**: Low, Medium, High, Critical

## 🔧 Model Setup Details

### 1. Mistral Nemo (LLM-based)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the model
ollama pull mistral-nemo

# Start server (runs on localhost:11434)
ollama serve
```

**Pros**: Provides explanations and can sanitize content  
**Cons**: Slower, requires running Ollama server

### 2. ProtectAI DeBERTa (Specialized)
**Scanner Type**: `LlamaPromptGuard` (confusing naming - this is NOT a Llama model)

```bash
# Install dependencies
pip install torch transformers

# Test the model
python3 -c "
from transformers import AutoTokenizer, AutoModelForSequenceClassification
tokenizer = AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
model = AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
print('✅ ProtectAI DeBERTa model ready!')
"
```

**Pros**: Fast, no authentication required, specialized for prompt injection  
**Cons**: Binary classification only (safe/unsafe)

### 3. Llama Prompt Guard 2 (Meta's Latest)
**Scanner Type**: `LlamaPromptGuard2`

```bash
# Install dependencies  
pip install torch transformers

# Get Hugging Face access (may require approval)
# 1. Go to: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
# 2. Click "Request access to this model"
# 3. Wait for approval (usually 1-2 days)
# 4. Login: huggingface-cli login

# Test access
python3 test_llama_prompt_guard2.py
```

**Pros**: Latest from Meta, designed specifically for prompt injection  
**Cons**: Requires Hugging Face approval, newer/less tested

## 📈 Understanding Results

After running the benchmark, there should be metrics like:

```
mistral-nemo-block-medium_accuracy: 0.85
mistral-nemo-block-medium_precision: 0.82  
mistral-nemo-block-medium_recall: 0.88
mistral-nemo-block-medium_f1_score: 0.85
mistral-nemo-block-medium_avg_scan_time: 2.3

prompt-injection-model-block-medium_accuracy: 0.91
prompt-injection-model-block-medium_precision: 0.89
prompt-injection-model-block-medium_recall: 0.93
prompt-injection-model-block-medium_f1_score: 0.91
prompt-injection-model-block-medium_avg_scan_time: 0.1
```

**Key Metrics**:
- **Accuracy**: Overall correctness (higher is better)
- **Precision**: How many flagged items were actually threats (fewer false positives)
- **Recall**: How many actual threats were caught (fewer false negatives)  
- **F1 Score**: Balanced measure of precision and recall
- **Scan Time**: Speed in seconds (lower is better)

## 🔧 Configuration

### Benchmark Config File

The `prompt-injection-benchmark-config.json` contains settings for the benchmark framework:

```json
{
  "models": [
    {
      "provider": "ollama",           // Valid provider (ollama, openai, anthropic, etc.)
      "name": "mistral-nemo",         // Model name (used for directory structure only)
      "parallel_safe": false,
      "tool_shim": null
    }
  ],
  "evals": [
    {
      "selector": "security:prompt_injection_detection",  // Points to your evaluation
      "post_process_cmd": null,
      "parallel_safe": false
    }
  ],
  "output_dir": "/tmp/goose-security-benchmark"  // Where results are saved
}
```

**Key Points**:
- The `models` section is required by the benchmark framework but **doesn't control which models are tested**
- `prompt_injection_detection.rs` hardcodes which models to test internally
- The provider/model specified here is only used for organizing output directories
- Valid providers: `ollama`, `openai`, `anthropic`, `azure_openai`, `aws_bedrock`, `databricks`, `groq`, `openrouter`, `gcp_vertex_ai`, `google`, `venice`, `snowflake`, `github_copilot`

### Security Scanner Configuration

Edit the security config to control individual model behavior:

```rust
let security_config = SecurityConfig {
    enabled: true,
    scanner_type: ScannerType::LlamaPromptGuard2, // or MistralNemo, LlamaPromptGuard
    action_policy: ActionPolicy::Block,           // or Sanitize, Warn, LogOnly  
    scan_threshold: ThreatThreshold::Medium,      // or Low, High, Critical
    ollama_endpoint: "http://localhost:11434".to_string(), // Only for Mistral
};
```

## 🔍 Testing Individual Models

### Test Mistral Nemo
```bash
# Make sure Ollama is running
ollama serve

# Test by running the full benchmark (Mistral Nemo is included)
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

### Test ProtectAI Model
```bash
# Test Python integration first
python3 -c "
from transformers import AutoTokenizer, AutoModelForSequenceClassification
tokenizer = AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
model = AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
print('✅ ProtectAI DeBERTa model ready!')
"

# Test by running the full benchmark (ProtectAI model is included)
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

### Test Llama Prompt Guard 2
```bash
# Test access first
python3 test_llama_prompt_guard2.py

# Test by running the full benchmark (Llama Guard 2 is included)
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

