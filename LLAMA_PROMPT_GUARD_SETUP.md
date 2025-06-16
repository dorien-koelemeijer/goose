# Llama Prompt Guard Setup Instructions

## Prerequisites

To use Llama Prompt Guard in the benchmarking system, install Python dependencies:

```bash
# Create a virtual environment (recommended)
python3 -m venv llama-guard-env
source llama-guard-env/bin/activate  # On macOS/Linux
# or
llama-guard-env\Scripts\activate     # On Windows

# Install required packages
pip install torch transformers

# Note: The model requires authentication with Hugging Face
# You may need to:
# 1. Create a Hugging Face account
# 2. Request access to meta-llama/Llama-Prompt-Guard-2-86M
# 3. Login: huggingface-cli login
```

## Model Access

The system uses ProtectAI's DeBERTa model which is publicly available:
- Model: `protectai/deberta-v3-base-prompt-injection-v2`
- No authentication or approval required
- Automatically downloaded on first use

## Testing the Setup

Test if the prompt injection detection model is working:

```bash
# Test the Python script directly
python3 -c "
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
print('Loading ProtectAI prompt injection detection model...')
tokenizer = AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
model = AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
print('✅ Prompt injection detection model loaded successfully!')
"
```

## Running the Benchmark

Once setup is complete, run the benchmark to compare both models:

```bash
cd /Users/dkoelemeijer/Development/goose
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

This will now test **9 configurations**:
- 3 Mistral Nemo configurations (via Ollama)
- 3 ProtectAI DeBERTa configurations (via Python/HuggingFace)
- 3 Llama Prompt Guard 2 configurations (via Python/HuggingFace)

## Expected Results

Expected output:

```
Testing scanner configuration: mistral-nemo-block-medium
Testing scanner configuration: mistral-nemo-block-low
Testing scanner configuration: mistral-nemo-sanitize-medium
Testing scanner configuration: prompt-injection-model-block-medium
Testing scanner configuration: prompt-injection-model-block-low
Testing scanner configuration: prompt-injection-model-sanitize-medium
Testing scanner configuration: llama-prompt-guard2-block-medium
Testing scanner configuration: llama-prompt-guard2-block-low
Testing scanner configuration: llama-prompt-guard2-sanitize-medium
```

The results will include side-by-side comparison of:
- Accuracy, Precision, Recall, F1 scores
- Speed (specialized models should be much faster than Mistral Nemo)
- Per-test-case results for detailed analysis

## Troubleshooting

### "torch not found" error
- Install PyTorch: `pip install torch`
- For GPU support: `pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118`

### Python script execution fails
- Ensure `python3` is in the PATH
- Try using `python` instead of `python3` on some systems
- Check that the virtual environment is activated

