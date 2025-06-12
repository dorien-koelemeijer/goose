# Llama Prompt Guard Setup Instructions

## Prerequisites

To use Llama Prompt Guard in the benchmarking system, you need to install Python dependencies:

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

Llama Prompt Guard 2 requires approval from Meta. To get access:

1. Go to https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
2. Click "Request access to this model"
3. Fill out the form and wait for approval
4. Once approved, authenticate with HuggingFace CLI:
   ```bash
   pip install huggingface_hub
   huggingface-cli login
   ```

## Testing the Setup

You can test if Llama Prompt Guard is working:

```bash
# Test the Python script directly
python3 -c "
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
print('Loading Llama Prompt Guard...')
tokenizer = AutoTokenizer.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M')
model = AutoModelForSequenceClassification.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M')
print('✅ Llama Prompt Guard loaded successfully!')
"
```

## Running the Benchmark

Once setup is complete, run the benchmark to compare both models:

```bash
cd /Users/dkoelemeijer/Development/goose
cargo run --bin goose -- bench run --config prompt-injection-benchmark-config.json
```

This will now test **6 configurations**:
- 3 Mistral Nemo configurations (via Ollama)
- 3 Llama Prompt Guard configurations (via Python/HuggingFace)

## Expected Results

You should see output like:

```
Testing scanner configuration: mistral-nemo-block-medium
Testing scanner configuration: mistral-nemo-block-low
Testing scanner configuration: mistral-nemo-sanitize-medium
Testing scanner configuration: llama-prompt-guard-block-medium
Testing scanner configuration: llama-prompt-guard-block-low
Testing scanner configuration: llama-prompt-guard-sanitize-medium
```

The results will include side-by-side comparison of:
- Accuracy, Precision, Recall, F1 scores
- Speed (Llama Prompt Guard should be much faster)
- Per-test-case results for detailed analysis

## Troubleshooting

### "Model not found" error
- Ensure you have access to the model on HuggingFace
- Run `huggingface-cli login` and enter your token

### "torch not found" error
- Install PyTorch: `pip install torch`
- For GPU support: `pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118`

### Python script execution fails
- Ensure `python3` is in your PATH
- Try using `python` instead of `python3` on some systems
- Check that the virtual environment is activated

### Permission denied
- The Python script should be automatically created with execute permissions
- If not, run: `chmod +x /path/to/script.py`