# Bashcat Model Testing Setup

This guide helps you test the bashcat model for detecting dangerous shell commands in goose.

## Quick Start

### 1. Start the Classification Server

```bash
# Terminal 1: Start the bashcat model server
cd reference-implementations/classification-server

# Create/activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start server with bashcat model
python classify_server.py --model-path ../../bashcat_distilbert2 --port 8001
```

You should see:
```
📦 Loading ONNX model from: ../../bashcat_distilbert2
✅ Model loaded successfully
🚀 Starting classification server
   Host: 0.0.0.0
   Port: 8001
```

### 2. Configure Goose
Add these to config file

```
SECURITY_PROMPT_ENABLED: true
SECURITY_PROMPT_THRESHOLD: 0.7
SECURITY_PROMPT_BERT_ENABLED: true
SECURITY_TOOL_CALL_BERT_ENDPOINT: http://localhost:8001/classify
```

### 3. Build and Run Goose

```bash
just run-ui
```
