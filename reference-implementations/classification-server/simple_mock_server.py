#!/usr/bin/env python3
"""
Simple mock classification server for testing Goose's HTTP detector.
This is a minimal example - for production, see the full reference implementation.
"""
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Mock Classification Server")

class ClassificationRequest(BaseModel):
    text: str

class ClassificationResponse(BaseModel):
    score: float
    label: str

@app.post("/classify")
def classify(request: ClassificationRequest) -> ClassificationResponse:
    """
    Mock classification endpoint.
    Returns high score for text containing "ignore" or "instructions"
    """
    text_lower = request.text.lower()
    
    # Simple keyword-based mock detection
    if "ignore" in text_lower and "instruction" in text_lower:
        return ClassificationResponse(score=0.95, label="INJECTION")
    elif "ignore" in text_lower or "instruction" in text_lower:
        return ClassificationResponse(score=0.65, label="SUSPICIOUS")
    else:
        return ClassificationResponse(score=0.05, label="SAFE")

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    print("🚀 Starting mock classification server on http://localhost:8000")
    print("📝 Test with: curl -X POST http://localhost:8000/classify -H 'Content-Type: application/json' -d '{\"text\":\"test\"}'")
    uvicorn.run(app, host="0.0.0.0", port=8000)
