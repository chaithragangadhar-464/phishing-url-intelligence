"""
Production startup script for Railway/Render.
Trains the model if not present, then starts the FastAPI server.
This runs as the START command, not build command.
"""
import os
import sys
import subprocess
from pathlib import Path

PORT = os.environ.get("PORT", "8000")
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_FILE = MODELS_DIR / "phishing_model.joblib"


def train_model():
    print("=" * 50)
    print("Model not found. Training now...")
    print("=" * 50)
    result = subprocess.run(
        [sys.executable, "train_model.py"],
        capture_output=False,
        text=True
    )
    if result.returncode != 0:
        print("WARNING: Training failed — starting in heuristic-only mode")
    else:
        print("Model training complete!")


if __name__ == "__main__":
    # Train model if missing
    if not MODEL_FILE.exists():
        train_model()
    else:
        print(f"Model found at {MODEL_FILE}, skipping training.")

    # Start the FastAPI server
    print(f"Starting server on port {PORT}...")
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(PORT),
        log_level="info"
    )
