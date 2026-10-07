#!/bin/bash
# Build script for Render deployment
# Runs training pipeline to generate the model during build

echo "=== Installing Python dependencies ==="
pip install -r requirements.txt

echo "=== Running ML training pipeline ==="
cd ..
python ml/training/train.py

echo "=== Verifying model exists ==="
ls -la models/

echo "=== Build complete ==="
