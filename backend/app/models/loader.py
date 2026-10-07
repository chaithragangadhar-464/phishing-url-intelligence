"""
ML Model Loader
Loads the trained model and preprocessing artifacts from disk.
Provides thread-safe singleton access to the model.
"""

import joblib
import os
import logging
from pathlib import Path
from typing import Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

_model = None
_feature_names = None
_model_loaded = False

# Check backend/models/ first (Railway deployment), then project-root models/ (local dev)
_BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
_PROJECT_ROOT = _BACKEND_ROOT.parent

def _find_model_path(filename: str) -> Path:
    """Find model file in backend/models/ or project-root models/."""
    candidates = [
        _BACKEND_ROOT / "models" / filename,
        _PROJECT_ROOT / "models" / filename,
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]  # Return first as default (for error messages)

MODEL_PATH = _find_model_path("phishing_model.joblib")
META_PATH  = _find_model_path("model_meta.joblib")


def load_model() -> bool:
    """Load the trained model from disk. Returns True on success."""
    global _model, _feature_names, _model_loaded
    try:
        if not MODEL_PATH.exists():
            logger.error(f"Model file not found at {MODEL_PATH}")
            return False
        _model = joblib.load(MODEL_PATH)
        if META_PATH.exists():
            meta = joblib.load(META_PATH)
            _feature_names = meta.get("feature_names", [])
        _model_loaded = True
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


def is_model_loaded() -> bool:
    return _model_loaded


def predict(feature_vector: list) -> Tuple[int, float]:
    """
    Run inference.
    Returns (label, probability) where label is 1=phishing, 0=legitimate.
    """
    if not _model_loaded:
        raise RuntimeError("Model is not loaded")
    X = np.array(feature_vector).reshape(1, -1)
    label = int(_model.predict(X)[0])
    if hasattr(_model, "predict_proba"):
        proba = float(_model.predict_proba(X)[0][1])  # P(phishing)
    else:
        proba = float(label)
    return label, proba


def get_feature_importances() -> Optional[dict]:
    """Return feature importances if the model supports them."""
    if not _model_loaded:
        return None
    try:
        importances = _model.feature_importances_
        if _feature_names and len(_feature_names) == len(importances):
            return dict(zip(_feature_names, importances.tolist()))
        return {"importances": importances.tolist()}
    except AttributeError:
        return None
