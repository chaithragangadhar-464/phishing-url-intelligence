"""
FastAPI Application Entry Point
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
from .api.mutate_routes import router as mutate_router
from .models.loader import load_model, is_model_loaded

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle handler."""
    logger.info("Starting Phishing URL Intelligence API...")
    success = load_model()
    if success:
        logger.info("✅ ML model loaded successfully")
    else:
        logger.warning("⚠️  ML model not found — running in heuristic-only mode")
    yield
    logger.info("API shutting down.")


app = FastAPI(
    title="Phishing URL Intelligence API",
    description=(
        "A cybersecurity API that analyzes URLs for phishing indicators "
        "using ML classification and deterministic security heuristics."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")
app.include_router(mutate_router, prefix="/api")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": is_model_loaded(),
        "version": "1.0.0",
    }


@app.get("/")
async def root():
    return {"message": "Phishing URL Intelligence API", "docs": "/docs"}
