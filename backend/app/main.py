"""
FastAPI Application Entry Point
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
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
import os
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = (
    [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    if allowed_origins_env
    else []
)
# Always allow localhost for development
allowed_origins += [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")


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
