"""
API Routes
"""

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, ConfigDict

from ..services.analyzer import analyze_url

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_URL_LENGTH = 2048


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: str

    @field_validator("url")
    @classmethod
    def validate_url_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("URL must not be empty.")
        if len(v) > MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds {MAX_URL_LENGTH} character limit.")
        return v


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Analyze a URL for phishing indicators.
    The URL is analyzed as a string — it is NOT visited or fetched.
    """
    try:
        result = analyze_url(request.url)
        if "error" in result:
            raise HTTPException(status_code=422, detail=result["error"])
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal analysis error.")


@router.get("/examples")
async def get_examples():
    """Return example URLs for frontend demonstration."""
    return {
        "examples": [
            {
                "label": "Safe — Google",
                "url": "https://www.google.com/search?q=cybersecurity",
                "expected": "legitimate",
            },
            {
                "label": "Safe — GitHub",
                "url": "https://github.com/features/actions",
                "expected": "legitimate",
            },
            {
                "label": "Suspicious — IP hostname",
                "url": "http://192.168.1.254/login/verify/account",
                "expected": "phishing",
            },
            {
                "label": "Suspicious — Brand impersonation",
                "url": "http://secure-paypal-login.verify-account.tk/signin",
                "expected": "phishing",
            },
            {
                "label": "Suspicious — Punycode",
                "url": "https://xn--pple-43d.com/account/verify",
                "expected": "phishing",
            },
            {
                "label": "Suspicious — Obfuscated",
                "url": "http://user@192.168.0.1:8080/payment/%76erify",
                "expected": "phishing",
            },
        ]
    }
