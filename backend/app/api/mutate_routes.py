"""
API Router for Mutation Lab Endpoint
"""

import time
import logging
from typing import Dict
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.services.mutator import generate_mutations

logger = logging.getLogger(__name__)

router = APIRouter()

# Simple in-memory rate limiter per IP for /api/mutate
MUTATE_RATE_LIMIT = 10  # 10 requests
MUTATE_WINDOW = 60      # 60 seconds
_ip_request_history: Dict[str, list] = {}


def check_mutate_rate_limit(request: Request):
    """Simple in-memory rate limiter for /api/mutate."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"

    now = time.time()
    history = _ip_request_history.get(client_ip, [])
    # Filter out requests older than window
    history = [t for t in history if now - t < MUTATE_WINDOW]
    
    if len(history) >= MUTATE_RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: maximum 10 mutation requests per minute per IP."
        )
        
    history.append(now)
    _ip_request_history[client_ip] = history


class MutateRequest(BaseModel):
    url: str = Field(..., description="URL string to generate mutations for", example="https://paypal-login.example.com")


@router.post("/mutate")
async def mutate_url_endpoint(request_data: MutateRequest, request: Request):
    """
    Generate red-team mutations of a URL and re-score each variant with the analyzer.
    """
    # 1. Enforce rate limit
    check_mutate_rate_limit(request)
    
    # 2. Process mutation request
    try:
        result = generate_mutations(request_data.url)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing mutation request: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error processing URL mutations."
        )
