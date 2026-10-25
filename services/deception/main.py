"""
AEGIS Ω — Isolated Decoy Environment Main Application
Lightweight synthetic application service running in an isolated Docker network.
Never connects to production database or real origin application.
"""

import logging
import time
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from config import decoy_settings
from routes import common, login, admin, api

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("aegis.decoy")

app = FastAPI(
    title=decoy_settings.SERVICE_NAME,
    version=decoy_settings.VERSION,
    docs_url=None, # Disable Swagger UI to avoid revealing API documentation
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enforce maximum body size protection
@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > decoy_settings.MAX_BODY_SIZE_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": "Payload Too Large", "message": "Request body exceeds maximum permitted limit."}
        )
    return await call_next(request)

# Structured interaction logging
@app.middleware("http")
async def interaction_logging_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    logger.info(
        f"Decoy Hit | {request.method} {request.url.path} | "
        f"Status: {response.status_code} | Duration: {duration_ms}ms"
    )
    return response

# Register synthetic decoy routes
app.include_router(common.router)
app.include_router(login.router)
app.include_router(admin.router)
app.include_router(api.router)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Realistic 404 error response without disclosing the decoy status."""
    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "error_code": "RESOURCE_NOT_FOUND",
            "message": f"The requested path '{request.url.path}' was not found on this server."
        }
    )
