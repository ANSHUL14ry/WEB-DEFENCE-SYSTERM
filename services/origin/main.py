import logging
import asyncio
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List, Optional
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ORIGIN] [%(levelname)s]: %(message)s"
)
logger = logging.getLogger("aegis.origin")

app = FastAPI(
    title="AEGIS Protected Origin Application",
    description="Simulated origin application workload sitting safely behind AEGIS Gateway and Coraza WAF",
    version="0.3.0"
)

# Enable CORS on origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory audit tracking for origin protection verification
REQUEST_LOG: List[Dict[str, Any]] = []

# Mock product state
PRODUCTS = [
    {"id": 1, "name": "Secure Gateway License", "category": "defense", "price": 499.0},
    {"id": 2, "name": "AgentShield Heuristic Engine", "category": "ai-defense", "price": 899.0},
    {"id": 3, "name": "Adaptive Honeypot Decoy Module", "category": "deception", "price": 650.0}
]

@app.middleware("http")
async def log_and_track_incoming_requests(request: Request, call_next):
    req_id = request.headers.get("x-request-id", "none")
    trace_id = request.headers.get("x-trace-id", "none")
    client_ip = request.client.host if request.client else "unknown"
    
    # Track request internally for verification
    if not request.url.path.startswith("/health") and not request.url.path.startswith("/stats"):
        REQUEST_LOG.append({
            "request_id": req_id,
            "trace_id": trace_id,
            "method": request.method,
            "path": request.url.path,
            "client_ip": client_ip,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    
    logger.info(f"Incoming: {request.method} {request.url.path} | Client: {client_ip} | X-Request-ID: {req_id} | X-Trace-ID: {trace_id}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code} for {request.method} {request.url.path} | X-Request-ID: {req_id}")
    return response

@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {
        "status": "healthy",
        "service": "temporary-origin",
        "version": "0.3.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.api_route("/stats", methods=["GET", "HEAD"])
def get_origin_stats():
    """Telemetry endpoint allowing automated tests and AEGIS verification engine to inspect origin reach."""
    return {
        "service": "origin",
        "total_requests_received": len(REQUEST_LOG),
        "recent_requests": REQUEST_LOG[-25:]
    }

@app.post("/reset-stats")
def reset_origin_stats():
    REQUEST_LOG.clear()
    return {"status": "reset", "total_requests_received": 0}

@app.api_route("/", methods=["GET", "HEAD", "OPTIONS"])
def read_root(request: Request) -> Dict[str, Any]:
    return {
        "message": "Welcome to Origin Application (Protected by AEGIS Ω)",
        "service": "origin",
        "protection": "AEGIS Ω Reverse Proxy + Coraza WAF Active",
        "request_id": request.headers.get("x-request-id", "Not Provided (Direct Connection)"),
        "trace_id": request.headers.get("x-trace-id", "none"),
        "client_host": request.client.host if request.client else "unknown",
        "headers_received": dict(request.headers),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.api_route("/products", methods=["GET", "HEAD", "OPTIONS"])
def list_products(request: Request):
    return {
        "service": "origin",
        "request_id": request.headers.get("x-request-id", "none"),
        "trace_id": request.headers.get("x-trace-id", "none"),
        "count": len(PRODUCTS),
        "products": PRODUCTS
    }

@app.post("/echo")
async def echo_payload(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "service": "origin",
        "status": "received",
        "method": "POST",
        "request_id": request.headers.get("x-request-id", "none"),
        "trace_id": request.headers.get("x-trace-id", "none"),
        "received_payload": body,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.put("/products/{product_id}")
async def update_product(product_id: int, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "service": "origin",
        "status": "updated",
        "method": "PUT",
        "product_id": product_id,
        "updated_fields": body,
        "request_id": request.headers.get("x-request-id", "none"),
        "trace_id": request.headers.get("x-trace-id", "none")
    }

@app.delete("/products/{product_id}")
def delete_product(product_id: int, request: Request):
    return {
        "service": "origin",
        "status": "deleted",
        "method": "DELETE",
        "product_id": product_id,
        "request_id": request.headers.get("x-request-id", "none"),
        "trace_id": request.headers.get("x-trace-id", "none")
    }

@app.get("/slow")
async def slow_endpoint(delay: float = 1.0):
    await asyncio.sleep(min(delay, 15.0))
    return {
        "service": "origin",
        "status": "completed",
        "simulated_delay_seconds": delay
    }
