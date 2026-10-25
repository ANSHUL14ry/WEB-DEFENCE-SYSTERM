import logging
from fastapi import FastAPI, Request
from typing import Dict, Any
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ORIGIN] [%(levelname)s]: %(message)s"
)
logger = logging.getLogger("aegis.origin")

app = FastAPI(
    title="AEGIS Protected Origin Application (Temporary)",
    description="Simulated origin application workload sitting safely behind AEGIS Gateway",
    version="0.1.0"
)

@app.middleware("http")
async def log_incoming_requests(request: Request, call_next):
    req_id = request.headers.get("x-request-id", "none")
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Incoming request: {request.method} {request.url.path} | Client: {client_ip} | X-Request-ID: {req_id}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code} for {request.method} {request.url.path} | X-Request-ID: {req_id}")
    return response

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "temporary-origin",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/")
def read_root(request: Request) -> Dict[str, Any]:
    return {
        "message": "Welcome to Origin Application (Protected by AEGIS Ω)",
        "service": "origin",
        "protection": "AEGIS Ω Reverse Proxy Active",
        "request_id": request.headers.get("x-request-id", "Not Provided (Direct Connection)"),
        "client_host": request.client.host if request.client else "unknown",
        "headers_received": dict(request.headers),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/products")
def list_products(request: Request):
    return {
        "service": "origin",
        "request_id": request.headers.get("x-request-id", "none"),
        "products": [
            {"id": 1, "name": "Secure Gateway License", "category": "defense", "price": 499.0},
            {"id": 2, "name": "AgentShield Heuristic Engine", "category": "ai-defense", "price": 899.0},
            {"id": 3, "name": "Adaptive Honeypot Decoy Module", "category": "deception", "price": 650.0}
        ]
    }
