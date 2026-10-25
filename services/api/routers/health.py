from fastapi import APIRouter, status, Response, Request
from pydantic import BaseModel
from typing import Optional
from database import check_db_connection
from config import settings

router = APIRouter(tags=["Health"])

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    environment: str
    request_id: Optional[str] = None
    trace_id: Optional[str] = None

@router.get("/health", response_model=HealthResponse)
def root_health(request: Request, response: Response):
    db_ok = check_db_connection()
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        db_status = "unhealthy"
    else:
        db_status = "connected"
        
    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        service="aegis-api",
        version=settings.AEGIS_VERSION,
        database=db_status,
        environment=settings.AEGIS_ENV,
        request_id=request.headers.get("x-request-id"),
        trace_id=request.headers.get("x-trace-id")
    )

@router.get("/api/v1/health", response_model=HealthResponse)
def v1_health(request: Request, response: Response):
    return root_health(request, response)
