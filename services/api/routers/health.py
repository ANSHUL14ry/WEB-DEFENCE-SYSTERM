from fastapi import APIRouter, status, Response
from pydantic import BaseModel
from database import check_db_connection
from config import settings

router = APIRouter(tags=["Health"])

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    environment: str

@router.get("/health", response_model=HealthResponse)
def root_health(response: Response):
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
        environment=settings.AEGIS_ENV
    )

@router.get("/api/v1/health", response_model=HealthResponse)
def v1_health(response: Response):
    return root_health(response)
