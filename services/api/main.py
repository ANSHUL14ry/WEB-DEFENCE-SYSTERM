import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from database import check_db_connection
from routers import health, system

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("aegis.api")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AEGIS Ω Control Plane API...")
    db_ok = check_db_connection()
    if db_ok:
        logger.info("PostgreSQL database connection verified.")
    else:
        logger.warning("PostgreSQL database is currently unavailable or initializing.")
    yield
    logger.info("Shutting down AEGIS Ω Control Plane API.")

app = FastAPI(
    title="AEGIS Ω Control Plane API",
    description="Backend API and Security Telemetry Engine for AEGIS Ω Adaptive Cyber Defense Platform",
    version=settings.AEGIS_VERSION,
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(system.router)

@app.get("/")
def root():
    return {
        "message": "AEGIS Ω Control Plane API",
        "tagline": "Detect. Predict. Deceive. Contain.",
        "version": settings.AEGIS_VERSION,
        "docs": "/docs",
        "health": "/health"
    }
