import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    AEGIS_ENV: str = "development"
    AEGIS_VERSION: str = "0.1.0-alpha"
    LOG_LEVEL: str = "INFO"
    
    # Database
    DATABASE_URL: str = "postgresql+psycopg2://aegis_admin:aegis_secure_hackathon_pass_2026@db:5432/aegis_security_db"
    
    # Ports
    API_PORT: int = 8000
    
    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:8080,http://127.0.0.1:3000,http://127.0.0.1:8080"
    
    @property
    def sqlalchemy_database_url(self) -> str:
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
