import pytest
import sys
import os

# Add services/api to sys.path for direct unit testing of FastAPI app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../services/api')))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_api_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "AEGIS Ω" in data["message"]
    assert data["docs"] == "/docs"

def test_api_health_endpoint():
    response = client.get("/health")
    # Health endpoint can return 200 or 503 depending on live DB, but schema must be valid
    data = response.json()
    assert "status" in data
    assert data["service"] == "aegis-api"
    assert "version" in data
    assert "database" in data
