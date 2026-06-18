"""Smoke tests for the application entry point (no database required)."""

from fastapi.testclient import TestClient

from app import __version__
from app.main import app

client = TestClient(app)


def test_health_ok():
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_root_points_to_docs():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["health"] == "/api/health"
