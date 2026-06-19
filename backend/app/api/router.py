"""Aggregates all API routers under a single entry point.

Routers added in later milestones: rules (M2), alerts (M3), websocket (M4).
"""

from fastapi import APIRouter

from app.api.routes import alerts, auth, health, ingest, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(ingest.router)
api_router.include_router(alerts.router)
