"""SQLAlchemy models. Importing this package registers every table on the
shared metadata so Alembic autogeneration can see them.
"""

from app.models.alert import Alert
from app.models.enrichment import IpEnrichment
from app.models.event import Event
from app.models.log_source import LogSource
from app.models.rule import DetectionRule
from app.models.user import User

__all__ = [
    "Alert",
    "DetectionRule",
    "Event",
    "IpEnrichment",
    "LogSource",
    "User",
]
