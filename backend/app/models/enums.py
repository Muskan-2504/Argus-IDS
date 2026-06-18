"""Shared enumerations used across the data model."""

import enum


class Role(enum.StrEnum):
    """Role-based access control levels."""

    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Severity(enum.StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(enum.StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class SourceType(enum.StrEnum):
    auth_log = "auth_log"
    nginx = "nginx"
    apache = "apache"
    suricata = "suricata"
    custom = "custom"
