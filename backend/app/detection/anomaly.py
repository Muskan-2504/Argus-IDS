"""Anomaly detection — statistical and ML — over per-IP features.

These complement the signature/threshold rules: instead of a fixed condition,
they flag IPs whose behavior deviates from the rest of the population, catching
attacks that don't trip a hard-coded rule.

* **Statistical**: a leave-one-out z-score on each IP's event count. Computing
  the baseline from the *other* IPs avoids a lone outlier inflating its own
  baseline and hiding.
* **ML**: an Isolation Forest over the full feature vector. scikit-learn is
  imported lazily, so the system still runs without the optional ``[ml]`` extra
  (the detector simply returns nothing).

Both are registered as pseudo-rules (:data:`ANOMALY_RULES`) so their alerts
link to a DB rule and dedupe per (detector, IP).
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable
from typing import TypedDict

from app.detection.features import IpFeatures, extract_features
from app.detection.finding import Finding
from app.models.enums import Severity
from app.models.event import Event

RATE_ANOMALY_KEY = "rate_anomaly"
ML_OUTLIER_KEY = "ml_outlier"


class AnomalyRuleSpec(TypedDict):
    key: str
    name: str
    description: str
    severity: Severity
    mitre_technique: str | None


ANOMALY_RULES: list[AnomalyRuleSpec] = [
    {
        "key": RATE_ANOMALY_KEY,
        "name": "Anomalous Request Rate",
        "description": "An IP whose event volume is a statistical outlier versus its peers.",
        "severity": Severity.medium,
        "mitre_technique": "T1498",
    },
    {
        "key": ML_OUTLIER_KEY,
        "name": "ML Behavioral Outlier",
        "description": "An IP flagged as an outlier by an Isolation Forest over behavior features.",
        "severity": Severity.medium,
        "mitre_technique": None,
    },
]


def statistical_anomalies(
    features: dict[str, IpFeatures], *, z_threshold: float = 3.0, min_count: int = 20
) -> list[Finding]:
    """Flag IPs whose event count is far above the rest of the population."""
    items = list(features.values())
    counts = [f.count for f in items]
    if len(items) < 3:
        return []

    findings: list[Finding] = []
    for i, feature in enumerate(items):
        if feature.count < min_count:
            continue
        others = counts[:i] + counts[i + 1 :]
        baseline = statistics.mean(others)
        spread = statistics.pstdev(others)

        if spread == 0:
            # Uniform baseline: flag only a clear excess over it.
            if feature.count <= baseline * 1.5:
                continue
            z = z_threshold  # nominal
            score = 0.8
        else:
            z = (feature.count - baseline) / spread
            if z < z_threshold:
                continue
            score = min(1.0, z / 6.0)

        findings.append(
            Finding(
                rule_key=RATE_ANOMALY_KEY,
                title=f"Anomalous Request Rate from {feature.source_ip}",
                description=(
                    f"{feature.count} events vs peer mean {baseline:.1f} "
                    f"(z-score {z:.1f}) — statistical outlier"
                ),
                severity=Severity.medium,
                mitre_technique="T1498",
                score=round(score, 2),
                source_ip=feature.source_ip,
            )
        )
    return findings


def ml_anomalies(
    features: dict[str, IpFeatures], *, min_samples: int = 8, contamination: float = 0.1
) -> list[Finding]:
    """Flag IPs that an Isolation Forest isolates as behavioral outliers."""
    items = list(features.values())
    if len(items) < min_samples:
        return []
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return []

    matrix = np.array([f.vector() for f in items], dtype=float)
    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(matrix)
    scores = model.score_samples(matrix)  # lower = more anomalous

    findings: list[Finding] = []
    for feature, prediction, score in zip(items, predictions, scores, strict=True):
        if prediction != -1:
            continue
        magnitude = min(1.0, max(0.0, float(-score)))
        findings.append(
            Finding(
                rule_key=ML_OUTLIER_KEY,
                title=f"ML Behavioral Outlier: {feature.source_ip}",
                description=(
                    f"Isolation Forest isolated this IP as an outlier "
                    f"(anomaly score {magnitude:.2f})"
                ),
                severity=Severity.medium,
                mitre_technique=None,
                score=round(magnitude, 2),
                source_ip=feature.source_ip,
            )
        )
    return findings


def detect_anomalies(events: Iterable[Event]) -> list[Finding]:
    """Run both anomaly detectors over a window of events."""
    features = extract_features(events)
    return statistical_anomalies(features) + ml_anomalies(features)
