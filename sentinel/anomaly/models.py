"""Data models for anomaly detection, geofencing baseline, and scoring."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class NetworkProfile(BaseModel):
    network_id: str = Field(..., description="Normalized SSID or subnet identifier")
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    observation_count: int = Field(default=1, ge=1)


class BaselineModel(BaseModel):
    """
    Rolling behavioural and contextual baseline.
    Protected with 0o600 permissions and Windows owner-only DACL.
    """
    version: int = Field(default=1)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_observations: int = Field(default=0, ge=0)

    # 24-hour histogram of successful authentications {hour: count}
    hourly_distribution: Dict[str, int] = Field(default_factory=lambda: {str(h): 0 for h in range(24)})
    # Day-of-week histogram {weekday: count} (0=Mon, 6=Sun)
    day_distribution: Dict[str, int] = Field(default_factory=lambda: {str(d): 0 for d in range(7)})
    # Known network profiles {network_id: NetworkProfile}
    known_networks: Dict[str, NetworkProfile] = Field(default_factory=dict)
    # Command tier activity rate {tier_name: count}
    tier_distribution: Dict[str, int] = Field(default_factory=dict)
    # Sliding window cluster trackers (epoch timestamps)
    face_failure_timestamps: List[float] = Field(default_factory=list)
    watchdog_restart_timestamps: List[float] = Field(default_factory=list)


class AnomalyVerdict(BaseModel):
    """Result of anomaly evaluation against baseline."""
    score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score between 0.0 (normal) and 1.0 (highly anomalous)")
    is_anomalous: bool = Field(..., description="True if score >= friction_threshold")
    reasons: List[str] = Field(default_factory=list)
    elevate_friction: bool = Field(default=False)
    required_factors: List[str] = Field(default_factory=list)
    risk_breakdown: Dict[str, float] = Field(default_factory=dict)

