"""
Anomaly detector and dynamic geofencing engine for Sentinel.
Calculates risk scores based on time-of-day, network identity, and activity patterns.
Enforces fail-secure defaults and tamper-evident audit emission upon elevated friction.
"""

import os
import json
import socket
import logging
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List, Callable
from filelock import FileLock

from sentinel.anomaly.models import BaselineModel, AnomalyVerdict, NetworkProfile
from sentinel.audit.security_utils import apply_owner_only_dacl
from sentinel.config.settings import default_settings

logger = logging.getLogger(__name__)

FRICTION_THRESHOLD = 0.5
MIN_OBSERVATIONS_FOR_CALIBRATION = 3


class AnomalyDetector:
    """
    Manages behavioural baseline tracking, anomaly scoring, and friction elevation gating.
    """

    def __init__(
        self,
        auth_dir: Optional[Path] = None,
        friction_threshold: float = FRICTION_THRESHOLD,
        lock_timeout_seconds: float = 3.0,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.auth_dir = Path(auth_dir or default_settings.auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.auth_dir / "anomaly_baseline.json"
        self.lock_file = self.auth_dir / ".anomaly_baseline.lock"
        self.friction_threshold = friction_threshold
        self.lock_timeout = lock_timeout_seconds
        self.event_sink = event_sink

    def _emit_event(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.event_sink:
            try:
                self.event_sink(event_type, details)
            except Exception:
                pass

    @staticmethod
    def get_current_network_identity() -> str:
        """
        Concretely discovers local network identity without requiring new permissions/dependencies:
        1. Checks Wi-Fi SSID on Windows (via netsh wlan show interfaces) if available.
        2. Discovers primary network subnet/interface IP via socket connection probe.
        """
        # 1. Attempt SSID discovery on Windows
        if platform.system().lower() == "windows":
            try:
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                    text=True,
                )
                for line in out.splitlines():
                    if "SSID" in line and "BSSID" not in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            ssid = parts[1].strip()
                            if ssid:
                                return f"wifi:{ssid}"
            except Exception:
                pass

        # 2. Fallback: query default outgoing interface subnet prefix
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            # Connect to public DNS address without sending packets
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Group into /24 subnet (e.g. 192.168.1.0/24)
            ip_parts = local_ip.split(".")
            if len(ip_parts) == 4:
                return f"subnet:{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except Exception:
            pass

        return "network:unknown_or_offline"

    def _load_baseline_locked(self) -> Tuple[Optional[BaselineModel], Optional[str]]:
        """
        Loads baseline from disk under lock.
        Returns (BaselineModel, error_reason).
        """
        if not self.baseline_file.exists():
            return None, "baseline_missing"

        try:
            with open(self.baseline_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return BaselineModel.model_validate(data), None
        except Exception as e:
            logger.warning("Anomaly baseline file unreadable or corrupted: %s", e)
            return None, f"baseline_corrupted: {e}"

    def _save_baseline_locked(self, baseline: BaselineModel) -> None:
        """Persists baseline atomically with 0o600 permissions and Windows DACL."""
        baseline.updated_at = datetime.now(timezone.utc).isoformat()
        temp_file = self.baseline_file.with_suffix(f".tmp.{os.getpid()}")
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            fd = os.open(temp_file, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(baseline.model_dump(), f, indent=2)
            os.replace(temp_file, self.baseline_file)
            apply_owner_only_dacl(self.baseline_file)
        except Exception as e:
            logger.error("Failed to save anomaly baseline: %s", e)
            if temp_file.exists():
                try:
                    temp_file.unlink(missing_ok=True)
                except Exception:
                    pass

    def seed_initial_enrollment(
        self,
        current_time: Optional[datetime] = None,
        network_id: Optional[str] = None,
    ) -> None:
        """Seeds the initial baseline at first enrollment from trusted local physical presence."""
        now = current_time or datetime.now()
        net_id = network_id or self.get_current_network_identity()
        hour_str = str(now.hour)
        day_str = str(now.weekday())

        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            baseline = BaselineModel()
            # Seed initial observations around current operating hours
            baseline.total_observations = 3
            # Add current hour and surrounding window (+/- 2h) as initial active hours
            for offset in (-2, -1, 0, 1, 2):
                h = (now.hour + offset) % 24
                baseline.hourly_distribution[str(h)] = 2
            baseline.day_distribution[day_str] = 3
            baseline.known_networks[net_id] = NetworkProfile(
                network_id=net_id,
                observation_count=3,
            )
            self._save_baseline_locked(baseline)

    def evaluate(
        self,
        current_time: Optional[datetime] = None,
        network_id: Optional[str] = None,
        command_tier: Optional[str] = None,
    ) -> AnomalyVerdict:
        """
        Evaluates context against the baseline.
        FAIL-SAFE BEHAVIOR: If baseline is missing, empty, or corrupted, fails closed
        by assigning maximum risk (score=1.0) and requesting elevated friction.
        """
        now = current_time or datetime.now()
        net_id = network_id or self.get_current_network_identity()
        hour_str = str(now.hour)
        day_str = str(now.weekday())

        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            baseline, err = self._load_baseline_locked()

            # FAIL-SAFE: Missing or unreadable baseline defaults to elevated friction
            if baseline is None or baseline.total_observations < MIN_OBSERVATIONS_FOR_CALIBRATION:
                reason = err or "baseline_uncalibrated"
                verdict = AnomalyVerdict(
                    score=1.0,
                    is_anomalous=True,
                    reasons=[reason],
                    elevate_friction=True,
                    required_factors=["pin", "step_up"],
                )
                self._emit_event("auth_anomaly_friction_elevated", {
                    "score": 1.0,
                    "reasons": verdict.reasons,
                    "network_id": net_id,
                    "hour": now.hour,
                    "weekday": now.weekday(),
                })
                return verdict

            # Calculate individual risk component scores
            score = 0.0
            reasons = []

            # 1. Time-of-day scoring (requires >= 2 observations to be considered established)
            hour_count = baseline.hourly_distribution.get(hour_str, 0)
            if hour_count < 2:
                # Find distance to closest active hour
                active_hours = [int(h) for h, count in baseline.hourly_distribution.items() if count >= 2]
                if active_hours:
                    min_dist = min(abs(now.hour - h) for h in active_hours)
                    if min_dist >= 3:
                        score += 0.45
                        reasons.append(f"unusual_hour_{now.hour}:00 (min_dist_{min_dist}h)")
                else:
                    score += 0.45
                    reasons.append(f"unusual_hour_{now.hour}:00")

            # 2. Network identity scoring (requires >= 2 observations to be considered established)
            if net_id not in baseline.known_networks or baseline.known_networks[net_id].observation_count < 2:
                score += 0.5
                reasons.append(f"unrecognized_or_new_network_{net_id}")

            # 3. Command tier distribution
            if command_tier in ("DESTRUCTIVE", "SYSTEM_LEVEL") and score > 0.0:
                score += 0.15
                reasons.append(f"elevated_tier_{command_tier}_in_anomalous_context")

            score = min(1.0, round(score, 2))
            is_anomalous = score >= self.friction_threshold

            required_factors = []
            if is_anomalous:
                required_factors = ["pin", "step_up"]
                self._emit_event("auth_anomaly_friction_elevated", {
                    "score": score,
                    "reasons": reasons,
                    "network_id": net_id,
                    "hour": now.hour,
                    "weekday": now.weekday(),
                    "tier": command_tier,
                })

            return AnomalyVerdict(
                score=score,
                is_anomalous=is_anomalous,
                reasons=reasons,
                elevate_friction=is_anomalous,
                required_factors=required_factors,
            )

    def record_success(
        self,
        current_time: Optional[datetime] = None,
        network_id: Optional[str] = None,
        command_tier: Optional[str] = None,
    ) -> None:
        """
        Updates the baseline with a confirmed successful authentication/action.
        Applies rolling window decay if total observations exceed capacity.
        """
        now = current_time or datetime.now()
        net_id = network_id or self.get_current_network_identity()
        hour_str = str(now.hour)
        day_str = str(now.weekday())

        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            baseline, _ = self._load_baseline_locked()
            if baseline is None:
                baseline = BaselineModel()

            baseline.total_observations += 1
            baseline.hourly_distribution[hour_str] = baseline.hourly_distribution.get(hour_str, 0) + 1
            baseline.day_distribution[day_str] = baseline.day_distribution.get(day_str, 0) + 1

            if net_id in baseline.known_networks:
                prof = baseline.known_networks[net_id]
                prof.last_seen = datetime.now(timezone.utc).isoformat()
                prof.observation_count += 1
            else:
                baseline.known_networks[net_id] = NetworkProfile(network_id=net_id)

            if command_tier:
                baseline.tier_distribution[command_tier] = baseline.tier_distribution.get(command_tier, 0) + 1

            # Rolling decay: if observations > 500, scale down to prevent integer overflow and accommodate habit shifts
            if baseline.total_observations > 500:
                for h in baseline.hourly_distribution:
                    baseline.hourly_distribution[h] = max(0, baseline.hourly_distribution[h] // 2)
                for d in baseline.day_distribution:
                    baseline.day_distribution[d] = max(0, baseline.day_distribution[d] // 2)
                for net in baseline.known_networks.values():
                    net.observation_count = max(1, net.observation_count // 2)
                baseline.total_observations = sum(baseline.hourly_distribution.values())

            self._save_baseline_locked(baseline)

    def reset_baseline(self) -> None:
        """Manually resets the baseline file."""
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            if self.baseline_file.exists():
                self.baseline_file.unlink()
            fresh = BaselineModel()
            self._save_baseline_locked(fresh)
            self._emit_event("auth_anomaly_baseline_reset", {})
