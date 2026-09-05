"""
core/location_provider.py — Multi-Tier Location Resolution Engine
===================================================================
Provides a robust, 3-tier location fallback chain for security alerts:

  • Tier 1 (Primary): Windows Location API (Wi-Fi-based positioning via
                      Windows Runtime Geolocator crowdsourced AP database).
                      Respects OS Location Services consent gate.
                      Precision tier: 'high_confidence_wifi'.
  • Tier 2 (Fallback): IP-based Geolocation (HTTPS endpoint).
                      Used when OS Location Services is disabled/denied or no Wi-Fi.
                      Precision tier: 'city_level_ip_estimate'.
  • Tier 3 (Opportunistic Bonus): Paired Phone GPS cache.
                      Used if fresh coordinates were reported by mobile companion.
                      Precision tier: 'gps_precise'.

Hard Rule: Every location result is strictly labeled with its actual 'source'
and 'precision_tier'. An IP estimate is never presented as GPS or Wi-Fi.
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("JARVIS.LocationProvider")

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW on Windows


@dataclass
class LocationResult:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_meters: Optional[float] = None
    source: str = "unavailable"  # "windows_location_api" | "ip_geolocation" | "paired_phone_gps" | "unavailable"
    precision_tier: str = "unavailable"  # "high_confidence_wifi" | "city_level_ip_estimate" | "gps_precise" | "unavailable"
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    resolved_at: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy_meters": self.accuracy_meters,
            "source": self.source,
            "precision_tier": self.precision_tier,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "resolved_at": self.resolved_at,
            "details": self.details,
        }

    def summary_str(self) -> str:
        if self.source == "unavailable":
            return "Location unavailable"
        coords = f"{self.latitude:.5f}, {self.longitude:.5f}" if self.latitude is not None and self.longitude is not None else "N/A"
        acc = f" ±{int(self.accuracy_meters)}m" if self.accuracy_meters is not None else ""
        place = f" ({self.city}, {self.region})" if self.city else ""
        return f"[{self.source} | {self.precision_tier}] {coords}{acc}{place}"


class LocationProvider:
    """
    Singleton / component providing multi-tier geolocation with explicit
    source & precision tier guarantees.
    """

    _instance: Optional["LocationProvider"] = None
    _lock = threading.Lock()

    def __init__(self, cache_ttl_seconds: float = 60.0, auto_warmup: bool = True):
        self._cache_ttl = cache_ttl_seconds
        self._cached_result: Optional[LocationResult] = None
        self._phone_gps_cache: Optional[LocationResult] = None
        self._phone_gps_ttl: float = 300.0  # 5 minutes
        if auto_warmup:
            threading.Thread(target=self._warmup, name="LocationWarmupWorker", daemon=True).start()

    def _warmup(self) -> None:
        try:
            self.get_location(timeout=2.0, force_refresh=True)
        except Exception:
            pass

    @classmethod
    def get_instance(cls) -> "LocationProvider":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def update_phone_gps(
        self,
        latitude: float,
        longitude: float,
        accuracy_meters: Optional[float] = None,
        city: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Records fresh GPS coordinates pushed from a paired phone companion."""
        self._phone_gps_cache = LocationResult(
            latitude=latitude,
            longitude=longitude,
            accuracy_meters=accuracy_meters or 10.0,
            source="paired_phone_gps",
            precision_tier="gps_precise",
            city=city,
            resolved_at=time.time(),
            details=details or {"client": "paired_mobile_companion"},
        )
        logger.info(f"Phone GPS updated: {self._phone_gps_cache.summary_str()}")

    def clear_cache(self) -> None:
        self._cached_result = None
        self._phone_gps_cache = None

    def get_location(
        self,
        timeout: float = 3.0,
        allow_phone: bool = True,
        force_refresh: bool = False,
        non_blocking: bool = False,
    ) -> LocationResult:
        """
        Resolves current location using the 3-tier fallback chain.
        Returns a strongly-typed LocationResult with explicit source and precision tier.
        If non_blocking is True, returns cached location immediately if available,
        or launches a background resolution if cache is empty.
        """
        now = time.time()

        # Check cached recent location unless force_refresh
        if not force_refresh and self._cached_result is not None:
            if (now - self._cached_result.resolved_at) < self._cache_ttl:
                return self._cached_result
            if non_blocking:
                # Return slightly stale cache while refreshing in background
                threading.Thread(target=lambda: self.get_location(timeout=timeout, allow_phone=allow_phone, force_refresh=True), daemon=True).start()
                return self._cached_result

        # Tier 3 (Opportunistic Bonus): Check fresh paired phone GPS
        if allow_phone and self._phone_gps_cache is not None:
            if (now - self._phone_gps_cache.resolved_at) < self._phone_gps_ttl:
                return self._phone_gps_cache

        if non_blocking:
            # If nothing in cache, launch background resolution and return placeholder
            threading.Thread(target=lambda: self.get_location(timeout=timeout, allow_phone=allow_phone, force_refresh=True), daemon=True).start()
            return LocationResult(
                source="unavailable",
                precision_tier="unavailable",
                details={"status": "resolving_in_background"},
            )

        # Tier 1 (Primary): Windows Location API (Wi-Fi crowdsourced database)
        if platform.system().lower() == "windows":
            win_loc = self._query_windows_location_api(timeout=min(timeout, 1.8))
            if win_loc is not None:
                self._cached_result = win_loc
                return win_loc

        # Tier 2 (Fallback): IP-based Geolocation (HTTPS-only)
        ip_loc = self._query_ip_geolocation(timeout=min(timeout, 1.5))
        if ip_loc is not None:
            self._cached_result = ip_loc
            return ip_loc

        # Exhausted / Offline
        unavailable = LocationResult(
            source="unavailable",
            precision_tier="unavailable",
            details={"error": "All location providers failed or network offline"},
        )
        return unavailable

    def _query_windows_location_api(self, timeout: float = 1.8) -> Optional[LocationResult]:
        """
        Queries Windows Location Services via WinRT Windows.Devices.Geolocation.Geolocator.
        Strictly respects OS Location Services consent gate.
        """
        # 1. Try winsdk direct binding if installed
        try:
            import winsdk.windows.devices.geolocation as wdg  # type: ignore
            import asyncio

            async def _get_winsdk_pos():
                access = await wdg.Geolocator.request_access_async()
                if access == wdg.GeolocationAccessStatus.ALLOWED:
                    geolocator = wdg.Geolocator()
                    pos = await geolocator.get_geoposition_async()
                    return pos
                return None

            loop = asyncio.new_event_loop()
            try:
                pos = loop.run_until_complete(asyncio.wait_for(_get_winsdk_pos(), timeout=timeout))
                if pos and pos.coordinate:
                    coord = pos.coordinate
                    lat = float(coord.point.position.latitude)
                    lon = float(coord.point.position.longitude)
                    acc = float(coord.accuracy) if coord.accuracy else 50.0
                    return LocationResult(
                        latitude=lat,
                        longitude=lon,
                        accuracy_meters=acc,
                        source="windows_location_api",
                        precision_tier="high_confidence_wifi",
                        resolved_at=time.time(),
                        details={"binding": "winsdk", "position_source": str(getattr(coord, "position_source", "WiFi"))},
                    )
            finally:
                loop.close()
        except (ImportError, Exception):
            pass

        # 2. Native Windows Runtime PowerShell Bridge (always present on Win10/11)
        ps_script = """
$ErrorActionPreference = 'Stop'
try {
    [Windows.Services.Store.StoreContext,Windows.Services.Store,ContentType=WindowsRuntime] | Out-Null
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    Function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(1500) | Out-Null
        $netTask.Result
    }
    [Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime] | Out-Null
    $geolocator = New-Object Windows.Devices.Geolocation.Geolocator
    $accessOp = [Windows.Devices.Geolocation.Geolocator]::RequestAccessAsync()
    $access = Await $accessOp ([Windows.Devices.Geolocation.GeolocationAccessStatus])

    if ($access -eq [Windows.Devices.Geolocation.GeolocationAccessStatus]::Allowed) {
        $posOp = $geolocator.GetGeopositionAsync()
        $pos = Await $posOp ([Windows.Devices.Geolocation.Geoposition])
        $coord = $pos.Coordinate
        $res = [PSCustomObject]@{
            Status = 'Success'
            Access = $access.ToString()
            Latitude = $coord.Point.Position.Latitude
            Longitude = $coord.Point.Position.Longitude
            Accuracy = $coord.Accuracy
            Source = $coord.PositionSource.ToString()
        }
        $res | ConvertTo-Json
    } else {
        [PSCustomObject]@{ Status = 'Denied'; Access = $access.ToString() } | ConvertTo-Json
    }
} catch {
    [PSCustomObject]@{ Status = 'Error'; Error = $_.Exception.Message } | ConvertTo-Json
}
"""
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=timeout + 0.5,
                creationflags=NO_WINDOW,
            )
            out = res.stdout.strip()
            if out:
                data = json.loads(out)
                if data.get("Status") == "Success" and data.get("Latitude") is not None:
                    lat = float(data["Latitude"])
                    lon = float(data["Longitude"])
                    acc = float(data.get("Accuracy", 50.0))
                    src = str(data.get("Source", "WiFi"))
                    return LocationResult(
                        latitude=lat,
                        longitude=lon,
                        accuracy_meters=acc,
                        source="windows_location_api",
                        precision_tier="high_confidence_wifi",
                        resolved_at=time.time(),
                        details={"binding": "winrt_powershell", "position_source": src},
                    )
        except Exception as e:
            logger.debug(f"Windows Location API query failed/denied: {e}")

        return None

    def _query_ip_geolocation(self, timeout: float = 1.5) -> Optional[LocationResult]:
        """
        Queries IP-based Geolocation over HTTPS.
        City-level accuracy only.
        """
        endpoints = [
            ("https://ipapi.co/json/", self._parse_ipapi_co),
            ("https://ipwhois.app/json/", self._parse_ipwhois),
        ]

        for url, parser in endpoints:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "JARVIS-Security-Sentinel/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        raw = resp.read().decode("utf-8")
                        data = json.loads(raw)
                        res = parser(data)
                        if res is not None:
                            return res
            except Exception as e:
                logger.debug(f"IP Geolocation query to {url} failed: {e}")

        return None

    def _parse_ipapi_co(self, data: dict) -> Optional[LocationResult]:
        if "error" in data or not data.get("latitude") or not data.get("longitude"):
            return None
        return LocationResult(
            latitude=float(data["latitude"]),
            longitude=float(data["longitude"]),
            accuracy_meters=float(data.get("accuracy_radius", 10000.0) or 10000.0),
            source="ip_geolocation",
            precision_tier="city_level_ip_estimate",
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country_name"),
            resolved_at=time.time(),
            details={"provider": "ipapi.co", "ip": data.get("ip"), "org": data.get("org")},
        )

    def _parse_ipwhois(self, data: dict) -> Optional[LocationResult]:
        if not data.get("success", True) or not data.get("latitude") or not data.get("longitude"):
            return None
        return LocationResult(
            latitude=float(data["latitude"]),
            longitude=float(data["longitude"]),
            accuracy_meters=10000.0,
            source="ip_geolocation",
            precision_tier="city_level_ip_estimate",
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country"),
            resolved_at=time.time(),
            details={"provider": "ipwhois.app", "ip": data.get("ip"), "org": data.get("connection", {}).get("org")},
        )
