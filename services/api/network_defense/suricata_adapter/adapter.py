"""
AEGIS Ω — Suricata & Multi-Sensor Network Adapter Interface (Phase 11)
Provides unified sensor interface for Suricata, Zeek, and external sensor feeds.
Clearly distinguishes LIVE vs SIMULATED vs NOT_CONNECTED.
"""

from abc import ABC, abstractmethod
import os
import logging
from typing import Dict, Any, Optional
from network_defense.network_parser.parser import parse_eve_record
from network_defense.models import NormalizedNetworkEvent
from network_defense.config import netdef_settings

logger = logging.getLogger("aegis.network_defense.adapter")


class NetworkSensorAdapter(ABC):
    """Abstract interface for all network intrusion detection sensors."""

    @abstractmethod
    def get_status(self) -> str:
        """Return sensor status: LIVE, SIMULATED, or NOT_CONNECTED."""
        pass

    @abstractmethod
    def parse_event(self, raw_payload: Dict[str, Any]) -> Optional[NormalizedNetworkEvent]:
        """Normalize raw sensor JSON into AEGIS schema."""
        pass


class SuricataSensorAdapter(NetworkSensorAdapter):
    """Real Suricata IDS/IPS adapter supporting EVE JSON telemetry."""

    def __init__(self, eve_path: Optional[str] = None):
        self.eve_path = eve_path or netdef_settings.SURICATA_EVE_LOG_PATH
        self.sensor_name = netdef_settings.SURICATA_SENSOR_NAME

    def get_status(self) -> str:
        if os.path.exists(self.eve_path):
            return "LIVE"
        return "NOT_CONNECTED"

    def parse_event(self, raw_payload: Dict[str, Any]) -> Optional[NormalizedNetworkEvent]:
        return parse_eve_record(raw_payload, sensor_name=self.sensor_name)


class ZeekSensorAdapter(NetworkSensorAdapter):
    """Zeek network telemetry sensor adapter."""

    def __init__(self):
        self.sensor_name = "zeek"

    def get_status(self) -> str:
        return "STANDBY"

    def parse_event(self, raw_payload: Dict[str, Any]) -> Optional[NormalizedNetworkEvent]:
        return parse_eve_record(raw_payload, sensor_name=self.sensor_name)


# Default sensor instance
_suricata_adapter = SuricataSensorAdapter()


def get_suricata_adapter() -> SuricataSensorAdapter:
    return _suricata_adapter
