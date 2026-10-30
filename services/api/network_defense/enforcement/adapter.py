"""
AEGIS Ω — Network IPS Enforcement Adapter & Abstraction (Phase 11)
Provides controlled, auditable network-level enforcement:
OBSERVE, RATE_LIMIT, TEMP_BLOCK, BLOCK, RELEASE.
Prevents arbitrary shell execution or uncontrolled firewall manipulation.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
import ipaddress
import logging
import uuid
from typing import Dict, Any, List, Optional
from network_defense.models import (
    EnforcementAction,
    NetworkEnforcementRecord,
    NetworkEnforcementRequest
)
from network_defense.config import netdef_settings

logger = logging.getLogger("aegis.network_defense.enforcement")


class NetworkEnforcementAdapter(ABC):
    """Abstract base class for Network IPS enforcement engines."""

    @abstractmethod
    def observe(self, source_ip: str, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        pass

    @abstractmethod
    def rate_limit(self, source_ip: str, rps: int, duration_seconds: int, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        pass

    @abstractmethod
    def temporary_block(self, source_ip: str, duration_seconds: int, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        pass

    @abstractmethod
    def block(self, source_ip: str, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        pass

    @abstractmethod
    def release(self, source_ip: str, reason: str = "Manual admin release") -> Optional[NetworkEnforcementRecord]:
        pass

    @abstractmethod
    def enforce(
        self,
        source_ip: str,
        action: str,
        reason: str,
        network_risk_score: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        trigger_event_id: Optional[str] = None
    ) -> NetworkEnforcementRecord:
        pass

    @abstractmethod
    def get_enforcement_status(self, source_ip: str) -> Optional[NetworkEnforcementRecord]:
        pass

    @abstractmethod
    def list_active(self) -> List[NetworkEnforcementRecord]:
        pass


class DevNetworkEnforcementAdapter(NetworkEnforcementAdapter):
    def enforce(
        self,
        source_ip: str,
        action: str,
        reason: str,
        network_risk_score: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        trigger_event_id: Optional[str] = None
    ) -> NetworkEnforcementRecord:
        act = action.upper()
        if act == "OBSERVE":
            rec = self.observe(source_ip, reason, trigger_event_id=trigger_event_id)
        elif act == "TEMP_BLOCK":
            rec = self.temporary_block(source_ip, duration_seconds=ttl_seconds or 300, reason=reason, trigger_event_id=trigger_event_id)
        elif act == "RATE_LIMIT":
            rec = self.rate_limit(source_ip, rps=10, duration_seconds=ttl_seconds or 300, reason=reason, trigger_event_id=trigger_event_id)
        elif act == "BLOCK":
            rec = self.block(source_ip, reason=reason, trigger_event_id=trigger_event_id)
        else:
            rec = self.observe(source_ip, reason, trigger_event_id=trigger_event_id)
        
        if network_risk_score is not None:
            rec.network_risk_score = network_risk_score
        return rec

    """
    In-memory stateful enforcement engine for development, staging, and container environments.
    Maintains active enforcement states, automatic TTL expiration, and audit trail.
    """

    def __init__(self):
        # source_ip -> NetworkEnforcementRecord
        self._active_enforcements: Dict[str, NetworkEnforcementRecord] = {}
        # List of all historical records for auditing
        self._audit_log: List[NetworkEnforcementRecord] = []

    def _clean_expired(self):
        now = datetime.now(timezone.utc)
        expired_ips = []
        for ip, rec in self._active_enforcements.items():
            if rec.expires_at:
                try:
                    exp_dt = datetime.fromisoformat(rec.expires_at)
                    if now >= exp_dt:
                        rec.status = "EXPIRED"
                        expired_ips.append(ip)
                except Exception:
                    pass
        for ip in expired_ips:
            del self._active_enforcements[ip]

    def observe(self, source_ip: str, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        self._clean_expired()
        rec = NetworkEnforcementRecord(
            enforcement_id=f"enf-{uuid.uuid4().hex[:12]}",
            source_ip=source_ip.strip(),
            action="OBSERVE",
            status="ACTIVE",
            reason=reason,
            trigger_event_id=trigger_event_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            audit_metadata={"mode": "DEV", "action": "OBSERVE"}
        )
        self._active_enforcements[source_ip.strip()] = rec
        self._audit_log.append(rec)
        logger.info(f"[NETWORK IPS] OBSERVE registered for IP: {source_ip} (Reason: {reason})")
        return rec

    def rate_limit(self, source_ip: str, rps: int, duration_seconds: int, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        self._clean_expired()
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=duration_seconds)
        rec = NetworkEnforcementRecord(
            enforcement_id=f"enf-{uuid.uuid4().hex[:12]}",
            source_ip=source_ip.strip(),
            action="RATE_LIMIT",
            status="ACTIVE",
            rate_limit_rps=rps,
            duration_seconds=duration_seconds,
            reason=reason,
            trigger_event_id=trigger_event_id,
            expires_at=exp.isoformat(),
            created_at=now.isoformat(),
            audit_metadata={"mode": "DEV", "rps": rps, "duration": duration_seconds}
        )
        self._active_enforcements[source_ip.strip()] = rec
        self._audit_log.append(rec)
        logger.warning(f"[NETWORK IPS] RATE_LIMIT ({rps} rps) applied to {source_ip} for {duration_seconds}s: {reason}")
        return rec

    def temporary_block(self, source_ip: str, duration_seconds: int, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        self._clean_expired()
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=duration_seconds)
        rec = NetworkEnforcementRecord(
            enforcement_id=f"enf-{uuid.uuid4().hex[:12]}",
            source_ip=source_ip.strip(),
            action="TEMP_BLOCK",
            status="ACTIVE",
            duration_seconds=duration_seconds,
            reason=reason,
            trigger_event_id=trigger_event_id,
            expires_at=exp.isoformat(),
            created_at=now.isoformat(),
            audit_metadata={"mode": "DEV", "duration": duration_seconds}
        )
        self._active_enforcements[source_ip.strip()] = rec
        self._audit_log.append(rec)
        logger.warning(f"[NETWORK IPS] TEMP_BLOCK applied to {source_ip} for {duration_seconds}s: {reason}")
        return rec

    def block(self, source_ip: str, reason: str, trigger_event_id: Optional[str] = None) -> NetworkEnforcementRecord:
        self._clean_expired()
        now = datetime.now(timezone.utc)
        rec = NetworkEnforcementRecord(
            enforcement_id=f"enf-{uuid.uuid4().hex[:12]}",
            source_ip=source_ip.strip(),
            action="BLOCK",
            status="ACTIVE",
            duration_seconds=None,
            reason=reason,
            trigger_event_id=trigger_event_id,
            expires_at=None,
            created_at=now.isoformat(),
            audit_metadata={"mode": "DEV", "permanent": True}
        )
        self._active_enforcements[source_ip.strip()] = rec
        self._audit_log.append(rec)
        logger.critical(f"[NETWORK IPS] PERMANENT BLOCK applied to {source_ip}: {reason}")
        return rec

    def release(self, source_ip: str, reason: str = "Manual admin release") -> Optional[NetworkEnforcementRecord]:
        self._clean_expired()
        ip = source_ip.strip()
        if ip in self._active_enforcements:
            rec = self._active_enforcements[ip]
            rec.action = "RELEASE"
            rec.status = "RELEASED"
            rec.released_at = datetime.now(timezone.utc).isoformat()
            rec.audit_metadata["release_reason"] = reason
            del self._active_enforcements[ip]
            logger.info(f"[NETWORK IPS] RELEASED enforcement for IP {ip}: {reason}")
            return rec
        return None

    def get_enforcement_status(self, source_ip: str) -> Optional[NetworkEnforcementRecord]:
        self._clean_expired()
        return self._active_enforcements.get(source_ip.strip())

    def list_active(self) -> List[NetworkEnforcementRecord]:
        self._clean_expired()
        return list(self._active_enforcements.values())


# Singleton enforcement adapter instance
_enforcement_adapter: NetworkEnforcementAdapter = DevNetworkEnforcementAdapter()


def get_enforcement_adapter() -> NetworkEnforcementAdapter:
    return _enforcement_adapter


def set_enforcement_adapter(adapter: NetworkEnforcementAdapter) -> None:
    global _enforcement_adapter
    _enforcement_adapter = adapter
