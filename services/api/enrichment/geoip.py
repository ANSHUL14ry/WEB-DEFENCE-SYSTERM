"""
Modular GeoIP & ASN enrichment engine with private IP detection and local caching.
Strict No-Fake-Data Enforcement:
- Private/container IPs return is_private=True, country=None, asn=None, display_label="PRIVATE / INTERNAL ADDRESS".
- Public IPs without verified local databases return UNKNOWN / None.
"""

import ipaddress
import logging
import time
from typing import Dict, Optional, Tuple
from enrichment.models import GeoIPContext
from enrichment.config import ti_settings

logger = logging.getLogger("aegis.enrichment.geoip")

# In-memory IP cache: ip -> (GeoIPContext, expiration_timestamp)
_GEOIP_CACHE: Dict[str, Tuple[GeoIPContext, float]] = {}


def is_ip_private(ip_str: str) -> bool:
    """Check if an IP string belongs to RFC1918, loopback, link-local, or reserved ranges."""
    if not ip_str or ip_str.lower() in ("unknown", "localhost", "none", ""):
        return True
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast
        )
    except ValueError:
        # Invalid IP strings treated safely as private/internal
        return True


def lookup_geoip(ip_str: str) -> GeoIPContext:
    """
    Look up GeoIP and ASN details for an IP address.
    Checks memory cache first.
    Strictly distinguishes private IPs from public IPs.
    Never invents fake coordinates, countries, or ASNs.
    """
    if not ip_str:
        ip_str = "127.0.0.1"

    clean_ip = ip_str.strip()
    now = time.time()

    # Check cache
    if clean_ip in _GEOIP_CACHE:
        ctx, expires_at = _GEOIP_CACHE[clean_ip]
        if now < expires_at:
            return ctx

    # 1. Private/Internal IP Check
    if is_ip_private(clean_ip):
        context = GeoIPContext(
            is_private=True,
            country=None,
            country_code=None,
            region=None,
            city=None,
            latitude=None,
            longitude=None,
            timezone=None,
            asn=None,
            organization=None,
            isp=None,
            display_label="PRIVATE / INTERNAL ADDRESS"
        )
        _GEOIP_CACHE[clean_ip] = (context, now + ti_settings.CACHE_TTL_SECONDS)
        return context

    # 2. Public IP handling
    # If a legitimate local MaxMind GeoLite2 database file exists, query it safely
    geo_db_path = ti_settings.GEOIP_DB_PATH
    if geo_db_path:
        try:
            import geoip2.database
            with geoip2.database.Reader(geo_db_path) as reader:
                response = reader.city(clean_ip)
                context = GeoIPContext(
                    is_private=False,
                    country=response.country.name or "UNKNOWN",
                    country_code=response.country.iso_code,
                    region=response.subdivisions.most_specific.name if response.subdivisions else None,
                    city=response.city.name,
                    latitude=float(response.location.latitude) if response.location.latitude else None,
                    longitude=float(response.location.longitude) if response.location.longitude else None,
                    timezone=response.location.time_zone,
                    asn=None,
                    organization=None,
                    isp=None,
                    display_label=f"{response.country.name or 'UNKNOWN'} ({response.country.iso_code or '??'})"
                )
                _GEOIP_CACHE[clean_ip] = (context, now + ti_settings.CACHE_TTL_SECONDS)
                return context
        except Exception as e:
            logger.debug(f"Local GeoIP lookup failed or database unreadable: {e}")

    # 3. Default when no verified local database is configured: return UNKNOWN
    context = GeoIPContext(
        is_private=False,
        country="UNKNOWN",
        country_code=None,
        region=None,
        city=None,
        latitude=None,
        longitude=None,
        timezone=None,
        asn="UNKNOWN",
        organization="UNKNOWN",
        isp="UNKNOWN",
        display_label="UNKNOWN"
    )
    _GEOIP_CACHE[clean_ip] = (context, now + ti_settings.CACHE_TTL_SECONDS)
    return context


def clear_geoip_cache() -> None:
    """Utility to clear cache in testing."""
    _GEOIP_CACHE.clear()
