"""
AEGIS Ω — Decoy Synthetic API Endpoints
Synthetic API endpoints returning completely fabricated JSON datasets.
Decoupled completely from production databases and business logic.
"""

from fastapi import APIRouter
from config import decoy_settings

router = APIRouter(prefix="/api", tags=["Decoy API"])


@router.get("/users")
def get_decoy_users():
    """Synthetic customer user directory."""
    return {
        "status": "success",
        "total": 3,
        "users": [
            {
                "id": "USR-DECOY-001",
                "role": "admin",
                "username": "admin_demo",
                "status": "active"
            },
            {
                "id": "USR-DECOY-002",
                "role": "operator",
                "username": "logistics_lead",
                "status": "active"
            },
            {
                "id": "USR-DECOY-003",
                "role": "auditor",
                "username": "external_compliance",
                "status": "restricted"
            }
        ]
    }


@router.get("/products")
def get_decoy_products():
    """Synthetic inventory catalog."""
    return {
        "status": "success",
        "category": "Industrial Logistics Sensors",
        "products": [
            {
                "id": "PRD-DECOY-101",
                "name": "IoT Freight Telemetry Beacon",
                "sku": "SENS-BEACON-V2",
                "price": 189.50,
                "inventory": 420
            },
            {
                "id": "PRD-DECOY-102",
                "name": "Cargo Tamper Optical Seal",
                "sku": "SEAL-OPT-88",
                "price": 45.00,
                "inventory": 1850
            },
            {
                "id": "PRD-DECOY-103",
                "name": "Cold-Chain Thermal Logger",
                "sku": "LOG-THERM-COLD",
                "price": 310.00,
                "inventory": 94
            }
        ]
    }


@router.get("/orders")
def get_decoy_orders():
    """Synthetic transaction records."""
    return {
        "status": "success",
        "orders": [
            {
                "order_id": "ORD-DECOY-771",
                "customer": "Bavaria Logistics GmbH",
                "total_usd": 4320.00,
                "status": "FULFILLED"
            },
            {
                "order_id": "ORD-DECOY-772",
                "customer": "Yokohama Cargo Network",
                "total_usd": 12850.00,
                "status": "PROCESSING"
            }
        ]
    }


@router.get("/admin/stats")
def get_decoy_stats():
    """Synthetic telemetry metrics for admin probing."""
    return {
        "organization": decoy_settings.SYNTHETIC_ORG_NAME,
        "environment": "synthetic-demo",
        "metrics": {
            "total_users": 1284,
            "total_orders": 7421,
            "revenue_usd": 184200.0,
            "api_requests_today": 93241,
            "system_status": "Operational",
            "cluster_nodes": 6,
            "database_latency_ms": 1.2
        }
    }
