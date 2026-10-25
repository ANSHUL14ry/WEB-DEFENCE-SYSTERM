"""
AEGIS Ω — Decoy Administrative Interface
Convincing synthetic administrative portal.
Provides realistic appearance for attacker observation while containing 0 real data.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from config import decoy_settings
from models import DecoyAdminStats

router = APIRouter(prefix="/admin", tags=["Decoy Admin"])


@router.get("", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard_page():
    """Synthetic admin dashboard HTML interface."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Ops Console — {decoy_settings.SYNTHETIC_ORG_NAME}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #f1f5f9; margin: 0; }}
        .header {{ background: #0f172a; border-bottom: 1px solid #1e293b; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-weight: 700; color: #38bdf8; font-size: 16px; letter-spacing: 0.5px; }}
        .user {{ font-size: 13px; color: #94a3b8; font-mono: monospace; }}
        .content {{ padding: 32px; max-width: 1100px; margin: 0 auto; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; }}
        .stat-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; }}
        .stat-val {{ font-size: 26px; font-weight: 700; color: #f8fafc; margin-top: 8px; }}
        .panel {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 24px; margin-top: 16px; }}
        h3 {{ margin-top: 0; font-size: 16px; color: #e2e8f0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }}
        th {{ text-align: left; padding: 8px 12px; color: #64748b; border-bottom: 1px solid #1e293b; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; color: #cbd5e1; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #064e3b; color: #34d399; }}
        .nav-links {{ display: flex; gap: 12px; margin-top: 16px; }}
        .nav-links a {{ color: #38bdf8; text-decoration: none; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">⚡ {decoy_settings.SYNTHETIC_ORG_NAME} &bull; Administration Console</div>
        <div class="user">Active Session: admin_demo@apex-logistics.demo</div>
    </div>
    <div class="content">
        <div class="grid">
            <div class="stat-card">
                <div class="stat-label">Total Users</div>
                <div class="stat-val">1,284</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Orders</div>
                <div class="stat-val">7,421</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Monthly Gross</div>
                <div class="stat-val">$184,200</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">API Requests (24h)</div>
                <div class="stat-val">93,241</div>
            </div>
        </div>

        <div class="panel">
            <h3>Recent Production Shipments</h3>
            <table>
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Client</th>
                        <th>Destination</th>
                        <th>Amount</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>ORD-84920</td>
                        <td>Global Hyperlogics Ltd</td>
                        <td>Frankfurt Hub (FRA-1)</td>
                        <td>$12,450.00</td>
                        <td><span class="badge">In Transit</span></td>
                    </tr>
                    <tr>
                        <td>ORD-84921</td>
                        <td>Nordic Shipping Corp</td>
                        <td>Rotterdam Terminal</td>
                        <td>$8,290.00</td>
                        <td><span class="badge">Cleared</span></td>
                    </tr>
                    <tr>
                        <td>ORD-84922</td>
                        <td>Pacifica Supply Systems</td>
                        <td>Tokyo Port (NRT)</td>
                        <td>$24,180.00</td>
                        <td><span class="badge">In Transit</span></td>
                    </tr>
                </tbody>
            </table>
            <div class="nav-links">
                <a href="/admin/users">&rarr; View User Accounts</a>
                <a href="/admin/settings">&rarr; System Configuration</a>
                <a href="/api/admin/stats">&rarr; Telemetry JSON</a>
            </div>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@router.get("/users")
def get_admin_users():
    """Synthetic admin user list."""
    return {
        "organization": decoy_settings.SYNTHETIC_ORG_NAME,
        "total_count": 4,
        "users": [
            {
                "id": "USR-DECOY-001",
                "username": "admin_demo",
                "role": "Super Administrator",
                "department": "Platform Operations",
                "email": "admin_demo@apex-logistics.demo",
                "status": "active",
                "mfa_enabled": True
            },
            {
                "id": "USR-DECOY-002",
                "username": "sec_operator",
                "role": "Security Analyst",
                "department": "InfoSec",
                "email": "sec_operator@apex-logistics.demo",
                "status": "active",
                "mfa_enabled": True
            },
            {
                "id": "USR-DECOY-003",
                "username": "api_service_account",
                "role": "Service Worker",
                "department": "Automation",
                "email": "svc_api@apex-logistics.demo",
                "status": "active",
                "mfa_enabled": False
            },
            {
                "id": "USR-DECOY-004",
                "username": "finance_lead",
                "role": "Billing Manager",
                "department": "Finance",
                "email": "billing@apex-logistics.demo",
                "status": "active",
                "mfa_enabled": True
            }
        ]
    }


@router.get("/settings")
def get_admin_settings():
    """Synthetic infrastructure settings with mock API keys."""
    return {
        "cluster_name": "apex-logistics-prod-cluster-01",
        "region": "us-east-1",
        "vpc_id": "vpc-089fa2810a0cde882",
        "api_gateway": {
            "mode": "hybrid",
            "rate_limit_per_minute": 5000,
            "public_key": "pk_live_synthetic_apex_984210"
        },
        "database": {
            "engine": "PostgreSQL 16 Enterprise (Synthetic Replica)",
            "host": "synthetic-replica-cluster.internal",
            "port": 5432,
            "ssl_mode": "require"
        },
        "integrations": {
            "webhook_target": "https://hooks.apex-logistics.demo/v1/events",
            "export_format": "JSON"
        }
    }
