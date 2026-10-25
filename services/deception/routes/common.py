"""
AEGIS Ω — Decoy Common & Public Routes
Synthetic public facing endpoints for the isolated honeypot application.
"""

from fastapi import APIRouter, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from config import decoy_settings

router = APIRouter(tags=["Decoy Public"])


@router.get("/healthz")
def healthcheck():
    """Internal health check for container orchestration."""
    return {
        "status": "operational",
        "service": decoy_settings.SERVICE_NAME,
        "environment": decoy_settings.ENVIRONMENT,
        "isolation": "enforced"
    }


@router.get("/", response_class=HTMLResponse)
def index_page():
    """Synthetic customer portal landing page."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{decoy_settings.SYNTHETIC_ORG_NAME}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; background: #1e293b; padding: 32px; border-radius: 12px; border: 1px solid #334155; }}
        h1 {{ color: #38bdf8; font-size: 24px; margin-bottom: 8px; }}
        p {{ color: #94a3b8; line-height: 1.6; }}
        .nav {{ margin-top: 24px; display: flex; gap: 16px; }}
        .nav a {{ color: #38bdf8; text-decoration: none; padding: 8px 16px; background: #0f172a; border-radius: 6px; border: 1px solid #334155; font-size: 14px; }}
        .nav a:hover {{ background: #1e293b; border-color: #38bdf8; }}
        .footer {{ margin-top: 40px; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{decoy_settings.SYNTHETIC_ORG_NAME}</h1>
        <p>Enterprise Global Supply Chain & Logistics Management Portal. Real-time freight tracking, inventory monitoring, and partner integrations.</p>
        <div class="nav">
            <a href="/login">Employee Login</a>
            <a href="/admin">Partner Console</a>
            <a href="/api/products">Product Catalog</a>
        </div>
        <div class="footer">
            &copy; 2026 {decoy_settings.SYNTHETIC_ORG_NAME}. All systems operational. Version {decoy_settings.VERSION}.
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    """Synthetic robots.txt designed to safely attract recon crawlers."""
    content = """User-agent: *
Disallow: /admin/
Disallow: /admin/dashboard
Disallow: /admin/settings
Disallow: /api/admin/
Disallow: /api/v1/internal/
Disallow: /config/
Disallow: /.env
Allow: /
Allow: /login
Allow: /api/products
"""
    return PlainTextResponse(content=content, status_code=200)


@router.get("/sitemap.xml")
def sitemap_xml():
    """Synthetic sitemap."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://apex-logistics.demo/</loc></url>
  <url><loc>https://apex-logistics.demo/login</loc></url>
  <url><loc>https://apex-logistics.demo/api/products</loc></url>
</urlset>"""
    return Response(content=content, media_type="application/xml", status_code=200)
