"""
AEGIS Ω — Decoy Authentication Interface
Synthetic login interface that records interaction evidence while strictly forbidding
any storage of plaintext passwords or real authentication secrets.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from config import decoy_settings
from models import DecoyLoginRequest
from evidence.collector import hash_identifier

router = APIRouter(tags=["Decoy Auth"])


@router.get("/login", response_class=HTMLResponse)
def login_page():
    """Synthetic employee login portal."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Portal Login — {decoy_settings.SYNTHETIC_ORG_NAME}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .card {{ background: #1e293b; padding: 36px; border-radius: 12px; border: 1px solid #334155; width: 100%; max-width: 380px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }}
        h2 {{ color: #f8fafc; font-size: 20px; margin-top: 0; margin-bottom: 6px; }}
        .subtitle {{ color: #94a3b8; font-size: 13px; margin-bottom: 24px; }}
        .field {{ margin-bottom: 16px; }}
        label {{ display: block; font-size: 12px; color: #cbd5e1; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
        input[type="text"], input[type="password"] {{ width: 100%; box-sizing: border-box; padding: 10px 12px; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #f8fafc; font-size: 14px; outline: none; }}
        input:focus {{ border-color: #38bdf8; }}
        button {{ width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: 600; font-size: 14px; cursor: pointer; margin-top: 8px; }}
        button:hover {{ background: #0369a1; }}
        .notice {{ margin-top: 20px; font-size: 11px; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Corporate Sign-In</h2>
        <div class="subtitle">{decoy_settings.SYNTHETIC_ORG_NAME}</div>
        <form action="/login" method="POST">
            <div class="field">
                <label for="username">Corporate ID or Email</label>
                <input type="text" id="username" name="username" placeholder="e.g. jdoe@apex-logistics.demo" required>
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit">Sign In to Dashboard</button>
        </form>
        <div class="notice">
            Authorized access only. All activity is logged and monitored.
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@router.post("/login")
async def handle_login(request: Request):
    """
    Synthetic authentication processor.
    Accepts login attempts to observe attacker username choices and patterns.
    STRICT SECURITY INVARIANT:
    - Passwords are NEVER stored, hashed for persistence, or logged.
    - Always responds with synthetic authentication failure.
    - Never grants production access.
    """
    attempt_id = f"att-{uuid.uuid4().hex[:12]}"
    username = "unknown"

    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
            username = body.get("username", "unknown")
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            username = str(form.get("username", "unknown"))
        except Exception:
            pass

    username_hash = hash_identifier(username)

    # Return realistic failure response; no honeypot revelation
    return JSONResponse(
        status_code=401,
        content={
            "status": "error",
            "error_code": "AUTH_CREDENTIALS_INVALID",
            "message": "Authentication failed. The provided username or password does not match our corporate records.",
            "attempt_id": attempt_id,
            "username_hash": username_hash
        }
    )
