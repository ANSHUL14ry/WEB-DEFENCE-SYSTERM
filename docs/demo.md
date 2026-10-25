# AEGIS Ω — Hackathon Demo Script (2–3 Minutes)

## Objective
Demonstrate real-time adaptive defense, automated behavioral detection (AgentShield), seamless honeypot deception, and verifiable mitigation within 180 seconds.

---

## Demo Flow

### Act 1: Normal User Experience (0:00 - 0:30)
1. Open SOC Dashboard: `http://localhost:3000`
2. Open Gateway Ingress: `http://localhost:8080/`
3. Result: Normal user is permitted, dashboard shows `ALLOW`, request ID generated, origin receives request.

### Act 2: Real WAF Threat Interception & Origin Protection (0:30 - 1:15)
1. Send controlled web attack requests through AEGIS Gateway:
   - **SQL Injection:** `GET http://localhost:8080/products?category=%27%20OR%201=1--`
   - **Cross-Site Scripting:** `GET http://localhost:8080/products?q=%3Cscript%3Ealert(1)%3C/script%3E`
   - **Path Traversal:** `GET http://localhost:8080/files?name=../../../../etc/passwd`
2. Observer:
   - Gateway returns HTTP 403 Forbidden with non-leaking JSON envelope.
   - Coraza WAF triggers OWASP CRS rules (e.g. 942100, 941100, 930110).
   - In-memory origin tracking confirms: **0 requests reached the origin application**.
   - Audit log watcher streams detection into PostgreSQL `waf_events` table.
   - SOC Dashboard displays real WAF operational status and live threat events.

### Act 3: Recon & Automated Attack Simulation (1:15 - 1:45)
1. Trigger safe automated attack sequence:
   - Rapid endpoint discovery: `/robots.txt`, `/api/`, `/.env`
   - Authentication brute force canary: `/login`
2. SOC Dashboard lights up:
   - AgentShield computes high automated/agentic confidence score (>90).

### Act 4: Adaptive Deception & Containment (1:45 - 2:15)
1. Policy engine dynamically classifies session as `CONTAIN + DECEIVE`.
2. Traffic is transparently diverted to the isolated synthetic decoy (`/decoy-admin`, `/decoy-api`).
3. Attacker interacts with synthetic tables while production remains untouched.
4. Telemetry collector extracts attacker commands and payload artifacts.

### Act 5: Mitigation Verification & Proof (2:15 - 3:00)
1. AEGIS runs automated verification query on origin server.
2. Origin request log count = 0 during the attack phase.
3. Dashboard updates status to: **`MITIGATION VERIFIED`**.
4. AI SOC Copilot explains why the attack was isolated in plain English with evidence links.
