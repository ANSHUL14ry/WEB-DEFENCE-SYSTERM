# AEGIS Ω — Hackathon Demo Script (2–3 Minutes)

## Objective
Demonstrate real-time adaptive defense, automated behavioral detection (AgentShield), seamless honeypot deception, and verifiable mitigation within 180 seconds.

---

## Demo Flow

### Act 1: Normal User Experience (0:00 - 0:30)
1. Open SOC Dashboard: `http://localhost:3000`
2. Open Gateway Ingress: `http://localhost:8080/`
3. Result: Normal user is permitted, dashboard shows `ALLOW`, request ID generated, origin receives request.

### Act 2: Recon & Automated Attack Simulation (0:30 - 1:15)
1. Trigger controlled attack scenario from the Attack Simulator.
2. Safe automated sequence executes:
   - Endpoint discovery: `/robots.txt`, `/api/`, `/.env`
   - Authentication brute force canary: `/login`
   - SQLi / XSS probe payload: `SELECT * FROM users WHERE '1'='1'`
3. SOC Dashboard lights up:
   - Coraza WAF triggers rule violations.
   - AgentShield computes high automated/agentic confidence score (>90).

### Act 3: Adaptive Deception & Containment (1:15 - 2:00)
1. Policy engine dynamically classifies session as `CONTAIN + DECEIVE`.
2. Traffic is transparently diverted to the isolated synthetic decoy (`/decoy-admin`, `/decoy-api`).
3. Attacker believes they have found vulnerable backend, but all actions are synthetic.
4. Telemetry collector extracts attacker commands and payload artifacts.

### Act 4: Mitigation Verification & Proof (2:00 - 2:45)
1. AEGIS runs automated verification query on origin server.
2. Origin request log count = 0 during the attack phase.
3. Dashboard updates status to: **`MITIGATION VERIFIED`**.
4. AI SOC Copilot explains why the attack was isolated in plain English with evidence links.
