# AEGIS Ω — Hackathon Demo Script (2–3 Minutes)

## Objective
Demonstrate real-time adaptive defense, automated behavioral detection (AgentShield), seamless honeypot deception, and verifiable mitigation within 180 seconds.

---

## Demo Flow

### Act 1: Normal User Experience (0:00 - 0:30)
1. Open SOC Dashboard: `http://localhost:3000`
2. Open Gateway Ingress: `http://localhost:8080/`
3. Result: Normal user is permitted, dashboard shows `ALLOW`, request ID generated, origin receives request.

### Act 2: Real WAF Threat Interception & Explainable Risk Scoring (0:30 - 1:15)
1. Send controlled web attack requests through AEGIS Gateway:
   - **SQL Injection:** `GET http://localhost:8080/products?category=%27%20OR%201=1--`
   - **Cross-Site Scripting:** `GET http://localhost:8080/products?q=%3Cscript%3Ealert(1)%3C/script%3E`
   - **Path Traversal:** `GET http://localhost:8080/files?name=../../../../etc/passwd`
2. Observer:
   - Gateway returns HTTP 403 Forbidden with non-leaking JSON envelope.
   - Coraza WAF triggers OWASP CRS rules (e.g. 942100, 941100, 930110).
   - In-memory origin tracking confirms: **0 requests reached the origin application**.
   - Audit log watcher tails Coraza audit JSON in real time.
   - Event pipeline normalizes event, computes deduplication signature, and stores in PostgreSQL `security_events`.
   - **Deterministic Risk Engine** evaluates normalized telemetry within a 60-second temporal window, deriving a threat score (0–100) and severity classification.
   - Transparent risk signals are decomposed:
     - `waf_severity` (+30 for Critical)
     - `known_attack_rule` (+20 for OWASP CRS SQLi/XSS/LFI/RCE rule ID)
     - `elevated_anomaly_score` (+10 for anomaly score >= 5)
   - Real-time risk assessment is persisted in `risk_assessments` table.
   - WebSocket broadcaster streams `RISK_SCORE_UPDATE` and `SECURITY_EVENT` live to SOC Dashboard without page reload!
   - Operator views the interactive **Risk Engine Gauge & Signals Panel** on the SOC Dashboard, drilling down into transparent reasons and mathematical score breakdown.

### Act 3: AgentShield Behavioral Automation & Attack Sequence Analysis (1:15 - 1:45)
1. Trigger safe automated attack progression through AEGIS Gateway:
   - **Stage 1 (Recon):** `GET /robots.txt`
   - **Stage 2 (Endpoint Discovery):** `GET /admin`, `GET /.env`
   - **Stage 3 (API Enumeration):** `GET /api/users`, `GET /api/products`
   - **Stage 4 (Auth Probing):** `POST /login` (repeated credential interface requests)
   - **Stage 5 (WAF Intercept):** `GET /products?category=' OR 1=1--` (SQLi canary payload)
2. Observer on SOC Dashboard:
   - **AgentShield Panel** updates instantaneously via WebSocket (`AGENTSHIELD_SIGNAL`) with zero page reload.
   - Automation score reaches **CRITICAL** (e.g. 90/100) with confidence 100%.
   - **Automation Indicators Checklist** illuminates detected heuristics:
     - [x] Rapid Reconnaissance (+15)
     - [x] Endpoint Enumeration (+15)
     - [x] API Enumeration (+15)
     - [x] High Request Velocity (+15)
     - [x] Authentication Probing (+10)
     - [x] Multi-Stage Attack Sequence (+20)
   - **Progression Tracker** visualizes chronological attack lifecycle:
     `RECON → ENDPOINT_DISCOVERY → API_ENUMERATION → AUTH_PROBING → WAF_TRIGGER`
   - Operator clicks **Drilldown Modal** to inspect sanitized evidence metrics and per-stage request timeline.
   - **Risk Engine Integration**: The Risk Engine automatically incorporates the AgentShield result, adding the `agentshield_behavior` signal (+20) to the overall risk assessment.
   - **Technical Disclaimer Highlighted**: The dashboard explicitly displays: *"AgentShield detects observable behavioral characteristics consistent with automated or agentic attack workflows. It does NOT identify specific AI models or claim proof of AI identity."*

### Act 4: Deterministic Policy Engine & Deception Qualification (1:45 - 2:15)
1. Policy Engine evaluates trusted security intelligence from WAF, Risk Engine, and AgentShield.
2. Invariant verification:
   - WAF-dropped attack requests are strictly enforced as `BLOCK` (Terminal: `True`, Reason: `WAF_BLOCKED_TERMINAL`). Zero deception bypass.
   - Legitimate low-risk traffic evaluates to `ALLOW` (Terminal: `False`, forwarded to Origin).
   - High-risk automated requests (High/Critical Risk + High/Critical AgentShield) qualify for `DECEIVE_ELIGIBLE`.
3. SOC Dashboard displays the **Policy Engine Decision Panel**:
   - Live distribution breakdown (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`, `DECEIVE_ELIGIBLE`).
   - Rule evaluation chain visualizer (`RULE_1_WAF_TERMINAL_BLOCK`, `RULE_2_DECEPTION_ELIGIBILITY`, etc.).
   - Interactive Decision Drilldown showing input context and deterministic explanation.
   - Clear Phase 7 disclaimer: *Phase 7 qualifies deception eligibility only; honeypot decoy redirection is scheduled for Phase 8 execution.*

### Act 5: Adaptive Deception & Verification (2:15 - 3:00) — Phase 8 Roadmap
1. Qualified `DECEIVE_ELIGIBLE` sessions are transparently diverted to isolated synthetic decoys in Phase 8.
2. AEGIS runs automated verification query on origin server: Origin request log count = 0 during the attack phase.
3. Dashboard updates status to: **`MITIGATION VERIFIED`**.
4. AI SOC Copilot explains why the attack was isolated in plain English with evidence links.
