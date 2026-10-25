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

### Act 4: Deterministic Policy Engine & Deception Qualification (1:45 - 2:05)
1. Policy Engine evaluates trusted security intelligence from WAF, Risk Engine, and AgentShield.
2. Invariant verification:
   - WAF-dropped attack requests are strictly enforced as `BLOCK` (Terminal: `True`, Reason: `WAF_BLOCKED_TERMINAL`). Zero deception bypass.
   - Legitimate low-risk traffic evaluates to `ALLOW` (Terminal: `False`, forwarded to Origin).
   - High-risk automated requests (High/Critical Risk + High/Critical AgentShield) qualify for `DECEIVE_ELIGIBLE`.
3. SOC Dashboard displays the **Policy Engine Decision Panel**:
   - Live distribution breakdown (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`, `DECEIVE_ELIGIBLE`).
   - Rule evaluation chain visualizer (`RULE_1_WAF_TERMINAL_BLOCK`, `RULE_2_DECEPTION_ELIGIBILITY`, etc.).

### Act 5: Isolated Adaptive Deception & Honeypot Execution (2:05 - 2:40) — Phase 8 Active
1. **Deception Hand-off**: Qualified `DECEIVE_ELIGIBLE` requests trigger the Deception Router on internal `deception-net`.
2. **Attacker Sandbox Interaction**:
   - Attacker attempts login at `/login` $\rightarrow$ Fake authentication interface records attempt without storing passwords.
   - Attacker probes `/admin/dashboard` $\rightarrow$ Decoy presents synthetic KPI metrics and logistics tables.
   - Attacker inspects `/api/users` $\rightarrow$ Decoy returns synthetic JSON rosters.
3. **Evidence Stream & Timeline**:
   - SOC Dashboard's **Deception Panel** updates in real-time via WebSocket (`DECEPTION_EVENT`).
   - Live Timeline visualizes the step-by-step attacker journey (`LOGIN` $\rightarrow$ `ADMIN` $\rightarrow$ `API`).
4. **Origin Protection Verified**:
   - Operator checks Origin logs: **0 requests hit the production origin application**. The attacker is completely contained within the synthetic sandbox.

### Act 6: Response Verification (Phase 9 Roadmap)
1. Cryptographic mitigation proof and verification receipts generated for compliance.
