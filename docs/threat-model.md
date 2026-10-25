# AEGIS Ω — Threat Model & Defensive Security Principles

## 1. Scope & Defensive Mandate
AEGIS Ω is explicitly designed as a defensive security system. 
All attack simulation tools provided within this platform operate strictly in safe, controlled, reproducible environments against explicitly authorized local targets.

### Prohibited Capabilities:
- Unauthorized penetration testing
- Real-world credential harvesting
- Active exploitation frameworks or malware distribution
- Persistence techniques or lateral movement across networks

---

## 2. Threat Actor Profiles

### 2.1 Automated Reconnaissance & Scrapers
- **Pattern:** High velocity, sweeping directory discovery (`/admin`, `/config`, `/.git`, `/api/users`), repetitive enumeration.
- **AEGIS Defense:** AgentShield detects rapid sequence variance and elevated request velocity, triggering early decoy redirection.

### 2.2 Agentic & LLM-Driven Autonomous Attackers
- **Pattern:** Adaptive probing, chain progression (Recon -> Discovery -> Auth Probing -> Parameter Manipulation).
- **AEGIS Defense:** Explainable behavioral indicators identify the structured attack chain rather than relying on brittle signatures alone.

### 2.3 Web Application Attackers (OWASP Top 10)
- **Pattern:** SQLi (`' OR '1'='1`), Cross-Site Scripting (`<script>alert(1)</script>`), Path Traversal (`../../etc/passwd`), SSRF, Command Injection.
- **AEGIS Defense:** Coraza WAF v3.2.2 with OWASP Core Rule Set (CRS) v4.30.0 evaluates anomalous payloads against strict anomaly thresholds.
- **Controlled Interception:** Requests that breach anomaly thresholds are dropped immediately with HTTP 403 Forbidden.
- **Zero Information Leakage:** Public 403 responses contain only generic sanitized error envelopes (`{"error": "request_blocked", ...}`). Internal CRS rule IDs, filesystem paths, and Caddy/Coraza stack internals are never leaked externally.

---

## 3. Data Sanitization & Credential Protection
- **No Password / Secret Logging:** Access logs and WAF event stores strip and redact sensitive parameters (passwords, tokens, authorization headers, API keys).
- **Safe URI Logging:** Gateway and event normalizers sanitize raw query strings to prevent leakage of credentials passed via URL (`(?i)(password|token|secret|key)=...`).
- **Telemetry Integrity:** Internal event ingestion endpoints enforce strict schema validation. Untrusted client claims regarding severity, action, or component status are never accepted without system verification.
- **Server-Side Deterministic Scoring:** Clients cannot supply or manipulate risk scores; risk assessment is computed exclusively by the internal Risk Engine based on verified telemetry.
- **Fail-Safe Isolation:** A failure in the risk evaluation engine is caught safely and cannot degrade WAF blocking capabilities or allow uninspected traffic through to origin.

### 3.1 AgentShield Behavioral Integrity & Non-AI Claim Boundary
- **Observable Heuristics vs. Speculative Attribution:** AgentShield operates strictly on observable HTTP traffic characteristics (request velocity, endpoint variety, authentication target frequency, and attack sequence progression).
- **No Model Identity Claims:** AgentShield explicitly disclaims the ability to identify specific AI models (e.g. ChatGPT, Claude, custom LLMs) or prove that an attacker is an AI. Such claims are scientifically indefensible on HTTP request streams alone.
- **Structural Parameter Privacy:** Parameter manipulation indicators evaluate structural keys only; actual parameter values (passwords, tokens, cookies, queries) are never stored in behavioral evidence.
- **Subsystem Isolation:** Failure within the behavioral analyzer is safely caught and logged. Neither WAF blocking, security event persistence, nor overall platform operation can be disrupted by AgentShield errors.

### 3.2 Policy Engine Invariants & Zero Deception Bypass
- **Terminal WAF Drop Invariant:** Any transaction dropped by the Coraza WAF (`waf_blocked == True` or `waf_action == BLOCK`) is strictly terminal. The Policy Engine enforces `BLOCK` (`RULE_1_WAF_TERMINAL_BLOCK`, `terminal = True`). It can NEVER be overridden to `DECEIVE_ELIGIBLE`, `CONTAIN`, or `ALLOW`.
- **Zero Deception Bypass:** Deception eligibility (`DECEIVE_ELIGIBLE`) is reserved exclusively for requests that have passed through the WAF inspection without being dropped, and demonstrate both high security risk and high-confidence behavioral automation. WAF-blocked attacks cannot be routed to decoys or allowed through.
- **Fail-Safe Conservative Fallback:** Incomplete, missing, or corrupt telemetry contexts never default to `ALLOW`. They conservatively default to `MONITOR` (`RULE_7_CONSERVATIVE_FALLBACK`).
- **Phase 7 Scope Boundary:** The Policy Engine in Phase 7 is solely a decision qualification layer. No honeypots, decoy redirects, or active deception mechanisms are executed in Phase 7.

---

## 4. Deception Isolation & Sandbox Principles
- **No Production Data in Honeypots:** Decoys use 100% synthetic mock tables and synthetic session tokens.
- **Network Isolation:** Honeypots have zero route access to real databases or production backends.
- **Non-Bypass Rule:** A WAF-blocked request is never automatically bypassed into a honeypot; deception occurs strictly through explicit Policy Engine qualification.
